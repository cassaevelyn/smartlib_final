"""
Views for analytics app
"""
from rest_framework import status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from django.db.models import Count, Sum, Avg, F, Q
from django.utils import timezone
from datetime import timedelta
from apps.core.permissions import IsAdminUser, IsSuperAdminUser
from apps.accounts.models import User
from apps.books.models import Book, BookReservation
from apps.seats.models import Seat, SeatBooking
from apps.events.models import Event, EventRegistration
from apps.library.models import Library
from apps.subscriptions.models import UserSubscription, SubscriptionPlan, SubscriptionTransaction


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated, IsAdminUser])
def get_dashboard_analytics(request):
    """Get dashboard analytics"""
    try:
        # Get date range parameters
        days = int(request.query_params.get('days', 30))
        start_date = timezone.now() - timedelta(days=days)
        
        # User statistics
        total_users = User.objects.count()
        active_users = User.objects.filter(is_active=True).count()
        new_users = User.objects.filter(created_at__gte=start_date).count()
        
        # Book statistics
        total_books = Book.objects.count()
        total_reservations = BookReservation.objects.count()
        active_reservations = BookReservation.objects.filter(
            status__in=['PENDING', 'CONFIRMED', 'READY_FOR_PICKUP', 'CHECKED_OUT']
        ).count()
        
        # Seat statistics
        total_seats = Seat.objects.count()
        total_bookings = SeatBooking.objects.count()
        active_bookings = SeatBooking.objects.filter(
            status__in=['CONFIRMED', 'CHECKED_IN']
        ).count()
        
        # Event statistics
        total_events = Event.objects.count()
        upcoming_events = Event.objects.filter(
            start_date__gte=timezone.now().date()
        ).count()
        total_registrations = EventRegistration.objects.count()
        
        # Subscription statistics
        total_subscriptions = UserSubscription.objects.count()
        active_subscriptions = UserSubscription.objects.filter(
            status='ACTIVE',
            end_date__gt=timezone.now()
        ).count()
        subscription_revenue = SubscriptionTransaction.objects.filter(
            status='COMPLETED',
            created_at__gte=start_date
        ).aggregate(total=Sum('amount'))['total'] or 0
        
        # Return analytics data
        return Response({
            'users': {
                'total': total_users,
                'active': active_users,
                'new': new_users,
            },
            'books': {
                'total': total_books,
                'reservations': total_reservations,
                'active_reservations': active_reservations,
            },
            'seats': {
                'total': total_seats,
                'bookings': total_bookings,
                'active_bookings': active_bookings,
            },
            'events': {
                'total': total_events,
                'upcoming': upcoming_events,
                'registrations': total_registrations,
            },
            'subscriptions': {
                'total': total_subscriptions,
                'active': active_subscriptions,
                'revenue': float(subscription_revenue),
            },
        })
    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated, IsAdminUser])
def get_user_analytics(request):
    """Get user analytics"""
    try:
        # Get date range parameters
        days = int(request.query_params.get('days', 30))
        start_date = timezone.now() - timedelta(days=days)
        
        # User statistics by role
        users_by_role = User.objects.values('role').annotate(
            count=Count('id')
        ).order_by('role')
        
        # User registrations over time
        user_registrations = User.objects.filter(
            created_at__gte=start_date
        ).extra(
            select={'date': 'date(created_at)'}
        ).values('date').annotate(
            count=Count('id')
        ).order_by('date')
        
        # User approval rate
        total_users = User.objects.count()
        approved_users = User.objects.filter(is_approved=True).count()
        approval_rate = (approved_users / total_users * 100) if total_users > 0 else 0
        
        # User activity
        active_users_last_30_days = User.objects.filter(
            last_login__gte=start_date
        ).count()
        
        # Return analytics data
        return Response({
            'users_by_role': users_by_role,
            'user_registrations': user_registrations,
            'approval_rate': approval_rate,
            'active_users': active_users_last_30_days,
            'total_users': total_users,
        })
    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated, IsAdminUser])
def get_book_analytics(request):
    """Get book analytics"""
    try:
        # Get date range parameters
        days = int(request.query_params.get('days', 30))
        start_date = timezone.now() - timedelta(days=days)
        
        # Book reservations by status
        reservations_by_status = BookReservation.objects.values('status').annotate(
            count=Count('id')
        ).order_by('status')
        
        # Book reservations over time
        reservations_over_time = BookReservation.objects.filter(
            created_at__gte=start_date
        ).extra(
            select={'date': 'date(created_at)'}
        ).values('date').annotate(
            count=Count('id')
        ).order_by('date')
        
        # Most reserved books
        most_reserved_books = Book.objects.annotate(
            reservation_count=Count('reservations')
        ).order_by('-reservation_count')[:10].values(
            'id', 'title', 'reservation_count', 'average_rating'
        )
        
        # Book types distribution
        book_types = Book.objects.values('book_type').annotate(
            count=Count('id')
        ).order_by('book_type')
        
        # Return analytics data
        return Response({
            'reservations_by_status': reservations_by_status,
            'reservations_over_time': reservations_over_time,
            'most_reserved_books': most_reserved_books,
            'book_types': book_types,
        })
    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated, IsAdminUser])
def get_seat_analytics(request):
    """Get seat analytics"""
    try:
        # Get date range parameters
        days = int(request.query_params.get('days', 30))
        start_date = timezone.now() - timedelta(days=days)
        
        # Seat bookings by status
        bookings_by_status = SeatBooking.objects.values('status').annotate(
            count=Count('id')
        ).order_by('status')
        
        # Seat bookings over time
        bookings_over_time = SeatBooking.objects.filter(
            created_at__gte=start_date
        ).extra(
            select={'date': 'date(created_at)'}
        ).values('date').annotate(
            count=Count('id')
        ).order_by('date')
        
        # Most booked seats
        most_booked_seats = Seat.objects.annotate(
            booking_count=Count('bookings')
        ).order_by('-booking_count')[:10].values(
            'id', 'seat_number', 'library__name', 'booking_count', 'average_rating'
        )
        
        # Seat types distribution
        seat_types = Seat.objects.values('seat_type').annotate(
            count=Count('id')
        ).order_by('seat_type')
        
        # Return analytics data
        return Response({
            'bookings_by_status': bookings_by_status,
            'bookings_over_time': bookings_over_time,
            'most_booked_seats': most_booked_seats,
            'seat_types': seat_types,
        })
    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated, IsAdminUser])
def get_event_analytics(request):
    """Get event analytics"""
    try:
        # Get date range parameters
        days = int(request.query_params.get('days', 30))
        start_date = timezone.now() - timedelta(days=days)
        
        # Event registrations by status
        registrations_by_status = EventRegistration.objects.values('status').annotate(
            count=Count('id')
        ).order_by('status')
        
        # Event registrations over time
        registrations_over_time = EventRegistration.objects.filter(
            created_at__gte=start_date
        ).extra(
            select={'date': 'date(created_at)'}
        ).values('date').annotate(
            count=Count('id')
        ).order_by('date')
        
        # Most popular events
        most_popular_events = Event.objects.annotate(
            registration_count=Count('registrations')
        ).order_by('-registration_count')[:10].values(
            'id', 'title', 'registration_count', 'average_rating'
        )
        
        # Event types distribution
        event_types = Event.objects.values('event_type').annotate(
            count=Count('id')
        ).order_by('event_type')
        
        # Return analytics data
        return Response({
            'registrations_by_status': registrations_by_status,
            'registrations_over_time': registrations_over_time,
            'most_popular_events': most_popular_events,
            'event_types': event_types,
        })
    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated, IsAdminUser])
def get_library_analytics(request):
    """Get library analytics"""
    try:
        # Get date range parameters
        days = int(request.query_params.get('days', 30))
        start_date = timezone.now() - timedelta(days=days)
        
        # Library usage (seat bookings)
        library_usage = SeatBooking.objects.filter(
            created_at__gte=start_date
        ).values('seat__library__name').annotate(
            count=Count('id')
        ).order_by('-count')
        
        # Library types distribution
        library_types = Library.objects.values('library_type').annotate(
            count=Count('id')
        ).order_by('library_type')
        
        # Library ratings
        library_ratings = Library.objects.values('id', 'name').annotate(
            avg_rating=Avg('average_rating'),
            review_count=Sum('total_reviews')
        ).order_by('-avg_rating')
        
        # Return analytics data
        return Response({
            'library_usage': library_usage,
            'library_types': library_types,
            'library_ratings': library_ratings,
        })
    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated, IsAdminUser])
def get_subscription_analytics(request):
    """Get subscription analytics"""
    try:
        # Get date range parameters
        days = int(request.query_params.get('days', 30))
        start_date = timezone.now() - timedelta(days=days)
        
        # Subscriptions by plan
        subscriptions_by_plan = UserSubscription.objects.values(
            'plan__name'
        ).annotate(
            count=Count('id')
        ).order_by('-count')
        
        # Subscriptions by status
        subscriptions_by_status = UserSubscription.objects.values('status').annotate(
            count=Count('id')
        ).order_by('status')
        
        # Subscriptions over time
        subscriptions_over_time = UserSubscription.objects.filter(
            created_at__gte=start_date
        ).extra(
            select={'date': 'date(created_at)'}
        ).values('date').annotate(
            count=Count('id')
        ).order_by('date')
        
        # Revenue over time
        revenue_over_time = SubscriptionTransaction.objects.filter(
            status='COMPLETED',
            created_at__gte=start_date
        ).extra(
            select={'date': 'date(created_at)'}
        ).values('date').annotate(
            revenue=Sum('amount')
        ).order_by('date')
        
        # Auto-renewal rate
        total_active = UserSubscription.objects.filter(status='ACTIVE').count()
        auto_renew = UserSubscription.objects.filter(status='ACTIVE', is_auto_renew=True).count()
        auto_renew_rate = (auto_renew / total_active * 100) if total_active > 0 else 0
        
        # Return analytics data
        return Response({
            'subscriptions_by_plan': subscriptions_by_plan,
            'subscriptions_by_status': subscriptions_by_status,
            'subscriptions_over_time': subscriptions_over_time,
            'revenue_over_time': revenue_over_time,
            'auto_renew_rate': auto_renew_rate,
            'total_subscriptions': UserSubscription.objects.count(),
            'active_subscriptions': UserSubscription.objects.filter(
                status='ACTIVE',
                end_date__gt=timezone.now()
            ).count(),
            'total_revenue': float(SubscriptionTransaction.objects.filter(
                status='COMPLETED'
            ).aggregate(total=Sum('amount'))['total'] or 0),
        })
    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )