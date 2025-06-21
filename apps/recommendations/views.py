"""
Views for recommendations app
"""
from rest_framework import status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from django.db.models import Count, Q, F, ExpressionWrapper, FloatField
from django.utils import timezone
from apps.books.models import Book, BookReservation, BookReview
from apps.events.models import Event, EventRegistration
from apps.seats.models import Seat, SeatBooking
from apps.subscriptions.models import SubscriptionPlan, UserSubscription


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_book_recommendations(request):
    """Get personalized book recommendations"""
    try:
        user = request.user
        
        # Get user's reading history
        user_books = BookReservation.objects.filter(
            user=user,
            is_deleted=False
        ).values_list('book_id', flat=True)
        
        # Get user's book categories
        user_categories = Book.objects.filter(
            id__in=user_books
        ).values_list('category_id', flat=True).distinct()
        
        # Get user's preferred authors
        user_authors = Book.objects.filter(
            id__in=user_books
        ).values_list('authors', flat=True).distinct()
        
        # Recommendations based on categories
        category_recommendations = Book.objects.filter(
            category_id__in=user_categories,
            is_deleted=False
        ).exclude(
            id__in=user_books
        ).order_by('-average_rating')[:5]
        
        # Recommendations based on authors
        author_recommendations = Book.objects.filter(
            authors__in=user_authors,
            is_deleted=False
        ).exclude(
            id__in=user_books
        ).order_by('-average_rating')[:5]
        
        # Popular books
        popular_recommendations = Book.objects.filter(
            is_popular=True,
            is_deleted=False
        ).exclude(
            id__in=user_books
        ).order_by('-total_reservations')[:5]
        
        # New arrivals
        new_recommendations = Book.objects.filter(
            is_new_arrival=True,
            is_deleted=False
        ).exclude(
            id__in=user_books
        ).order_by('-created_at')[:5]
        
        # Premium recommendations if user has subscription
        premium_recommendations = []
        if hasattr(user, 'current_subscription') and user.current_subscription:
            premium_recommendations = Book.objects.filter(
                is_premium=True,
                is_deleted=False
            ).exclude(
                id__in=user_books
            ).order_by('-average_rating')[:5]
        
        # Serialize the recommendations
        from apps.books.serializers import BookListSerializer
        
        return Response({
            'category_based': BookListSerializer(category_recommendations, many=True).data,
            'author_based': BookListSerializer(author_recommendations, many=True).data,
            'popular': BookListSerializer(popular_recommendations, many=True).data,
            'new_arrivals': BookListSerializer(new_recommendations, many=True).data,
            'premium': BookListSerializer(premium_recommendations, many=True).data,
        })
    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_event_recommendations(request):
    """Get personalized event recommendations"""
    try:
        user = request.user
        
        # Get user's event history
        user_events = EventRegistration.objects.filter(
            user=user,
            is_deleted=False
        ).values_list('event_id', flat=True)
        
        # Get user's event categories
        user_categories = Event.objects.filter(
            id__in=user_events
        ).values_list('category_id', flat=True).distinct()
        
        # Upcoming events in user's categories
        category_recommendations = Event.objects.filter(
            category_id__in=user_categories,
            start_date__gte=timezone.now().date(),
            status__in=['PUBLISHED', 'REGISTRATION_OPEN'],
            is_deleted=False
        ).exclude(
            id__in=user_events
        ).order_by('start_date')[:5]
        
        # Popular events
        popular_recommendations = Event.objects.filter(
            start_date__gte=timezone.now().date(),
            status__in=['PUBLISHED', 'REGISTRATION_OPEN'],
            is_deleted=False
        ).exclude(
            id__in=user_events
        ).order_by('-total_registrations')[:5]
        
        # Free events
        free_recommendations = Event.objects.filter(
            start_date__gte=timezone.now().date(),
            status__in=['PUBLISHED', 'REGISTRATION_OPEN'],
            registration_fee=0,
            is_deleted=False
        ).exclude(
            id__in=user_events
        ).order_by('start_date')[:5]
        
        # Premium events if user has subscription
        premium_recommendations = []
        if hasattr(user, 'current_subscription') and user.current_subscription:
            premium_recommendations = Event.objects.filter(
                start_date__gte=timezone.now().date(),
                status__in=['PUBLISHED', 'REGISTRATION_OPEN'],
                required_subscription=True,
                is_deleted=False
            ).exclude(
                id__in=user_events
            ).order_by('start_date')[:5]
        
        # Serialize the recommendations
        from apps.events.serializers import EventListSerializer
        
        return Response({
            'category_based': EventListSerializer(category_recommendations, many=True).data,
            'popular': EventListSerializer(popular_recommendations, many=True).data,
            'free': EventListSerializer(free_recommendations, many=True).data,
            'premium': EventListSerializer(premium_recommendations, many=True).data,
        })
    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_seat_recommendations(request):
    """Get personalized seat recommendations"""
    try:
        user = request.user
        
        # Get user's booking history
        user_seats = SeatBooking.objects.filter(
            user=user,
            is_deleted=False
        ).values_list('seat_id', flat=True)
        
        # Get user's preferred seat types
        user_seat_types = Seat.objects.filter(
            id__in=user_seats
        ).values_list('seat_type', flat=True).distinct()
        
        # Get user's preferred libraries
        user_libraries = Seat.objects.filter(
            id__in=user_seats
        ).values_list('library_id', flat=True).distinct()
        
        # Recommendations based on seat types
        type_recommendations = Seat.objects.filter(
            seat_type__in=user_seat_types,
            status='AVAILABLE',
            is_bookable=True,
            is_deleted=False
        ).exclude(
            id__in=user_seats
        ).order_by('-average_rating')[:5]
        
        # Recommendations based on libraries
        library_recommendations = Seat.objects.filter(
            library_id__in=user_libraries,
            status='AVAILABLE',
            is_bookable=True,
            is_deleted=False
        ).exclude(
            id__in=user_seats
        ).order_by('-average_rating')[:5]
        
        # Highly rated seats
        rated_recommendations = Seat.objects.filter(
            status='AVAILABLE',
            is_bookable=True,
            is_deleted=False,
            average_rating__gte=4.0
        ).exclude(
            id__in=user_seats
        ).order_by('-average_rating')[:5]
        
        # Premium seats if user has subscription
        premium_recommendations = []
        if hasattr(user, 'current_subscription') and user.current_subscription:
            premium_recommendations = Seat.objects.filter(
                status='AVAILABLE',
                is_bookable=True,
                is_premium=True,
                is_deleted=False
            ).exclude(
                id__in=user_seats
            ).order_by('-average_rating')[:5]
        
        # Serialize the recommendations
        from apps.seats.serializers import SeatListSerializer
        
        return Response({
            'type_based': SeatListSerializer(type_recommendations, many=True).data,
            'library_based': SeatListSerializer(library_recommendations, many=True).data,
            'highly_rated': SeatListSerializer(rated_recommendations, many=True).data,
            'premium': SeatListSerializer(premium_recommendations, many=True).data,
        })
    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_subscription_recommendations(request):
    """Get subscription plan recommendations"""
    try:
        user = request.user
        
        # Check if user already has an active subscription
        has_subscription = hasattr(user, 'current_subscription') and user.current_subscription
        
        if has_subscription:
            # Get current plan
            current_plan = user.current_subscription.plan
            
            # Recommend upgrade options
            upgrade_recommendations = SubscriptionPlan.objects.filter(
                price__gt=current_plan.price,
                is_active=True,
                is_deleted=False
            ).order_by('price')[:3]
            
            # Serialize the recommendations
            from apps.subscriptions.serializers import SubscriptionPlanSerializer
            
            return Response({
                'has_subscription': True,
                'current_plan': SubscriptionPlanSerializer(current_plan).data,
                'upgrade_options': SubscriptionPlanSerializer(upgrade_recommendations, many=True).data,
            })
        else:
            # Recommend plans for new subscribers
            featured_plan = SubscriptionPlan.objects.filter(
                is_featured=True,
                is_active=True,
                is_deleted=False
            ).first()
            
            basic_plan = SubscriptionPlan.objects.filter(
                plan_type='BASIC',
                is_active=True,
                is_deleted=False
            ).first()
            
            student_plan = SubscriptionPlan.objects.filter(
                plan_type='STUDENT',
                is_active=True,
                is_deleted=False
            ).first()
            
            all_plans = SubscriptionPlan.objects.filter(
                is_active=True,
                is_deleted=False
            ).order_by('price')
            
            # Serialize the recommendations
            from apps.subscriptions.serializers import SubscriptionPlanSerializer
            
            return Response({
                'has_subscription': False,
                'featured_plan': SubscriptionPlanSerializer(featured_plan).data if featured_plan else None,
                'basic_plan': SubscriptionPlanSerializer(basic_plan).data if basic_plan else None,
                'student_plan': SubscriptionPlanSerializer(student_plan).data if student_plan else None,
                'all_plans': SubscriptionPlanSerializer(all_plans, many=True).data,
            })
    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )