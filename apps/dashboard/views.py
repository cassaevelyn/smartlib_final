"""
Views for dashboard app
"""
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from django.db.models import Sum, Count, Avg
from django.utils import timezone
from datetime import timedelta
from apps.core.models import ActivityLog
from apps.core.serializers import ActivityLogSerializer
from apps.accounts.models import User, UserProfile
from apps.seats.models import SeatBooking
from apps.books.models import BookReservation
from apps.events.models import EventRegistration


class DashboardStatsView(generics.GenericAPIView):
    """Get dashboard statistics for the current user"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        user = request.user
        today = timezone.now().date()
        
        # Get user profile
        try:
            profile = UserProfile.objects.get(user=user)
        except UserProfile.DoesNotExist:
            profile = None
        
        # Current bookings (today)
        current_bookings = SeatBooking.objects.filter(
            user=user,
            booking_date=today,
            status__in=['CONFIRMED', 'CHECKED_IN'],
            is_deleted=False
        ).count()
        
        # Active book reservations
        active_reservations = BookReservation.objects.filter(
            user=user,
            status__in=['PENDING', 'CONFIRMED', 'READY_FOR_PICKUP', 'CHECKED_OUT'],
            is_deleted=False
        ).count()
        
        # Upcoming events
        upcoming_events = EventRegistration.objects.filter(
            user=user,
            event__start_date__gte=today,
            status__in=['CONFIRMED', 'WAITLISTED'],
            is_deleted=False
        ).count()
        
        # Loyalty points
        loyalty_points = profile.loyalty_points if profile else 0
        
        # Total study hours
        total_study_hours = profile.total_study_hours if profile else 0
        
        # Books read
        books_read = profile.books_read if profile else 0
        
        # Events attended
        events_attended = profile.events_attended if profile else 0
        
        # Completion rate
        total_bookings = SeatBooking.objects.filter(
            user=user,
            is_deleted=False
        ).count()
        
        completed_bookings = SeatBooking.objects.filter(
            user=user,
            status='COMPLETED',
            is_deleted=False
        ).count()
        
        completion_rate = (completed_bookings / total_bookings * 100) if total_bookings > 0 else 0
        
        return Response({
            'current_bookings': current_bookings,
            'active_reservations': active_reservations,
            'upcoming_events': upcoming_events,
            'loyalty_points': loyalty_points,
            'total_study_hours': total_study_hours,
            'books_read': books_read,
            'events_attended': events_attended,
            'completion_rate': round(completion_rate, 1),
        })


class RecentActivityListView(generics.ListAPIView):
    """Get recent activities for the current user"""
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ActivityLogSerializer
    
    def get_queryset(self):
        user = self.request.user
        
        # Get recent activities from ActivityLog
        activities = ActivityLog.objects.filter(
            user=user
        ).order_by('-created_at')[:10]
        
        return activities
    
    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        
        # Transform the data to match the frontend expected format
        transformed_data = []
        
        activity_type_mapping = {
            'LOGIN': 'ACCOUNT',
            'LOGOUT': 'ACCOUNT',
            'SEAT_BOOK': 'SEAT_BOOKING',
            'SEAT_CHECKIN': 'SEAT_BOOKING',
            'SEAT_CHECKOUT': 'SEAT_BOOKING',
            'BOOK_RESERVE': 'BOOK_RESERVATION',
            'BOOK_PICKUP': 'BOOK_RESERVATION',
            'BOOK_RETURN': 'BOOK_RESERVATION',
            'EVENT_REGISTER': 'EVENT_REGISTRATION',
            'EVENT_ATTEND': 'EVENT_REGISTRATION',
            'PROFILE_UPDATE': 'ACCOUNT',
            'PASSWORD_CHANGE': 'ACCOUNT',
        }
        
        for activity in serializer.data:
            activity_type = activity['activity_type']
            mapped_type = activity_type_mapping.get(activity_type, 'ACCOUNT')
            
            # Extract status from metadata if available
            status = 'COMPLETED'
            if 'metadata' in activity and 'status' in activity['metadata']:
                status = activity['metadata']['status']
            
            # Create a title based on activity type
            title_mapping = {
                'LOGIN': 'Account Login',
                'LOGOUT': 'Account Logout',
                'SEAT_BOOK': 'Seat Booking',
                'SEAT_CHECKIN': 'Seat Check-in',
                'SEAT_CHECKOUT': 'Seat Check-out',
                'BOOK_RESERVE': 'Book Reservation',
                'BOOK_PICKUP': 'Book Pickup',
                'BOOK_RETURN': 'Book Return',
                'EVENT_REGISTER': 'Event Registration',
                'EVENT_ATTEND': 'Event Attendance',
                'PROFILE_UPDATE': 'Profile Update',
                'PASSWORD_CHANGE': 'Password Change',
            }
            
            title = title_mapping.get(activity_type, activity_type.replace('_', ' ').title())
            
            transformed_data.append({
                'id': activity['id'],
                'type': mapped_type,
                'title': title,
                'description': activity['description'],
                'timestamp': activity['created_at'],
                'status': status,
            })
        
        return Response(transformed_data)