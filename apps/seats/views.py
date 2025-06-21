"""
Views for seats app
"""
from rest_framework import generics, status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from django.db.models import Q, Count, Avg
from django.utils import timezone
from django.shortcuts import get_object_or_404
from apps.core.permissions import IsAdminUser, CanManageBookings
from .models import (
    Seat, SeatBooking, SeatBookingWaitlist, SeatReview,
    SeatMaintenanceLog, SeatUsageStatistics
)
from .serializers import (
    SeatSerializer, SeatListSerializer, SeatBookingSerializer,
    SeatBookingCreateSerializer, SeatBookingWaitlistSerializer,
    SeatReviewSerializer, SeatMaintenanceLogSerializer,
    SeatUsageStatisticsSerializer, SeatAvailabilitySerializer,
    CheckInSerializer, CheckOutSerializer, SeatSearchSerializer,
    QRCodeDataSerializer
)
import json


class SeatListView(generics.ListAPIView):
    """List seats with filtering and search"""
    serializer_class = SeatListSerializer
    permission_classes = [permissions.IsAuthenticated]
    filterset_fields = [
        'seat_type', 'status', 'has_power_outlet', 'has_ethernet',
        'has_monitor', 'is_near_window', 'is_accessible', 'is_premium'
    ]
    search_fields = ['seat_number', 'seat_code']
    ordering_fields = ['seat_number', 'average_rating', 'total_bookings']
    ordering = ['seat_number']
    
    def get_queryset(self):
        library_id = self.kwargs.get('library_id')
        floor_id = self.kwargs.get('floor_id')
        section_id = self.kwargs.get('section_id')
        
        queryset = Seat.objects.filter(is_deleted=False)
        
        if library_id:
            queryset = queryset.filter(library_id=library_id)
        if floor_id:
            queryset = queryset.filter(floor_id=floor_id)
        if section_id:
            queryset = queryset.filter(section_id=section_id)
        
        # Filter based on user access
        user = self.request.user
        if not user.is_super_admin:
            if user.role == 'ADMIN':
                admin_profile = getattr(user, 'admin_profile', None)
                if admin_profile and admin_profile.managed_library:
                    queryset = queryset.filter(library=admin_profile.managed_library)
                else:
                    queryset = queryset.none()
            else:
                # Students can see seats in libraries they have access to
                accessible_libraries = user.library_access.filter(
                    is_active=True
                ).values_list('library_id', flat=True)
                queryset = queryset.filter(library_id__in=accessible_libraries)
        
        return queryset.select_related('library', 'floor', 'section')


class SeatDetailView(generics.RetrieveAPIView):
    """Get seat details"""
    serializer_class = SeatSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'id'
    
    def get_queryset(self):
        return Seat.objects.filter(is_deleted=False).select_related(
            'library', 'floor', 'section'
        )


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def search_seats(request):
    """Advanced seat search"""
    serializer = SeatSearchSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    
    data = serializer.validated_data
    queryset = Seat.objects.filter(is_deleted=False, is_bookable=True)
    
    # Apply filters
    if data.get('library_id'):
        queryset = queryset.filter(library_id=data['library_id'])
    
    if data.get('floor_id'):
        queryset = queryset.filter(floor_id=data['floor_id'])
    
    if data.get('section_id'):
        queryset = queryset.filter(section_id=data['section_id'])
    
    if data.get('seat_type'):
        queryset = queryset.filter(seat_type=data['seat_type'])
    
    if data.get('has_power_outlet') is not None:
        queryset = queryset.filter(has_power_outlet=data['has_power_outlet'])
    
    if data.get('has_ethernet') is not None:
        queryset = queryset.filter(has_ethernet=data['has_ethernet'])
    
    if data.get('has_monitor') is not None:
        queryset = queryset.filter(has_monitor=data['has_monitor'])
    
    if data.get('is_near_window') is not None:
        queryset = queryset.filter(is_near_window=data['is_near_window'])
    
    if data.get('is_accessible') is not None:
        queryset = queryset.filter(is_accessible=data['is_accessible'])
    
    if data.get('is_premium') is not None:
        queryset = queryset.filter(is_premium=data['is_premium'])
    
    if data.get('min_rating'):
        queryset = queryset.filter(average_rating__gte=data['min_rating'])
    
    # Filter by availability if date and time provided
    if data.get('date') and data.get('start_time') and data.get('end_time'):
        booking_date = data['date']
        start_time = data['start_time']
        end_time = data['end_time']
        
        # Exclude seats with conflicting bookings
        conflicting_bookings = SeatBooking.objects.filter(
            booking_date=booking_date,
            status__in=['CONFIRMED', 'CHECKED_IN'],
            is_deleted=False
        ).filter(
            Q(start_time__lt=end_time) & Q(end_time__gt=start_time)
        ).values_list('seat_id', flat=True)
        
        queryset = queryset.exclude(id__in=conflicting_bookings)
    
    # Apply user access restrictions
    user = request.user
    if not user.is_super_admin:
        if user.role == 'ADMIN':
            admin_profile = getattr(user, 'admin_profile', None)
            if admin_profile and admin_profile.managed_library:
                queryset = queryset.filter(library=admin_profile.managed_library)
            else:
                queryset = queryset.none()
        else:
            accessible_libraries = user.library_access.filter(
                is_active=True
            ).values_list('library_id', flat=True)
            queryset = queryset.filter(library_id__in=accessible_libraries)
    
    # Apply sorting
    sort_by = data.get('sort_by', 'seat_number')
    if sort_by == 'rating':
        queryset = queryset.order_by('-average_rating')
    elif sort_by == 'availability':
        # This would require more complex logic
        queryset = queryset.order_by('status', 'seat_number')
    else:
        queryset = queryset.order_by('seat_number')
    
    # Serialize results
    serializer = SeatListSerializer(queryset, many=True, context={'request': request})
    
    return Response({
        'count': queryset.count(),
        'results': serializer.data
    })


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def check_seat_availability(request):
    """Check seat availability for specific date/time"""
    serializer = SeatAvailabilitySerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    
    data = serializer.validated_data
    seat = get_object_or_404(Seat, id=data['seat_id'], is_deleted=False)
    
    # Check if user can access this seat's library
    if not seat.library.can_user_access(request.user):
        return Response(
            {'error': "You don't have access to this library"},
            status=status.HTTP_403_FORBIDDEN
        )
    
    availability_date = data['date']
    
    if data.get('start_time') and data.get('end_time'):
        # Check specific time slot
        can_book, message = seat.can_user_book(
            request.user,
            data['start_time'],
            data['end_time'],
            availability_date
        )
        
        return Response({
            'available': can_book,
            'message': message,
            'seat': SeatListSerializer(seat).data
        })
    else:
        # Get all available slots for the day
        available_slots = seat.get_availability_for_date(availability_date)
        
        return Response({
            'seat': SeatListSerializer(seat).data,
            'date': availability_date,
            'available_slots': available_slots
        })


class SeatBookingListCreateView(generics.ListCreateAPIView):
    """List and create seat bookings"""
    permission_classes = [permissions.IsAuthenticated, CanManageBookings]
    
    def get_serializer_class(self):
        if self.request.method == 'POST':
            return SeatBookingCreateSerializer
        return SeatBookingSerializer
    
    def get_queryset(self):
        user = self.request.user
        queryset = SeatBooking.objects.filter(is_deleted=False)
        
        # Filter by user unless admin
        if not user.is_admin:
            queryset = queryset.filter(user=user)
        
        return queryset.select_related('user', 'seat', 'seat__library').order_by('-booking_date', '-start_time')


class SeatBookingDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Seat booking detail view"""
    serializer_class = SeatBookingSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'id'
    
    def get_queryset(self):
        user = self.request.user
        queryset = SeatBooking.objects.filter(is_deleted=False)
        
        # Users can only access their own bookings unless admin
        if not user.is_admin:
            queryset = queryset.filter(user=user)
        
        return queryset.select_related('user', 'seat', 'seat__library')
    
    def destroy(self, request, *args, **kwargs):
        """Cancel booking instead of deleting"""
        booking = self.get_object()
        
        if booking.status not in ['CONFIRMED', 'PENDING']:
            return Response(
                {'error': 'Cannot cancel booking in current status'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        success, message = booking.cancel_booking('Cancelled by user')
        
        if success:
            return Response({'message': message})
        else:
            return Response(
                {'error': message},
                status=status.HTTP_400_BAD_REQUEST
            )


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def generate_qr_code(request, booking_id):
    """Generate QR code for booking"""
    try:
        booking = SeatBooking.objects.get(
            id=booking_id,
            user=request.user,
            is_deleted=False
        )
        
        if booking.status != 'CONFIRMED':
            return Response(
                {'error': 'QR code can only be generated for confirmed bookings'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        qr_data = booking.generate_qr_code()
        
        return Response({
            'qr_data': qr_data,
            'expires_at': booking.qr_code_expires_at
        })
        
    except SeatBooking.DoesNotExist:
        return Response(
            {'error': 'Booking not found'},
            status=status.HTTP_404_NOT_FOUND
        )


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def check_in_seat(request):
    """Check in to a seat"""
    serializer = CheckInSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    
    data = serializer.validated_data
    
    # Get booking
    if data.get('booking_id'):
        try:
            booking = SeatBooking.objects.get(
                id=data['booking_id'],
                user=request.user,
                is_deleted=False
            )
        except SeatBooking.DoesNotExist:
            return Response(
                {'error': 'Booking not found'},
                status=status.HTTP_404_NOT_FOUND
            )
    elif data.get('qr_code_data'):
        try:
            qr_data = json.loads(data['qr_code_data'])
            booking = SeatBooking.objects.get(
                id=qr_data['booking_id'],
                booking_code=qr_data['booking_code'],
                user=request.user,
                is_deleted=False
            )
            
            # Verify access token if provided
            if data.get('access_token') and qr_data.get('access_token') != data['access_token']:
                return Response(
                    {'error': 'Invalid access token'},
                    status=status.HTTP_400_BAD_REQUEST
                )
                
            # Check QR code expiry
            if booking.qr_code_expires_at and timezone.now() > booking.qr_code_expires_at:
                return Response(
                    {'error': 'QR code has expired'},
                    status=status.HTTP_400_BAD_REQUEST
                )
                
        except (json.JSONDecodeError, KeyError, SeatBooking.DoesNotExist):
            return Response(
                {'error': 'Invalid QR code'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    # Perform check-in
    success, message = booking.check_in(data.get('check_in_method', 'QR'))
    
    if success:
        return Response({
            'message': message,
            'booking': SeatBookingSerializer(booking).data
        })
    else:
        return Response(
            {'error': message},
            status=status.HTTP_400_BAD_REQUEST
        )


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def check_out_seat(request):
    """Check out from a seat"""
    serializer = CheckOutSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    
    data = serializer.validated_data
    
    # Get booking
    if data.get('booking_id'):
        try:
            booking = SeatBooking.objects.get(
                id=data['booking_id'],
                user=request.user,
                is_deleted=False
            )
        except SeatBooking.DoesNotExist:
            return Response(
                {'error': 'Booking not found'},
                status=status.HTTP_404_NOT_FOUND
            )
    elif data.get('qr_code_data'):
        try:
            qr_data = json.loads(data['qr_code_data'])
            booking = SeatBooking.objects.get(
                id=qr_data['booking_id'],
                booking_code=qr_data['booking_code'],
                user=request.user,
                is_deleted=False
            )
        except (json.JSONDecodeError, KeyError, SeatBooking.DoesNotExist):
            return Response(
                {'error': 'Invalid QR code'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    # Perform check-out
    success, message = booking.check_out(data.get('check_out_method', 'QR'))
    
    if success:
        return Response({
            'message': message,
            'booking': SeatBookingSerializer(booking).data
        })
    else:
        return Response(
            {'error': message},
            status=status.HTTP_400_BAD_REQUEST
        )


class SeatBookingWaitlistListCreateView(generics.ListCreateAPIView):
    """List and create seat booking waitlist entries"""
    serializer_class = SeatBookingWaitlistSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return SeatBookingWaitlist.objects.filter(
            user=self.request.user,
            is_active=True,
            is_deleted=False
        ).select_related('seat', 'seat__library')


class SeatReviewListCreateView(generics.ListCreateAPIView):
    """List and create seat reviews"""
    serializer_class = SeatReviewSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        seat_id = self.kwargs.get('seat_id')
        queryset = SeatReview.objects.filter(
            is_approved=True,
            is_deleted=False
        ).select_related('user', 'seat')
        
        if seat_id:
            queryset = queryset.filter(seat_id=seat_id)
        
        return queryset.order_by('-created_at')
    
    def perform_create(self, serializer):
        seat_id = self.kwargs.get('seat_id')
        if seat_id:
            seat = get_object_or_404(Seat, id=seat_id, is_deleted=False)
            serializer.save(seat=seat, created_by=self.request.user)
        else:
            serializer.save(created_by=self.request.user)


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_user_booking_summary(request):
    """Get user's booking summary"""
    user = request.user
    today = timezone.now().date()
    
    # Current bookings
    current_bookings = SeatBooking.objects.filter(
        user=user,
        booking_date=today,
        status__in=['CONFIRMED', 'CHECKED_IN'],
        is_deleted=False
    ).select_related('seat', 'seat__library')
    
    # Upcoming bookings
    upcoming_bookings = SeatBooking.objects.filter(
        user=user,
        booking_date__gt=today,
        status='CONFIRMED',
        is_deleted=False
    ).select_related('seat', 'seat__library')[:5]
    
    # Recent bookings
    recent_bookings = SeatBooking.objects.filter(
        user=user,
        booking_date__lt=today,
        is_deleted=False
    ).select_related('seat', 'seat__library')[:5]
    
    # Statistics
    total_bookings = SeatBooking.objects.filter(
        user=user,
        is_deleted=False
    ).count()
    
    completed_bookings = SeatBooking.objects.filter(
        user=user,
        status='COMPLETED',
        is_deleted=False
    ).count()
    
    no_shows = SeatBooking.objects.filter(
        user=user,
        status='NO_SHOW',
        is_deleted=False
    ).count()
    
    return Response({
        'current_bookings': SeatBookingSerializer(current_bookings, many=True).data,
        'upcoming_bookings': SeatBookingSerializer(upcoming_bookings, many=True).data,
        'recent_bookings': SeatBookingSerializer(recent_bookings, many=True).data,
        'statistics': {
            'total_bookings': total_bookings,
            'completed_bookings': completed_bookings,
            'no_shows': no_shows,
            'completion_rate': (completed_bookings / total_bookings * 100) if total_bookings > 0 else 0
        }
    })


# Admin Views
class SeatManagementView(generics.ListCreateAPIView):
    """Admin view for managing seats"""
    serializer_class = SeatSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def get_queryset(self):
        if self.request.user.is_super_admin:
            return Seat.objects.filter(is_deleted=False)
        elif self.request.user.role == 'ADMIN':
            admin_profile = getattr(self.request.user, 'admin_profile', None)
            if admin_profile and admin_profile.managed_library:
                return Seat.objects.filter(
                    library=admin_profile.managed_library,
                    is_deleted=False
                )
        return Seat.objects.none()
    
    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)


class SeatMaintenanceLogListCreateView(generics.ListCreateAPIView):
    """List and create seat maintenance logs"""
    serializer_class = SeatMaintenanceLogSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def get_queryset(self):
        seat_id = self.kwargs.get('seat_id')
        queryset = SeatMaintenanceLog.objects.filter(is_deleted=False)
        
        if seat_id:
            queryset = queryset.filter(seat_id=seat_id)
        
        # Filter based on user permissions
        if not self.request.user.is_super_admin:
            admin_profile = getattr(self.request.user, 'admin_profile', None)
            if admin_profile and admin_profile.managed_library:
                queryset = queryset.filter(seat__library=admin_profile.managed_library)
            else:
                queryset = queryset.none()
        
        return queryset.select_related('seat', 'assigned_to', 'performed_by').order_by('-scheduled_date')
    
    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)


class SeatUsageStatisticsView(generics.ListAPIView):
    """View seat usage statistics"""
    serializer_class = SeatUsageStatisticsSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def get_queryset(self):
        seat_id = self.kwargs.get('seat_id')
        queryset = SeatUsageStatistics.objects.all()
        
        if seat_id:
            queryset = queryset.filter(seat_id=seat_id)
        
        # Filter based on user permissions
        if not self.request.user.is_super_admin:
            admin_profile = getattr(self.request.user, 'admin_profile', None)
            if admin_profile and admin_profile.managed_library:
                queryset = queryset.filter(seat__library=admin_profile.managed_library)
            else:
                queryset = queryset.none()
        
        return queryset.select_related('seat').order_by('-date')