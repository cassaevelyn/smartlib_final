"""
Serializers for seats app
"""
from rest_framework import serializers
from django.utils import timezone
from apps.core.serializers import BaseModelSerializer
from .models import (
    Seat, SeatBooking, SeatBookingWaitlist, SeatReview,
    SeatMaintenanceLog, SeatUsageStatistics
)


class SeatSerializer(BaseModelSerializer):
    """Serializer for seat details"""
    library_name = serializers.CharField(source='library.name', read_only=True)
    floor_name = serializers.CharField(source='floor.floor_name', read_only=True)
    section_name = serializers.CharField(source='section.name', read_only=True)
    seat_type_display = serializers.CharField(source='get_seat_type_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    is_available = serializers.ReadOnlyField()
    current_booking = serializers.SerializerMethodField()
    
    class Meta:
        model = Seat
        fields = [
            'id', 'library', 'library_name', 'floor', 'floor_name',
            'section', 'section_name', 'seat_number', 'seat_code',
            'seat_type', 'seat_type_display', 'status', 'status_display',
            'is_available', 'has_power_outlet', 'has_ethernet', 'has_monitor',
            'has_whiteboard', 'is_near_window', 'is_accessible',
            'x_coordinate', 'y_coordinate', 'rotation', 'is_bookable',
            'requires_approval', 'is_premium', 'max_booking_duration_hours',
            'total_bookings', 'total_usage_hours', 'average_rating',
            'description', 'features', 'current_booking', 'created_at'
        ]
        read_only_fields = [
            'id', 'seat_code', 'total_bookings', 'total_usage_hours',
            'average_rating', 'created_at'
        ]
    
    def get_current_booking(self, obj):
        current_booking = obj.current_booking
        if current_booking:
            return {
                'id': current_booking.id,
                'booking_code': current_booking.booking_code,
                'user': current_booking.user.get_full_name(),
                'start_time': current_booking.start_time,
                'end_time': current_booking.end_time,
                'status': current_booking.status
            }
        return None


class SeatListSerializer(serializers.ModelSerializer):
    """Simplified serializer for seat list view"""
    seat_type_display = serializers.CharField(source='get_seat_type_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    is_available = serializers.ReadOnlyField()
    
    class Meta:
        model = Seat
        fields = [
            'id', 'seat_number', 'seat_code', 'seat_type', 'seat_type_display',
            'status', 'status_display', 'is_available', 'has_power_outlet',
            'has_ethernet', 'has_monitor', 'is_near_window', 'is_accessible',
            'is_premium', 'x_coordinate', 'y_coordinate', 'average_rating'
        ]


class SeatAvailabilitySerializer(serializers.Serializer):
    """Serializer for seat availability check"""
    seat_id = serializers.UUIDField()
    date = serializers.DateField()
    start_time = serializers.TimeField(required=False)
    end_time = serializers.TimeField(required=False)
    
    def validate_date(self, value):
        if value < timezone.now().date():
            raise serializers.ValidationError("Cannot check availability for past dates")
        return value
    
    def validate(self, attrs):
        if attrs.get('start_time') and attrs.get('end_time'):
            if attrs['start_time'] >= attrs['end_time']:
                raise serializers.ValidationError("Start time must be before end time")
        return attrs


class SeatBookingSerializer(BaseModelSerializer):
    """Serializer for seat bookings"""
    user_display = serializers.CharField(source='user.get_full_name', read_only=True)
    seat_display = serializers.CharField(source='seat.seat_number', read_only=True)
    library_name = serializers.CharField(source='seat.library.name', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    booking_type_display = serializers.CharField(source='get_booking_type_display', read_only=True)
    duration_hours = serializers.ReadOnlyField()
    actual_duration_hours = serializers.ReadOnlyField()
    is_active = serializers.ReadOnlyField()
    can_check_in = serializers.ReadOnlyField()
    can_check_out = serializers.ReadOnlyField()
    
    class Meta:
        model = SeatBooking
        fields = [
            'id', 'user', 'user_display', 'seat', 'seat_display',
            'library_name', 'booking_code', 'booking_type',
            'booking_type_display', 'booking_date', 'start_time',
            'end_time', 'status', 'status_display', 'duration_hours',
            'actual_start_time', 'actual_end_time', 'actual_duration_hours',
            'checked_in_at', 'checked_out_at', 'is_active',
            'can_check_in', 'can_check_out', 'auto_cancel_at',
            'reminder_sent', 'late_cancellation', 'purpose',
            'special_requirements', 'notes', 'penalty_points',
            'loyalty_points_earned', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'booking_code', 'actual_start_time', 'actual_end_time',
            'checked_in_at', 'checked_out_at', 'auto_cancel_at',
            'reminder_sent', 'late_cancellation', 'penalty_points',
            'loyalty_points_earned', 'created_at', 'updated_at'
        ]
    
    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


class SeatBookingCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating seat bookings"""
    
    class Meta:
        model = SeatBooking
        fields = [
            'seat', 'booking_date', 'start_time', 'end_time',
            'booking_type', 'purpose', 'special_requirements', 'notes'
        ]
    
    def validate(self, attrs):
        seat = attrs['seat']
        booking_date = attrs['booking_date']
        start_time = attrs['start_time']
        end_time = attrs['end_time']
        user = self.context['request'].user
        
        # Check if seat can be booked
        can_book, message = seat.can_user_book(user, start_time, end_time, booking_date)
        if not can_book:
            raise serializers.ValidationError(message)
        
        return attrs
    
    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        validated_data['created_by'] = self.context['request'].user
        return super().create(validated_data)


class SeatBookingWaitlistSerializer(BaseModelSerializer):
    """Serializer for seat booking waitlist"""
    user_display = serializers.CharField(source='user.get_full_name', read_only=True)
    seat_display = serializers.CharField(source='seat.seat_number', read_only=True)
    
    class Meta:
        model = SeatBookingWaitlist
        fields = [
            'id', 'user', 'user_display', 'seat', 'seat_display',
            'booking_date', 'preferred_start_time', 'preferred_end_time',
            'flexible_timing', 'acceptable_duration_hours', 'is_active',
            'notified_at', 'expires_at', 'priority_score', 'created_at'
        ]
        read_only_fields = [
            'id', 'notified_at', 'priority_score', 'created_at'
        ]
    
    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        
        # Set expiry time (24 hours from now)
        validated_data['expires_at'] = timezone.now() + timezone.timedelta(hours=24)
        
        return super().create(validated_data)


class SeatReviewSerializer(BaseModelSerializer):
    """Serializer for seat reviews"""
    user_display = serializers.CharField(source='user.get_full_name', read_only=True)
    seat_display = serializers.CharField(source='seat.seat_number', read_only=True)
    
    class Meta:
        model = SeatReview
        fields = [
            'id', 'user', 'user_display', 'seat', 'seat_display',
            'booking', 'overall_rating', 'comfort_rating',
            'cleanliness_rating', 'noise_level_rating', 'facilities_rating',
            'title', 'review_text', 'reported_issues', 'is_approved',
            'created_at'
        ]
        read_only_fields = [
            'id', 'is_approved', 'approved_by', 'created_at'
        ]
    
    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


class SeatMaintenanceLogSerializer(BaseModelSerializer):
    """Serializer for seat maintenance logs"""
    seat_display = serializers.CharField(source='seat.seat_number', read_only=True)
    maintenance_type_display = serializers.CharField(
        source='get_maintenance_type_display', read_only=True
    )
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    assigned_to_display = serializers.CharField(
        source='assigned_to.get_full_name', read_only=True
    )
    performed_by_display = serializers.CharField(
        source='performed_by.get_full_name', read_only=True
    )
    
    class Meta:
        model = SeatMaintenanceLog
        fields = [
            'id', 'seat', 'seat_display', 'maintenance_type',
            'maintenance_type_display', 'status', 'status_display',
            'scheduled_date', 'started_at', 'completed_at',
            'assigned_to', 'assigned_to_display', 'performed_by',
            'performed_by_display', 'description', 'issues_found',
            'actions_taken', 'parts_used', 'cost', 'requires_follow_up',
            'follow_up_date', 'follow_up_notes', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']


class SeatUsageStatisticsSerializer(serializers.ModelSerializer):
    """Serializer for seat usage statistics"""
    seat_display = serializers.CharField(source='seat.seat_number', read_only=True)
    
    class Meta:
        model = SeatUsageStatistics
        fields = [
            'id', 'seat', 'seat_display', 'date', 'total_bookings',
            'successful_checkins', 'no_shows', 'cancellations',
            'total_booked_hours', 'total_used_hours',
            'average_session_duration', 'utilization_rate',
            'peak_usage_hour', 'unique_users', 'repeat_users'
        ]
        read_only_fields = ['id']


class QRCodeDataSerializer(serializers.Serializer):
    """Serializer for QR code data"""
    booking_id = serializers.UUIDField()
    booking_code = serializers.CharField()
    access_token = serializers.CharField()
    seat_code = serializers.CharField()
    user_id = serializers.UUIDField()
    expires_at = serializers.DateTimeField()


class CheckInSerializer(serializers.Serializer):
    """Serializer for check-in process"""
    booking_id = serializers.UUIDField(required=False)
    qr_code_data = serializers.CharField(required=False)
    access_token = serializers.CharField(required=False)
    check_in_method = serializers.ChoiceField(
        choices=[('QR', 'QR Code'), ('MANUAL', 'Manual'), ('NFC', 'NFC')],
        default='QR'
    )
    
    def validate(self, attrs):
        if not any([attrs.get('booking_id'), attrs.get('qr_code_data')]):
            raise serializers.ValidationError(
                "Either booking_id or qr_code_data is required"
            )
        return attrs


class CheckOutSerializer(serializers.Serializer):
    """Serializer for check-out process"""
    booking_id = serializers.UUIDField(required=False)
    qr_code_data = serializers.CharField(required=False)
    access_token = serializers.CharField(required=False)
    check_out_method = serializers.ChoiceField(
        choices=[('QR', 'QR Code'), ('MANUAL', 'Manual'), ('NFC', 'NFC')],
        default='QR'
    )
    
    def validate(self, attrs):
        if not any([attrs.get('booking_id'), attrs.get('qr_code_data')]):
            raise serializers.ValidationError(
                "Either booking_id or qr_code_data is required"
            )
        return attrs


class SeatSearchSerializer(serializers.Serializer):
    """Serializer for seat search parameters"""
    library_id = serializers.UUIDField(required=False)
    floor_id = serializers.UUIDField(required=False)
    section_id = serializers.UUIDField(required=False)
    seat_type = serializers.ChoiceField(choices=Seat.SEAT_TYPES, required=False)
    date = serializers.DateField(required=False)
    start_time = serializers.TimeField(required=False)
    end_time = serializers.TimeField(required=False)
    has_power_outlet = serializers.BooleanField(required=False)
    has_ethernet = serializers.BooleanField(required=False)
    has_monitor = serializers.BooleanField(required=False)
    is_near_window = serializers.BooleanField(required=False)
    is_accessible = serializers.BooleanField(required=False)
    is_premium = serializers.BooleanField(required=False)
    min_rating = serializers.DecimalField(
        max_digits=3, decimal_places=2, required=False, min_value=0, max_value=5
    )
    sort_by = serializers.ChoiceField(
        choices=[
            ('seat_number', 'Seat Number'),
            ('rating', 'Rating'),
            ('availability', 'Availability'),
            ('features', 'Features'),
        ],
        required=False,
        default='seat_number'
    )
    
    def validate(self, attrs):
        if attrs.get('start_time') and attrs.get('end_time'):
            if attrs['start_time'] >= attrs['end_time']:
                raise serializers.ValidationError("Start time must be before end time")
        
        if attrs.get('date'):
            if attrs['date'] < timezone.now().date():
                raise serializers.ValidationError("Cannot search for past dates")
        
        return attrs