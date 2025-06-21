# apps/library/serializers.py
"""
Serializers for library app
"""
from rest_framework import serializers
from django.db.models import Avg
from apps.core.serializers import BaseModelSerializer
from .models import (
    Library, LibraryFloor, LibrarySection, LibraryAmenity,
    LibraryOperatingHours, LibraryHoliday, LibraryReview,
    LibraryStatistics, LibraryNotification, LibraryConfiguration
)


class LibraryAmenitySerializer(BaseModelSerializer):
    """Serializer for library amenities"""
    
    class Meta:
        model = LibraryAmenity
        fields = [
            'id', 'name', 'amenity_type', 'description', 'icon',
            'is_available', 'is_premium', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']


class LibraryOperatingHoursSerializer(serializers.ModelSerializer):
    """Serializer for library operating hours"""
    day_name = serializers.CharField(source='get_day_of_week_display', read_only=True)
    
    class Meta:
        model = LibraryOperatingHours
        fields = [
            'id', 'day_of_week', 'day_name', 'opening_time',
            'closing_time', 'is_closed', 'is_24_hours'
        ]
        read_only_fields = ['id']


class LibraryHolidaySerializer(BaseModelSerializer):
    """Serializer for library holidays"""
    holiday_type_display = serializers.CharField(
        source='get_holiday_type_display', read_only=True
    )
    is_active_today = serializers.BooleanField(read_only=True)
    
    class Meta:
        model = LibraryHoliday
        fields = [
            'id', 'name', 'holiday_type', 'holiday_type_display',
            'start_date', 'end_date', 'description', 'is_recurring',
            'is_active_today', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']


class LibrarySectionSerializer(BaseModelSerializer):
    """Serializer for library sections"""
    section_type_display = serializers.CharField(
        source='get_section_type_display', read_only=True
    )
    available_seats = serializers.ReadOnlyField()
    is_section_full = serializers.BooleanField(read_only=True)
    
    class Meta:
        model = LibrarySection
        fields = [
            'id', 'name', 'section_type', 'section_type_display',
            'description', 'total_seats', 'available_seats', 'max_occupancy',
            'is_section_full', 'has_power_outlets', 'has_ethernet',
            'has_whiteboard', 'has_projector', 'noise_level',
            'requires_booking', 'advance_booking_hours',
            'max_booking_duration', 'layout_coordinates', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']


class LibraryFloorSerializer(BaseModelSerializer):
    """Serializer for library floors"""
    sections = LibrarySectionSerializer(many=True, read_only=True)
    available_seats = serializers.ReadOnlyField()
    occupancy_rate = serializers.ReadOnlyField()
    
    class Meta:
        model = LibraryFloor
        fields = [
            'id', 'floor_number', 'floor_name', 'description',
            'total_seats', 'available_seats', 'occupancy_rate',
            'study_rooms', 'has_silent_zone', 'has_group_study',
            'has_computer_lab', 'has_printer', 'has_restroom',
            'floor_plan_image', 'layout_data', 'sections', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']


class LibraryListSerializer(serializers.ModelSerializer):
    """Serializer for library list view"""
    library_type_display = serializers.CharField(
        source='get_library_type_display', read_only=True
    )
    status_display = serializers.CharField(
        source='get_status_display', read_only=True
    )
    is_open = serializers.ReadOnlyField()
    available_seats = serializers.ReadOnlyField()
    occupancy_rate = serializers.SerializerMethodField()
    distance = serializers.SerializerMethodField()
    
    class Meta:
        model = Library
        fields = [
            'id', 'name', 'code', 'library_type', 'library_type_display',
            'status', 'status_display', 'city', 'address', 'phone_number',
            'is_open', 'opening_time', 'closing_time', 'is_24_hours',
            'total_seats', 'available_seats', 'occupancy_rate',
            'has_wifi', 'has_parking', 'main_image', 'average_rating',
            'total_reviews', 'distance'
        ]
    
    def get_occupancy_rate(self, obj):
        return round(obj.get_occupancy_rate(), 1)
    
    def get_distance(self, obj):
        # Calculate distance from user's location if provided
        request = self.context.get('request')
        if request and hasattr(request, 'user_location'):
            # Implement distance calculation logic here
            return None
        return None


class LibraryDetailSerializer(BaseModelSerializer):
    """Serializer for library detail view"""
    library_type_display = serializers.CharField(
        source='get_library_type_display', read_only=True
    )
    status_display = serializers.CharField(
        source='get_status_display', read_only=True
    )
    is_open = serializers.ReadOnlyField()
    available_seats = serializers.ReadOnlyField()
    occupied_seats = serializers.ReadOnlyField()
    occupancy_rate = serializers.SerializerMethodField()
    
    # Related data
    floors = LibraryFloorSerializer(many=True, read_only=True)
    amenities = LibraryAmenitySerializer(many=True, read_only=True)
    operating_hours = LibraryOperatingHoursSerializer(many=True, read_only=True)
    active_holidays = serializers.SerializerMethodField()
    recent_reviews = serializers.SerializerMethodField()
    
    class Meta:
        model = Library
        fields = [
            'id', 'name', 'code', 'library_type', 'library_type_display',
            'status', 'status_display', 'description', 'address', 'city',
            'postal_code', 'latitude', 'longitude', 'phone_number',
            'email', 'website', 'is_open', 'opening_time', 'closing_time',
            'is_24_hours', 'total_capacity', 'total_seats', 'available_seats',
            'occupied_seats', 'occupancy_rate', 'total_study_rooms',
            'has_wifi', 'has_printing', 'has_scanning', 'has_cafeteria',
            'has_parking', 'main_image', 'gallery_images', 'floor_plan',
            'allow_booking', 'booking_advance_days', 'max_booking_duration_hours',
            'auto_cancel_minutes', 'average_rating', 'total_reviews',
            'amenities', 'rules', 'floors', 'amenities', 'operating_hours',
            'active_holidays', 'recent_reviews', 'created_at'
        ]
        read_only_fields = [
            'id', 'code', 'total_visits', 'average_rating', 'total_reviews',
            'created_at'
        ]
    
    def get_occupancy_rate(self, obj):
        return round(obj.get_occupancy_rate(), 1)
    
    def get_active_holidays(self, obj):
        from django.utils import timezone
        today = timezone.now().date()
        holidays = obj.holidays.filter(
            start_date__lte=today,
            end_date__gte=today,
            is_deleted=False
        )
        return LibraryHolidaySerializer(holidays, many=True).data
    
    def get_recent_reviews(self, obj):
        reviews = obj.reviews.filter(
            is_approved=True,
            is_deleted=False
        ).select_related('user')[:5]
        return LibraryReviewSerializer(reviews, many=True).data


class LibraryReviewSerializer(BaseModelSerializer):
    """Serializer for library reviews"""
    user_display = serializers.CharField(source='user.get_full_name', read_only=True)
    user_avatar = serializers.ImageField(source='user.avatar', read_only=True)
    approved_by_display = serializers.CharField(
        source='approved_by.get_full_name', read_only=True
    )
    
    class Meta:
        model = LibraryReview
        fields = [
            'id', 'user', 'user_display', 'user_avatar', 'rating',
            'title', 'review_text', 'cleanliness_rating', 'noise_level_rating',
            'facilities_rating', 'staff_rating', 'is_approved',
            'approved_by', 'approved_by_display', 'approved_at',
            'helpful_count', 'reported_count', 'created_at'
        ]
        read_only_fields = [
            'id', 'is_approved', 'approved_by', 'approved_at',
            'helpful_count', 'reported_count', 'created_at'
        ]
    
    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


class LibraryNotificationSerializer(BaseModelSerializer):
    """Serializer for library notifications"""
    notification_type_display = serializers.CharField(
        source='get_notification_type_display', read_only=True
    )
    priority_display = serializers.CharField(
        source='get_priority_display', read_only=True
    )
    is_currently_active = serializers.BooleanField(read_only=True)
    
    class Meta:
        model = LibraryNotification
        fields = [
            'id', 'title', 'message', 'notification_type',
            'notification_type_display', 'priority', 'priority_display',
            'target_all_users', 'target_user_roles', 'start_date',
            'end_date', 'is_active', 'is_currently_active',
            'show_on_dashboard', 'show_on_booking', 'requires_acknowledgment',
            'views_count', 'acknowledgments_count', 'created_at'
        ]
        read_only_fields = [
            'id', 'views_count', 'acknowledgments_count', 'created_at'
        ]


class LibraryStatisticsSerializer(serializers.ModelSerializer):
    """Serializer for library statistics"""
    library_display = serializers.CharField(source='library.name', read_only=True)
    
    class Meta:
        model = LibraryStatistics
        fields = [
            'id', 'library', 'library_display', 'date', 'total_visitors',
            'unique_visitors', 'total_bookings', 'successful_checkins',
            'no_shows', 'cancellations', 'peak_occupancy', 'average_occupancy',
            'peak_hour', 'average_session_duration', 'total_study_hours',
            'subscription_revenue', 'penalty_revenue', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']


class LibraryConfigurationSerializer(BaseModelSerializer):
    """Serializer for library configuration"""
    library_display = serializers.CharField(source='library.name', read_only=True)
    
    class Meta:
        model = LibraryConfiguration
        fields = [
            'id', 'library', 'library_display', 'max_advance_booking_days',
            'max_daily_bookings_per_user', 'max_booking_duration_hours',
            'min_booking_duration_minutes', 'auto_cancel_no_show_minutes',
            'early_checkin_minutes', 'late_checkout_grace_minutes',
            'qr_code_expiry_minutes', 'no_show_penalty_points',
            'late_cancellation_penalty_points', 'overstay_penalty_per_hour',
            'booking_completion_points', 'review_submission_points',
            'referral_points', 'reminder_hours_before',
            'send_booking_confirmations', 'send_checkin_reminders',
            'send_checkout_reminders', 'enable_seat_selection',
            'enable_recurring_bookings', 'enable_group_bookings',
            'enable_waitlist', 'enable_reviews', 'integration_settings',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class LibrarySearchSerializer(serializers.Serializer):
    """Serializer for library search parameters"""
    query = serializers.CharField(required=False, allow_blank=True)
    city = serializers.CharField(required=False, allow_blank=True)
    library_type = serializers.ChoiceField(
        choices=Library.LIBRARY_TYPES,
        required=False,
        allow_blank=True
    )
    has_wifi = serializers.BooleanField(required=False)
    has_parking = serializers.BooleanField(required=False)
    has_cafeteria = serializers.BooleanField(required=False)
    is_24_hours = serializers.BooleanField(required=False)
    min_available_seats = serializers.IntegerField(required=False, min_value=0)
    latitude = serializers.DecimalField(
        max_digits=9, decimal_places=6, required=False
    )
    longitude = serializers.DecimalField(
        max_digits=9, decimal_places=6, required=False
    )
    radius_km = serializers.IntegerField(required=False, min_value=1, max_value=100)
    sort_by = serializers.ChoiceField(
        choices=[
            ('name', 'Name'),
            ('distance', 'Distance'),
            ('rating', 'Rating'),
            ('available_seats', 'Available Seats'),
            ('created_at', 'Newest'),
        ],
        required=False,
        default='name'
    )


# Admin Serializers
class LibraryAdminSerializer(BaseModelSerializer):
    """Admin serializer for Library model (full control)"""
    class Meta:
        model = Library
        fields = '__all__' # Include all fields for admin control


class LibraryFloorAdminSerializer(BaseModelSerializer):
    """Admin serializer for LibraryFloor model"""
    class Meta:
        model = LibraryFloor
        fields = '__all__'


class LibrarySectionAdminSerializer(BaseModelSerializer):
    """Admin serializer for LibrarySection model"""
    class Meta:
        model = LibrarySection
        fields = '__all__'


class LibraryAmenityAdminSerializer(BaseModelSerializer):
    """Admin serializer for LibraryAmenity model"""
    class Meta:
        model = LibraryAmenity
        fields = '__all__'


class LibraryOperatingHoursAdminSerializer(BaseModelSerializer):
    """Admin serializer for LibraryOperatingHours model"""
    class Meta:
        model = LibraryOperatingHours
        fields = '__all__'


class LibraryHolidayAdminSerializer(BaseModelSerializer):
    """Admin serializer for LibraryHoliday model"""
    class Meta:
        model = LibraryHoliday
        fields = '__all__'

