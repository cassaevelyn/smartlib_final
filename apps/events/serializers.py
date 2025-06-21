"""
Serializers for events app
"""
from rest_framework import serializers
from django.utils import timezone
from apps.core.serializers import BaseModelSerializer
from .models import (
    EventCategory, EventSpeaker, Event, EventRegistration,
    EventFeedback, EventWaitlist, EventResource, EventStatistics,
    EventSeries, EventNotification
)


class EventCategorySerializer(BaseModelSerializer):
    """Serializer for event categories"""
    events_count = serializers.ReadOnlyField()
    
    class Meta:
        model = EventCategory
        fields = [
            'id', 'name', 'code', 'description', 'icon', 'color',
            'is_active', 'sort_order', 'events_count', 'created_at'
        ]
        read_only_fields = ['id', 'code', 'created_at']


class EventSpeakerSerializer(BaseModelSerializer):
    """Serializer for event speakers"""
    full_name = serializers.ReadOnlyField()
    
    class Meta:
        model = EventSpeaker
        fields = [
            'id', 'first_name', 'last_name', 'full_name', 'title',
            'organization', 'bio', 'expertise', 'email', 'phone',
            'website', 'linkedin', 'photo', 'total_events',
            'average_rating', 'created_at'
        ]
        read_only_fields = ['id', 'total_events', 'average_rating', 'created_at']


class EventListSerializer(serializers.ModelSerializer):
    """Simplified serializer for event list view"""
    category_name = serializers.CharField(source='category.name', read_only=True)
    library_name = serializers.CharField(source='library.name', read_only=True)
    organizer_name = serializers.CharField(source='organizer.get_full_name', read_only=True)
    event_type_display = serializers.CharField(source='get_event_type_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    registration_type_display = serializers.CharField(
        source='get_registration_type_display', read_only=True
    )
    is_registration_open = serializers.ReadOnlyField()
    is_full = serializers.ReadOnlyField()
    available_spots = serializers.ReadOnlyField()
    duration_hours = serializers.ReadOnlyField()
    speakers_list = serializers.ReadOnlyField()
    
    class Meta:
        model = Event
        fields = [
            'id', 'title', 'slug', 'event_code', 'category_name',
            'event_type', 'event_type_display', 'status', 'status_display',
            'start_date', 'end_date', 'start_time', 'end_time',
            'library_name', 'organizer_name', 'speakers_list',
            'registration_type', 'registration_type_display',
            'registration_fee', 'max_participants', 'total_registrations',
            'is_registration_open', 'is_full', 'available_spots',
            'registration_deadline', 'duration_hours', 'is_online',
            'banner_image', 'thumbnail', 'average_rating', 'total_feedback'
        ]


class EventDetailSerializer(BaseModelSerializer):
    """Detailed serializer for event detail view"""
    category = EventCategorySerializer(read_only=True)
    speakers = EventSpeakerSerializer(many=True, read_only=True)
    organizer_name = serializers.CharField(source='organizer.get_full_name', read_only=True)
    co_organizers_names = serializers.SerializerMethodField()
    library_name = serializers.CharField(source='library.name', read_only=True)
    event_type_display = serializers.CharField(source='get_event_type_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    registration_type_display = serializers.CharField(
        source='get_registration_type_display', read_only=True
    )
    is_registration_open = serializers.ReadOnlyField()
    is_full = serializers.ReadOnlyField()
    available_spots = serializers.ReadOnlyField()
    duration_hours = serializers.ReadOnlyField()
    user_can_register = serializers.SerializerMethodField()
    user_registration_status = serializers.SerializerMethodField()
    user_registration_fee = serializers.SerializerMethodField()
    similar_events = serializers.SerializerMethodField()
    
    class Meta:
        model = Event
        fields = [
            'id', 'title', 'slug', 'event_code', 'category', 'event_type',
            'event_type_display', 'status', 'status_display', 'description',
            'agenda', 'learning_objectives', 'prerequisites', 'materials_provided',
            'speakers', 'organizer', 'organizer_name', 'co_organizers_names',
            'start_date', 'end_date', 'start_time', 'end_time', 'timezone',
            'is_recurring', 'recurrence_pattern', 'library', 'library_name',
            'venue_details', 'is_online', 'online_meeting_link',
            'registration_type', 'registration_type_display', 'registration_fee',
            'max_participants', 'min_participants', 'total_registrations',
            'total_attendees', 'is_registration_open', 'is_full',
            'available_spots', 'registration_deadline', 'early_bird_deadline',
            'early_bird_discount', 'target_audience', 'required_role',
            'required_subscription', 'duration_hours', 'banner_image',
            'thumbnail', 'gallery_images', 'attachments', 'has_certificate',
            'has_feedback_form', 'requires_attendance_tracking',
            'average_rating', 'total_feedback', 'send_reminders',
            'reminder_hours', 'tags', 'external_links', 'additional_info',
            'user_can_register', 'user_registration_status',
            'user_registration_fee', 'similar_events', 'created_at'
        ]
        read_only_fields = [
            'id', 'event_code', 'slug', 'total_registrations', 'total_attendees',
            'average_rating', 'total_feedback', 'created_at'
        ]
    
    def get_co_organizers_names(self, obj):
        return [co_org.get_full_name() for co_org in obj.co_organizers.all()]
    
    def get_user_can_register(self, obj):
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            can_register, _ = obj.can_user_register(request.user)
            return can_register
        return False
    
    def get_user_registration_status(self, obj):
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            registration = obj.registrations.filter(
                user=request.user,
                is_deleted=False
            ).first()
            return registration.status if registration else None
        return None
    
    def get_user_registration_fee(self, obj):
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            return obj.get_registration_fee_for_user(request.user)
        return obj.registration_fee
    
    def get_similar_events(self, obj):
        similar_events = Event.objects.filter(
            category=obj.category,
            is_deleted=False,
            status__in=['PUBLISHED', 'REGISTRATION_OPEN']
        ).exclude(id=obj.id)[:3]
        return EventListSerializer(similar_events, many=True).data


class EventRegistrationSerializer(BaseModelSerializer):
    """Serializer for event registrations"""
    user_display = serializers.CharField(source='user.get_full_name', read_only=True)
    event_title = serializers.CharField(source='event.title', read_only=True)
    event_banner = serializers.ImageField(source='event.banner_image', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    payment_status_display = serializers.CharField(
        source='get_payment_status_display', read_only=True
    )
    can_check_in = serializers.ReadOnlyField()
    can_check_out = serializers.ReadOnlyField()
    
    class Meta:
        model = EventRegistration
        fields = [
            'id', 'user', 'user_display', 'event', 'event_title',
            'event_banner', 'registration_code', 'status', 'status_display',
            'registration_date', 'registration_fee_paid', 'payment_status',
            'payment_status_display', 'payment_reference', 'can_check_in',
            'can_check_out', 'check_in_time', 'check_out_time',
            'attendance_duration', 'qr_code_expires_at', 'dietary_requirements',
            'special_needs', 'emergency_contact', 'how_did_you_hear',
            'expectations', 'certificate_issued', 'certificate_file',
            'feedback_submitted', 'created_at'
        ]
        read_only_fields = [
            'id', 'registration_code', 'registration_date', 'check_in_time',
            'check_out_time', 'attendance_duration', 'qr_code_expires_at',
            'certificate_issued', 'certificate_file', 'feedback_submitted',
            'created_at'
        ]
    
    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


class EventRegistrationCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating event registrations"""
    
    class Meta:
        model = EventRegistration
        fields = [
            'event', 'dietary_requirements', 'special_needs',
            'emergency_contact', 'how_did_you_hear', 'expectations'
        ]
    
    def validate(self, attrs):
        event = attrs['event']
        user = self.context['request'].user
        
        # Check if user can register
        can_register, message = event.can_user_register(user)
        if not can_register:
            raise serializers.ValidationError(message)
        
        return attrs
    
    def create(self, validated_data):
        event = validated_data['event']
        user = self.context['request'].user
        
        # Calculate registration fee
        registration_fee = event.get_registration_fee_for_user(user)
        
        validated_data['user'] = user
        validated_data['registration_fee_paid'] = registration_fee
        validated_data['payment_status'] = 'NOT_REQUIRED' if registration_fee == 0 else 'PENDING'
        validated_data['created_by'] = user
        
        registration = super().create(validated_data)
        
        # Update event statistics
        event.total_registrations += 1
        event.save()
        
        return registration


class EventFeedbackSerializer(BaseModelSerializer):
    """Serializer for event feedback"""
    user_display = serializers.CharField(source='user.get_full_name', read_only=True)
    event_title = serializers.CharField(source='event.title', read_only=True)
    
    class Meta:
        model = EventFeedback
        fields = [
            'id', 'user', 'user_display', 'event', 'event_title',
            'registration', 'overall_rating', 'content_rating',
            'speaker_rating', 'organization_rating', 'venue_rating',
            'what_you_liked', 'what_could_improve', 'additional_comments',
            'would_recommend', 'would_attend_similar', 'future_topics',
            'preferred_format', 'preferred_duration', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']
    
    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


class EventResourceSerializer(BaseModelSerializer):
    """Serializer for event resources"""
    resource_type_display = serializers.CharField(
        source='get_resource_type_display', read_only=True
    )
    file_size_mb = serializers.SerializerMethodField()
    
    class Meta:
        model = EventResource
        fields = [
            'id', 'title', 'description', 'resource_type',
            'resource_type_display', 'file', 'external_link',
            'is_public', 'available_before_event', 'available_after_event',
            'file_size', 'file_size_mb', 'download_count', 'created_at'
        ]
        read_only_fields = ['id', 'file_size', 'download_count', 'created_at']
    
    def get_file_size_mb(self, obj):
        if obj.file_size:
            return round(obj.file_size / (1024 * 1024), 2)
        return None


class EventWaitlistSerializer(BaseModelSerializer):
    """Serializer for event waitlist"""
    user_display = serializers.CharField(source='user.get_full_name', read_only=True)
    event_title = serializers.CharField(source='event.title', read_only=True)
    
    class Meta:
        model = EventWaitlist
        fields = [
            'id', 'user', 'user_display', 'event', 'event_title',
            'position', 'notified', 'notification_sent_at',
            'expires_at', 'created_at'
        ]
        read_only_fields = [
            'id', 'position', 'notified', 'notification_sent_at', 'created_at'
        ]
    
    def create(self, validated_data):
        event = validated_data['event']
        
        # Set position as next in line
        last_position = EventWaitlist.objects.filter(
            event=event,
            is_deleted=False
        ).aggregate(max_pos=models.Max('position'))['max_pos'] or 0
        
        validated_data['user'] = self.context['request'].user
        validated_data['position'] = last_position + 1
        validated_data['expires_at'] = timezone.now() + timezone.timedelta(hours=24)
        
        return super().create(validated_data)


class EventSeriesSerializer(BaseModelSerializer):
    """Serializer for event series"""
    organizer_name = serializers.CharField(source='organizer.get_full_name', read_only=True)
    total_events = serializers.ReadOnlyField()
    upcoming_events = serializers.SerializerMethodField()
    
    class Meta:
        model = EventSeries
        fields = [
            'id', 'name', 'description', 'organizer', 'organizer_name',
            'banner_image', 'is_active', 'requires_series_registration',
            'series_fee', 'total_events', 'upcoming_events', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']
    
    def get_upcoming_events(self, obj):
        upcoming = obj.upcoming_events[:5]
        return EventListSerializer(upcoming, many=True).data


class EventNotificationSerializer(BaseModelSerializer):
    """Serializer for event notifications"""
    event_title = serializers.CharField(source='event.title', read_only=True)
    notification_type_display = serializers.CharField(
        source='get_notification_type_display', read_only=True
    )
    
    class Meta:
        model = EventNotification
        fields = [
            'id', 'event', 'event_title', 'notification_type',
            'notification_type_display', 'title', 'message',
            'send_to_all_registrants', 'send_to_attendees_only',
            'send_to_waitlist', 'send_immediately', 'scheduled_send_time',
            'is_sent', 'sent_at', 'recipients_count', 'created_at'
        ]
        read_only_fields = [
            'id', 'is_sent', 'sent_at', 'recipients_count', 'created_at'
        ]


class EventSearchSerializer(serializers.Serializer):
    """Serializer for event search parameters"""
    query = serializers.CharField(required=False, allow_blank=True)
    category_id = serializers.UUIDField(required=False)
    event_type = serializers.ChoiceField(choices=Event.EVENT_TYPES, required=False)
    library_id = serializers.UUIDField(required=False)
    start_date_from = serializers.DateField(required=False)
    start_date_to = serializers.DateField(required=False)
    is_online = serializers.BooleanField(required=False)
    is_free = serializers.BooleanField(required=False)
    has_certificate = serializers.BooleanField(required=False)
    registration_open = serializers.BooleanField(required=False)
    sort_by = serializers.ChoiceField(
        choices=[
            ('start_date', 'Start Date'),
            ('title', 'Title'),
            ('registration_deadline', 'Registration Deadline'),
            ('popularity', 'Popularity'),
            ('rating', 'Rating'),
        ],
        required=False,
        default='start_date'
    )
    
    def validate(self, attrs):
        if attrs.get('start_date_from') and attrs.get('start_date_to'):
            if attrs['start_date_from'] > attrs['start_date_to']:
                raise serializers.ValidationError(
                    "Start date 'from' must be less than or equal to 'to'"
                )
        return attrs


class QRCodeDataSerializer(serializers.Serializer):
    """Serializer for QR code data"""
    registration_id = serializers.UUIDField()
    registration_code = serializers.CharField()
    event_id = serializers.UUIDField()
    event_code = serializers.CharField()
    user_id = serializers.UUIDField()
    access_token = serializers.CharField()
    generated_at = serializers.DateTimeField()


class CheckInSerializer(serializers.Serializer):
    """Serializer for event check-in process"""
    registration_id = serializers.UUIDField(required=False)
    qr_code_data = serializers.CharField(required=False)
    access_token = serializers.CharField(required=False)
    check_in_method = serializers.ChoiceField(
        choices=[('QR', 'QR Code'), ('MANUAL', 'Manual'), ('NFC', 'NFC')],
        default='QR'
    )
    
    def validate(self, attrs):
        if not any([attrs.get('registration_id'), attrs.get('qr_code_data')]):
            raise serializers.ValidationError(
                "Either registration_id or qr_code_data is required"
            )
        return attrs


class CheckOutSerializer(serializers.Serializer):
    """Serializer for event check-out process"""
    registration_id = serializers.UUIDField(required=False)
    qr_code_data = serializers.CharField(required=False)
    access_token = serializers.CharField(required=False)
    check_out_method = serializers.ChoiceField(
        choices=[('QR', 'QR Code'), ('MANUAL', 'Manual'), ('NFC', 'NFC')],
        default='QR'
    )
    
    def validate(self, attrs):
        if not any([attrs.get('registration_id'), attrs.get('qr_code_data')]):
            raise serializers.ValidationError(
                "Either registration_id or qr_code_data is required"
            )
        return attrs