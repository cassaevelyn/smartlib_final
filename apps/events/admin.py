from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils.safestring import mark_safe
from .models import (
    EventCategory, EventSpeaker, Event, EventRegistration,
    EventFeedback, EventWaitlist, EventResource, EventStatistics,
    EventSeries, EventNotification
)


@admin.register(EventCategory)
class EventCategoryAdmin(admin.ModelAdmin):
    list_display = [
        'name', 'code', 'events_count', 'is_active', 'sort_order', 'created_at'
    ]
    list_filter = ['is_active']
    search_fields = ['name', 'code', 'description']
    ordering = ['sort_order', 'name']
    readonly_fields = ['code', 'created_at', 'updated_at']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'code', 'description')
        }),
        ('Display Settings', {
            'fields': ('icon', 'color', 'sort_order', 'is_active')
        }),
    )


@admin.register(EventSpeaker)
class EventSpeakerAdmin(admin.ModelAdmin):
    list_display = [
        'full_name', 'title', 'organization', 'total_events',
        'average_rating', 'created_at'
    ]
    list_filter = ['organization', 'total_events']
    search_fields = ['first_name', 'last_name', 'title', 'organization']
    ordering = ['last_name', 'first_name']
    readonly_fields = ['total_events', 'average_rating', 'created_at', 'updated_at']
    
    fieldsets = (
        ('Personal Information', {
            'fields': ('first_name', 'last_name', 'title', 'organization', 'photo')
        }),
        ('Professional Details', {
            'fields': ('bio', 'expertise')
        }),
        ('Contact Information', {
            'fields': ('email', 'phone', 'website', 'linkedin')
        }),
        ('Statistics', {
            'fields': ('total_events', 'average_rating'),
            'classes': ('collapse',)
        }),
    )


@admin.register(Event)
class EventAdmin(admin.ModelAdmin):
    list_display = [
        'title', 'event_code', 'category', 'event_type', 'status_display',
        'start_date', 'start_time', 'library', 'total_registrations',
        'max_participants', 'organizer'
    ]
    list_filter = [
        'event_type', 'status', 'category', 'library', 'registration_type',
        'is_online', 'has_certificate', 'start_date'
    ]
    search_fields = ['title', 'event_code', 'description']
    readonly_fields = [
        'event_code', 'slug', 'total_registrations', 'total_attendees',
        'average_rating', 'total_feedback', 'created_at', 'updated_at'
    ]
    date_hierarchy = 'start_date'
    ordering = ['-start_date', '-start_time']
    filter_horizontal = ['speakers', 'co_organizers']
    
    fieldsets = (
        ('Basic Information', {
            'fields': (
                'title', 'slug', 'event_code', 'category', 'event_type', 'status'
            )
        }),
        ('Content', {
            'fields': (
                'description', 'agenda', 'learning_objectives',
                'prerequisites', 'materials_provided'
            )
        }),
        ('People', {
            'fields': ('organizer', 'co_organizers', 'speakers')
        }),
        ('Scheduling', {
            'fields': (
                'start_date', 'end_date', 'start_time', 'end_time',
                'timezone', 'is_recurring', 'recurrence_pattern'
            )
        }),
        ('Location', {
            'fields': (
                'library', 'venue_details', 'is_online',
                'online_meeting_link', 'online_meeting_password'
            )
        }),
        ('Registration', {
            'fields': (
                'registration_type', 'registration_fee', 'max_participants',
                'min_participants', 'registration_deadline',
                'early_bird_deadline', 'early_bird_discount'
            )
        }),
        ('Eligibility', {
            'fields': (
                'target_audience', 'required_role', 'required_subscription'
            )
        }),
        ('Media', {
            'fields': ('banner_image', 'thumbnail', 'gallery_images', 'attachments'),
            'classes': ('collapse',)
        }),
        ('Features', {
            'fields': (
                'has_certificate', 'certificate_template', 'has_feedback_form',
                'requires_attendance_tracking'
            ),
            'classes': ('collapse',)
        }),
        ('Statistics', {
            'fields': (
                'total_registrations', 'total_attendees', 'average_rating',
                'total_feedback'
            ),
            'classes': ('collapse',)
        }),
        ('Notifications', {
            'fields': ('send_reminders', 'reminder_hours'),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('tags', 'external_links', 'additional_info'),
            'classes': ('collapse',)
        }),
    )
    
    def status_display(self, obj):
        colors = {
            'DRAFT': 'gray',
            'PUBLISHED': 'blue',
            'REGISTRATION_OPEN': 'green',
            'REGISTRATION_CLOSED': 'orange',
            'IN_PROGRESS': 'purple',
            'COMPLETED': 'darkgreen',
            'CANCELLED': 'red',
            'POSTPONED': 'orange'
        }
        color = colors.get(obj.status, 'black')
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color, obj.get_status_display()
        )
    status_display.short_description = 'Status'
    
    actions = ['open_registration', 'close_registration', 'mark_completed']
    
    def open_registration(self, request, queryset):
        updated = queryset.update(status='REGISTRATION_OPEN')
        self.message_user(request, f'{updated} events opened for registration.')
    open_registration.short_description = 'Open registration for selected events'
    
    def close_registration(self, request, queryset):
        updated = queryset.update(status='REGISTRATION_CLOSED')
        self.message_user(request, f'{updated} events closed for registration.')
    close_registration.short_description = 'Close registration for selected events'
    
    def mark_completed(self, request, queryset):
        updated = queryset.update(status='COMPLETED')
        self.message_user(request, f'{updated} events marked as completed.')
    mark_completed.short_description = 'Mark selected events as completed'


@admin.register(EventRegistration)
class EventRegistrationAdmin(admin.ModelAdmin):
    list_display = [
        'registration_code', 'user', 'event_title', 'status_display',
        'registration_date', 'payment_status', 'check_in_time',
        'certificate_issued'
    ]
    list_filter = [
        'status', 'payment_status', 'registration_date', 'certificate_issued',
        'feedback_submitted'
    ]
    search_fields = [
        'registration_code', 'user__email', 'user__first_name',
        'user__last_name', 'event__title'
    ]
    readonly_fields = [
        'registration_code', 'registration_date', 'check_in_time',
        'check_out_time', 'attendance_duration', 'created_at', 'updated_at'
    ]
    date_hierarchy = 'registration_date'
    ordering = ['-registration_date']
    
    fieldsets = (
        ('Registration Information', {
            'fields': (
                'user', 'event', 'registration_code', 'status', 'registration_date'
            )
        }),
        ('Payment', {
            'fields': (
                'registration_fee_paid', 'payment_status', 'payment_reference'
            )
        }),
        ('Attendance', {
            'fields': (
                'check_in_time', 'check_out_time', 'attendance_duration',
                'qr_code_expires_at'
            )
        }),
        ('Additional Information', {
            'fields': (
                'dietary_requirements', 'special_needs', 'emergency_contact',
                'how_did_you_hear', 'expectations'
            ),
            'classes': ('collapse',)
        }),
        ('Certificates & Feedback', {
            'fields': (
                'certificate_issued', 'certificate_file', 'feedback_submitted'
            )
        }),
        ('Notifications', {
            'fields': ('reminder_sent', 'confirmation_sent'),
            'classes': ('collapse',)
        }),
    )
    
    def event_title(self, obj):
        return obj.event.title
    event_title.short_description = 'Event'
    
    def status_display(self, obj):
        colors = {
            'PENDING': 'orange',
            'CONFIRMED': 'blue',
            'WAITLISTED': 'purple',
            'CANCELLED': 'red',
            'ATTENDED': 'green',
            'NO_SHOW': 'darkred',
            'REFUNDED': 'gray'
        }
        color = colors.get(obj.status, 'black')
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color, obj.get_status_display()
        )
    status_display.short_description = 'Status'
    
    actions = ['mark_attended', 'issue_certificates', 'send_reminders']
    
    def mark_attended(self, request, queryset):
        from django.utils import timezone
        updated = queryset.filter(status='CONFIRMED').update(
            status='ATTENDED',
            check_in_time=timezone.now()
        )
        self.message_user(request, f'{updated} registrations marked as attended.')
    mark_attended.short_description = 'Mark selected registrations as attended'
    
    def issue_certificates(self, request, queryset):
        updated = queryset.filter(
            status='ATTENDED',
            certificate_issued=False
        ).update(certificate_issued=True)
        self.message_user(request, f'{updated} certificates issued.')
    issue_certificates.short_description = 'Issue certificates for selected registrations'


@admin.register(EventFeedback)
class EventFeedbackAdmin(admin.ModelAdmin):
    list_display = [
        'event_title', 'user', 'overall_rating', 'would_recommend',
        'would_attend_similar', 'created_at'
    ]
    list_filter = [
        'overall_rating', 'would_recommend', 'would_attend_similar', 'created_at'
    ]
    search_fields = ['event__title', 'user__email', 'what_you_liked']
    readonly_fields = ['created_at', 'updated_at']
    ordering = ['-created_at']
    
    fieldsets = (
        ('Feedback Information', {
            'fields': ('user', 'event', 'registration')
        }),
        ('Ratings', {
            'fields': (
                'overall_rating', 'content_rating', 'speaker_rating',
                'organization_rating', 'venue_rating'
            )
        }),
        ('Feedback Content', {
            'fields': (
                'what_you_liked', 'what_could_improve', 'additional_comments',
                'would_recommend', 'would_attend_similar'
            )
        }),
        ('Suggestions', {
            'fields': (
                'future_topics', 'preferred_format', 'preferred_duration'
            ),
            'classes': ('collapse',)
        }),
    )
    
    def event_title(self, obj):
        return obj.event.title
    event_title.short_description = 'Event'


@admin.register(EventWaitlist)
class EventWaitlistAdmin(admin.ModelAdmin):
    list_display = [
        'user', 'event_title', 'position', 'notified', 'notification_sent_at', 'expires_at'
    ]
    list_filter = ['notified', 'notification_sent_at', 'expires_at']
    search_fields = ['user__email', 'event__title']
    ordering = ['event', 'position']
    
    def event_title(self, obj):
        return obj.event.title
    event_title.short_description = 'Event'


@admin.register(EventResource)
class EventResourceAdmin(admin.ModelAdmin):
    list_display = [
        'title', 'event_title', 'resource_type', 'is_public',
        'available_before_event', 'available_after_event', 'download_count'
    ]
    list_filter = [
        'resource_type', 'is_public', 'available_before_event',
        'available_after_event'
    ]
    search_fields = ['title', 'event__title', 'description']
    ordering = ['event', 'resource_type', 'title']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('event', 'title', 'description', 'resource_type')
        }),
        ('Content', {
            'fields': ('file', 'external_link')
        }),
        ('Access Control', {
            'fields': (
                'is_public', 'available_before_event', 'available_after_event'
            )
        }),
        ('Statistics', {
            'fields': ('file_size', 'download_count'),
            'classes': ('collapse',)
        }),
    )
    
    def event_title(self, obj):
        return obj.event.title
    event_title.short_description = 'Event'


@admin.register(EventStatistics)
class EventStatisticsAdmin(admin.ModelAdmin):
    list_display = [
        'event_title', 'date', 'new_registrations', 'total_registrations',
        'attendees', 'attendance_rate', 'average_rating'
    ]
    list_filter = ['date']
    search_fields = ['event__title']
    readonly_fields = ['created_at', 'updated_at']
    date_hierarchy = 'date'
    ordering = ['-date']
    
    def event_title(self, obj):
        return obj.event.title
    event_title.short_description = 'Event'
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False


@admin.register(EventSeries)
class EventSeriesAdmin(admin.ModelAdmin):
    list_display = [
        'name', 'organizer', 'total_events', 'is_active',
        'requires_series_registration', 'series_fee', 'created_at'
    ]
    list_filter = ['is_active', 'requires_series_registration']
    search_fields = ['name', 'description', 'organizer__email']
    filter_horizontal = ['events']
    ordering = ['name']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'description', 'organizer', 'banner_image')
        }),
        ('Events', {
            'fields': ('events',)
        }),
        ('Settings', {
            'fields': (
                'is_active', 'requires_series_registration', 'series_fee'
            )
        }),
    )


@admin.register(EventNotification)
class EventNotificationAdmin(admin.ModelAdmin):
    list_display = [
        'title', 'event_title', 'notification_type', 'is_sent',
        'sent_at', 'recipients_count', 'created_at'
    ]
    list_filter = [
        'notification_type', 'is_sent', 'send_immediately',
        'send_to_all_registrants'
    ]
    search_fields = ['title', 'message', 'event__title']
    readonly_fields = ['is_sent', 'sent_at', 'recipients_count', 'created_at', 'updated_at']
    ordering = ['-created_at']
    
    fieldsets = (
        ('Notification Information', {
            'fields': ('event', 'notification_type', 'title', 'message')
        }),
        ('Targeting', {
            'fields': (
                'send_to_all_registrants', 'send_to_attendees_only',
                'send_to_waitlist'
            )
        }),
        ('Scheduling', {
            'fields': ('send_immediately', 'scheduled_send_time')
        }),
        ('Status', {
            'fields': ('is_sent', 'sent_at', 'recipients_count'),
            'classes': ('collapse',)
        }),
    )
    
    def event_title(self, obj):
        return obj.event.title
    event_title.short_description = 'Event'
    
    actions = ['send_notifications']
    
    def send_notifications(self, request, queryset):
        # This would trigger the notification sending task
        count = queryset.filter(is_sent=False).count()
        self.message_user(request, f'{count} notifications queued for sending.')
    send_notifications.short_description = 'Send selected notifications'