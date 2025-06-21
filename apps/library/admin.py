from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils.safestring import mark_safe
from . import models


@admin.register(models.Library)
class LibraryAdmin(admin.ModelAdmin):
    list_display = [
        'name', 'code', 'library_type', 'status', 'city',
        'total_seats', 'admin_occupancy_display', 'is_open_display', 'created_at'
    ]
    list_filter = [
        'library_type', 'status', 'city', 'has_wifi', 'has_parking',
        'is_24_hours', 'allow_booking'
    ]
    search_fields = ['name', 'code', 'city', 'address']
    readonly_fields = [
        'code', 'total_visits', 'average_rating', 'total_reviews',
        'created_at', 'updated_at'
    ]
    ordering = ['name']
    
    fieldsets = (
        ('Basic Information', {
            'fields': (
                'name', 'code', 'library_type', 'status', 'description'
            )
        }),
        ('Location', {
            'fields': (
                'address', 'city', 'postal_code', 'latitude', 'longitude'
            )
        }),
        ('Contact Information', {
            'fields': ('phone_number', 'email', 'website')
        }),
        ('Operating Hours', {
            'fields': (
                'opening_time', 'closing_time', 'is_24_hours'
            )
        }),
        ('Capacity & Features', {
            'fields': (
                'total_capacity', 'total_seats', 'total_study_rooms',
                'has_wifi', 'has_printing', 'has_scanning',
                'has_cafeteria', 'has_parking'
            )
        }),
        ('Booking Settings', {
            'fields': (
                'allow_booking', 'booking_advance_days',
                'max_booking_duration_hours', 'auto_cancel_minutes'
            )
        }),
        ('Media', {
            'fields': ('main_image', 'gallery_images', 'floor_plan'),
            'classes': ('collapse',)
        }),
        ('Statistics', {
            'fields': ('total_visits', 'average_rating', 'total_reviews'),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('amenities', 'rules'),
            'classes': ('collapse',)
        }),
    )
    
    def admin_occupancy_display(self, obj):
        rate = obj.get_occupancy_rate()
        color = 'green' if rate < 70 else 'orange' if rate < 90 else 'red'
        # Format the rate as a string first, then pass to format_html
        formatted_rate = f"{rate:.1f}"
        return format_html(
            '<span style="color: {};">{}</span>',
            color, formatted_rate + '%'
        )
    admin_occupancy_display.short_description = 'Occupancy'
    
    def is_open_display(self, obj):
        is_open = obj.is_open
        color = 'green' if is_open else 'red'
        text = 'Open' if is_open else 'Closed'
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color, text
        )
    is_open_display.short_description = 'Status'
    
    actions = ['mark_active', 'mark_maintenance', 'mark_closed']
    
    def mark_active(self, request, queryset):
        updated = queryset.update(status='ACTIVE')
        self.message_user(request, f'{updated} libraries marked as active.')
    mark_active.short_description = 'Mark selected libraries as active'
    
    def mark_maintenance(self, request, queryset):
        updated = queryset.update(status='MAINTENANCE')
        self.message_user(request, f'{updated} libraries marked under maintenance.')
    mark_maintenance.short_description = 'Mark selected libraries under maintenance'
    
    def mark_closed(self, request, queryset):
        updated = queryset.update(status='CLOSED')
        self.message_user(request, f'{updated} libraries marked as closed.')
    mark_closed.short_description = 'Mark selected libraries as closed'


class LibrarySectionInline(admin.TabularInline):
    model = models.LibrarySection
    extra = 0
    fields = [
        'name', 'section_type', 'total_seats', 'requires_booking',
        'noise_level', 'has_power_outlets'
    ]


@admin.register(models.LibraryFloor)
class LibraryFloorAdmin(admin.ModelAdmin):
    list_display = [
        'library', 'floor_number', 'floor_name', 'total_seats',
        'available_seats', 'occupancy_rate'
    ]
    list_filter = ['library', 'has_silent_zone', 'has_group_study', 'has_computer_lab']
    search_fields = ['library__name', 'floor_name']
    ordering = ['library', 'floor_number']
    inlines = [LibrarySectionInline]
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('library', 'floor_number', 'floor_name', 'description')
        }),
        ('Capacity', {
            'fields': ('total_seats', 'study_rooms')
        }),
        ('Features', {
            'fields': (
                'has_silent_zone', 'has_group_study', 'has_computer_lab',
                'has_printer', 'has_restroom'
            )
        }),
        ('Layout', {
            'fields': ('floor_plan_image', 'layout_data'),
            'classes': ('collapse',)
        }),
    )


@admin.register(models.LibrarySection)
class LibrarySectionAdmin(admin.ModelAdmin):
    list_display = [
        'floor', 'name', 'section_type', 'total_seats',
        'available_seats', 'requires_booking', 'noise_level'
    ]
    list_filter = [
        'section_type', 'requires_booking', 'noise_level',
        'has_power_outlets', 'has_whiteboard'
    ]
    search_fields = ['floor__library__name', 'floor__floor_name', 'name']
    ordering = ['floor', 'name']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('floor', 'name', 'section_type', 'description')
        }),
        ('Capacity', {
            'fields': ('total_seats', 'max_occupancy')
        }),
        ('Features', {
            'fields': (
                'has_power_outlets', 'has_ethernet', 'has_whiteboard',
                'has_projector', 'noise_level'
            )
        }),
        ('Booking Settings', {
            'fields': (
                'requires_booking', 'advance_booking_hours',
                'max_booking_duration'
            )
        }),
    )


@admin.register(models.LibraryAmenity)
class LibraryAmenityAdmin(admin.ModelAdmin):
    list_display = [
        'library', 'name', 'amenity_type', 'is_available', 'is_premium'
    ]
    list_filter = ['amenity_type', 'is_available', 'is_premium']
    search_fields = ['library__name', 'name']
    ordering = ['library', 'amenity_type', 'name']


class LibraryOperatingHoursInline(admin.TabularInline):
    model = models.LibraryOperatingHours
    extra = 0
    fields = ['day_of_week', 'opening_time', 'closing_time', 'is_closed', 'is_24_hours']


@admin.register(models.LibraryOperatingHours)
class LibraryOperatingHoursAdmin(admin.ModelAdmin):
    list_display = [
        'library', 'get_day_name', 'opening_time', 'closing_time',
        'is_closed', 'is_24_hours'
    ]
    list_filter = ['day_of_week', 'is_closed', 'is_24_hours']
    search_fields = ['library__name']
    ordering = ['library', 'day_of_week']
    
    def get_day_name(self, obj):
        return dict(obj.DAYS_OF_WEEK)[obj.day_of_week]
    get_day_name.short_description = 'Day'


@admin.register(models.LibraryHoliday)
class LibraryHolidayAdmin(admin.ModelAdmin):
    list_display = [
        'library', 'name', 'holiday_type', 'start_date', 'end_date',
        'is_recurring', 'is_active_today'
    ]
    list_filter = ['holiday_type', 'is_recurring', 'start_date']
    search_fields = ['library__name', 'name']
    date_hierarchy = 'start_date'
    ordering = ['library', '-start_date']


@admin.register(models.LibraryReview)
class LibraryReviewAdmin(admin.ModelAdmin):
    list_display = [
        'library', 'user', 'rating', 'title', 'is_approved',
        'helpful_count', 'created_at'
    ]
    list_filter = [
        'rating', 'is_approved', 'created_at',
        'cleanliness_rating', 'facilities_rating'
    ]
    search_fields = ['library__name', 'user__email', 'title', 'review_text']
    readonly_fields = ['helpful_count', 'reported_count', 'created_at', 'updated_at']
    date_hierarchy = 'created_at'
    ordering = ['-created_at']
    
    fieldsets = (
        ('Review Information', {
            'fields': ('library', 'user', 'rating', 'title', 'review_text')
        }),
        ('Detailed Ratings', {
            'fields': (
                'cleanliness_rating', 'noise_level_rating',
                'facilities_rating', 'staff_rating'
            )
        }),
        ('Moderation', {
            'fields': ('is_approved', 'approved_by', 'approved_at')
        }),
        ('Statistics', {
            'fields': ('helpful_count', 'reported_count'),
            'classes': ('collapse',)
        }),
    )
    
    actions = ['approve_reviews', 'reject_reviews']
    
    def approve_reviews(self, request, queryset):
        from django.utils import timezone
        updated = queryset.update(
            is_approved=True,
            approved_by=request.user,
            approved_at=timezone.now()
        )
        self.message_user(request, f'{updated} reviews approved.')
    approve_reviews.short_description = 'Approve selected reviews'
    
    def reject_reviews(self, request, queryset):
        updated = queryset.update(is_approved=False)
        self.message_user(request, f'{updated} reviews rejected.')
    reject_reviews.short_description = 'Reject selected reviews'


@admin.register(models.LibraryStatistics)
class LibraryStatisticsAdmin(admin.ModelAdmin):
    list_display = [
        'library', 'date', 'total_visitors', 'total_bookings',
        'successful_checkins', 'no_shows', 'average_occupancy'
    ]
    list_filter = ['date', 'library']
    search_fields = ['library__name']
    date_hierarchy = 'date'
    ordering = ['-date', 'library']
    readonly_fields = ['created_at', 'updated_at']
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False


@admin.register(models.LibraryNotification)
class LibraryNotificationAdmin(admin.ModelAdmin):
    list_display = [
        'library', 'title', 'notification_type', 'priority',
        'is_active', 'start_date', 'views_count'
    ]
    list_filter = [
        'notification_type', 'priority', 'is_active',
        'show_on_dashboard', 'requires_acknowledgment'
    ]
    search_fields = ['library__name', 'title', 'message']
    date_hierarchy = 'start_date'
    ordering = ['-priority', '-start_date']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('library', 'title', 'message', 'notification_type', 'priority')
        }),
        ('Targeting', {
            'fields': ('target_all_users', 'target_user_roles')
        }),
        ('Scheduling', {
            'fields': ('start_date', 'end_date', 'is_active')
        }),
        ('Display Settings', {
            'fields': (
                'show_on_dashboard', 'show_on_booking',
                'requires_acknowledgment'
            )
        }),
        ('Statistics', {
            'fields': ('views_count', 'acknowledgments_count'),
            'classes': ('collapse',)
        }),
    )
    
    actions = ['activate_notifications', 'deactivate_notifications']
    
    def activate_notifications(self, request, queryset):
        updated = queryset.update(is_active=True)
        self.message_user(request, f'{updated} notifications activated.')
    activate_notifications.short_description = 'Activate selected notifications'
    
    def deactivate_notifications(self, request, queryset):
        updated = queryset.update(is_active=False)
        self.message_user(request, f'{updated} notifications deactivated.')
    deactivate_notifications.short_description = 'Deactivate selected notifications'


@admin.register(models.LibraryConfiguration)
class LibraryConfigurationAdmin(admin.ModelAdmin):
    list_display = [
        'library', 'max_advance_booking_days', 'max_daily_bookings_per_user',
        'auto_cancel_no_show_minutes', 'enable_seat_selection'
    ]
    search_fields = ['library__name']
    
    fieldsets = (
        ('Library', {
            'fields': ('library',)
        }),
        ('Booking Settings', {
            'fields': (
                'max_advance_booking_days', 'max_daily_bookings_per_user',
                'max_booking_duration_hours', 'min_booking_duration_minutes',
                'auto_cancel_no_show_minutes'
            )
        }),
        ('Check-in/Check-out Settings', {
            'fields': (
                'early_checkin_minutes', 'late_checkout_grace_minutes',
                'qr_code_expiry_minutes'
            )
        }),
        ('Penalty Settings', {
            'fields': (
                'no_show_penalty_points', 'late_cancellation_penalty_points',
                'overstay_penalty_per_hour'
            )
        }),
        ('Loyalty Settings', {
            'fields': (
                'booking_completion_points', 'review_submission_points',
                'referral_points'
            )
        }),
        ('Notification Settings', {
            'fields': (
                'reminder_hours_before', 'send_booking_confirmations',
                'send_checkin_reminders', 'send_checkout_reminders'
            )
        }),
        ('Feature Flags', {
            'fields': (
                'enable_seat_selection', 'enable_recurring_bookings',
                'enable_group_bookings', 'enable_waitlist', 'enable_reviews'
            )
        }),
        ('Integration Settings', {
            'fields': ('integration_settings',),
            'classes': ('collapse',)
        }),
    )