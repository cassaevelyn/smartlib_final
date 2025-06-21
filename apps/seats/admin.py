from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils.safestring import mark_safe
from .models import (
    Seat, SeatBooking, SeatBookingWaitlist, SeatReview,
    SeatMaintenanceLog, SeatUsageStatistics
)


@admin.register(Seat)
class SeatAdmin(admin.ModelAdmin):
    list_display = [
        'seat_number', 'seat_code', 'library', 'floor', 'section',
        'seat_type', 'status_display', 'is_bookable', 'is_premium',
        'total_bookings', 'average_rating'
    ]
    list_filter = [
        'library', 'floor', 'section', 'seat_type', 'status',
        'is_bookable', 'is_premium', 'has_power_outlet', 'is_accessible'
    ]
    search_fields = ['seat_number', 'seat_code', 'library__name']
    readonly_fields = [
        'seat_code', 'total_bookings', 'total_usage_hours',
        'average_rating', 'created_at', 'updated_at'
    ]
    ordering = ['library', 'floor', 'section', 'seat_number']
    
    fieldsets = (
        ('Basic Information', {
            'fields': (
                'library', 'floor', 'section', 'seat_number', 'seat_code',
                'seat_type', 'status', 'description'
            )
        }),
        ('Physical Properties', {
            'fields': (
                'has_power_outlet', 'has_ethernet', 'has_monitor',
                'has_whiteboard', 'is_near_window', 'is_accessible'
            )
        }),
        ('Position & Layout', {
            'fields': ('x_coordinate', 'y_coordinate', 'rotation'),
            'classes': ('collapse',)
        }),
        ('Booking Settings', {
            'fields': (
                'is_bookable', 'requires_approval', 'is_premium',
                'max_booking_duration_hours'
            )
        }),
        ('Statistics', {
            'fields': (
                'total_bookings', 'total_usage_hours', 'average_rating',
                'last_cleaned'
            ),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('features', 'maintenance_notes'),
            'classes': ('collapse',)
        }),
    )
    
    def status_display(self, obj):
        colors = {
            'AVAILABLE': 'green',
            'OCCUPIED': 'orange',
            'RESERVED': 'blue',
            'MAINTENANCE': 'red',
            'OUT_OF_ORDER': 'darkred'
        }
        color = colors.get(obj.status, 'black')
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color, obj.get_status_display()
        )
    status_display.short_description = 'Status'
    
    actions = ['mark_available', 'mark_maintenance', 'mark_out_of_order']
    
    def mark_available(self, request, queryset):
        updated = queryset.update(status='AVAILABLE')
        self.message_user(request, f'{updated} seats marked as available.')
    mark_available.short_description = 'Mark selected seats as available'
    
    def mark_maintenance(self, request, queryset):
        updated = queryset.update(status='MAINTENANCE')
        self.message_user(request, f'{updated} seats marked under maintenance.')
    mark_maintenance.short_description = 'Mark selected seats under maintenance'
    
    def mark_out_of_order(self, request, queryset):
        updated = queryset.update(status='OUT_OF_ORDER')
        self.message_user(request, f'{updated} seats marked as out of order.')
    mark_out_of_order.short_description = 'Mark selected seats as out of order'


@admin.register(SeatBooking)
class SeatBookingAdmin(admin.ModelAdmin):
    list_display = [
        'booking_code', 'user', 'seat', 'booking_date', 'start_time',
        'end_time', 'status_display', 'booking_type', 'duration_hours',
        'loyalty_points_earned'
    ]
    list_filter = [
        'status', 'booking_type', 'booking_date', 'seat__library',
        'late_cancellation', 'reminder_sent'
    ]
    search_fields = [
        'booking_code', 'user__email', 'user__first_name', 'user__last_name',
        'seat__seat_number', 'seat__library__name'
    ]
    readonly_fields = [
        'booking_code', 'actual_duration_hours', 'checked_in_at',
        'checked_out_at', 'qr_code_expires_at', 'created_at', 'updated_at'
    ]
    date_hierarchy = 'booking_date'
    ordering = ['-booking_date', '-start_time']
    
    fieldsets = (
        ('Booking Information', {
            'fields': (
                'user', 'seat', 'booking_code', 'booking_type',
                'booking_date', 'start_time', 'end_time', 'status'
            )
        }),
        ('Check-in/Check-out', {
            'fields': (
                'actual_start_time', 'actual_end_time', 'checked_in_at',
                'checked_out_at'
            )
        }),
        ('QR Code & Security', {
            'fields': ('qr_code_data', 'qr_code_expires_at', 'access_token'),
            'classes': ('collapse',)
        }),
        ('Management', {
            'fields': (
                'auto_cancel_at', 'reminder_sent', 'late_cancellation'
            ),
            'classes': ('collapse',)
        }),
        ('Group Booking', {
            'fields': ('group_booking_id', 'group_size', 'group_leader'),
            'classes': ('collapse',)
        }),
        ('Additional Information', {
            'fields': ('purpose', 'special_requirements', 'notes'),
            'classes': ('collapse',)
        }),
        ('Points & Penalties', {
            'fields': ('penalty_points', 'loyalty_points_earned'),
            'classes': ('collapse',)
        }),
    )
    
    def status_display(self, obj):
        colors = {
            'PENDING': 'orange',
            'CONFIRMED': 'blue',
            'CHECKED_IN': 'green',
            'COMPLETED': 'darkgreen',
            'CANCELLED': 'red',
            'NO_SHOW': 'darkred',
            'EXPIRED': 'gray'
        }
        color = colors.get(obj.status, 'black')
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color, obj.get_status_display()
        )
    status_display.short_description = 'Status'
    
    actions = ['mark_no_show', 'cancel_bookings', 'send_reminders']
    
    def mark_no_show(self, request, queryset):
        updated = queryset.filter(status='CONFIRMED').update(status='NO_SHOW')
        self.message_user(request, f'{updated} bookings marked as no-show.')
    mark_no_show.short_description = 'Mark selected bookings as no-show'
    
    def cancel_bookings(self, request, queryset):
        updated = queryset.filter(status__in=['CONFIRMED', 'PENDING']).update(status='CANCELLED')
        self.message_user(request, f'{updated} bookings cancelled.')
    cancel_bookings.short_description = 'Cancel selected bookings'
    
    def send_reminders(self, request, queryset):
        # This would trigger reminder emails
        count = queryset.filter(reminder_sent=False).count()
        queryset.update(reminder_sent=True)
        self.message_user(request, f'Reminders sent for {count} bookings.')
    send_reminders.short_description = 'Send reminders for selected bookings'


@admin.register(SeatBookingWaitlist)
class SeatBookingWaitlistAdmin(admin.ModelAdmin):
    list_display = [
        'user', 'seat', 'booking_date', 'preferred_start_time',
        'preferred_end_time', 'is_active', 'priority_score', 'created_at'
    ]
    list_filter = ['is_active', 'booking_date', 'flexible_timing']
    search_fields = ['user__email', 'seat__seat_number']
    readonly_fields = ['created_at', 'updated_at']
    ordering = ['-priority_score', 'created_at']


@admin.register(SeatReview)
class SeatReviewAdmin(admin.ModelAdmin):
    list_display = [
        'seat', 'user', 'overall_rating', 'title', 'is_approved', 'created_at'
    ]
    list_filter = ['overall_rating', 'is_approved', 'created_at']
    search_fields = ['seat__seat_number', 'user__email', 'title', 'review_text']
    readonly_fields = ['created_at', 'updated_at']
    ordering = ['-created_at']
    
    fieldsets = (
        ('Review Information', {
            'fields': ('user', 'seat', 'booking', 'title', 'review_text')
        }),
        ('Ratings', {
            'fields': (
                'overall_rating', 'comfort_rating', 'cleanliness_rating',
                'noise_level_rating', 'facilities_rating'
            )
        }),
        ('Issues & Moderation', {
            'fields': ('reported_issues', 'is_approved', 'approved_by')
        }),
    )
    
    actions = ['approve_reviews', 'reject_reviews']
    
    def approve_reviews(self, request, queryset):
        from django.utils import timezone
        updated = queryset.update(
            is_approved=True,
            approved_by=request.user
        )
        self.message_user(request, f'{updated} reviews approved.')
    approve_reviews.short_description = 'Approve selected reviews'
    
    def reject_reviews(self, request, queryset):
        updated = queryset.update(is_approved=False)
        self.message_user(request, f'{updated} reviews rejected.')
    reject_reviews.short_description = 'Reject selected reviews'


@admin.register(SeatMaintenanceLog)
class SeatMaintenanceLogAdmin(admin.ModelAdmin):
    list_display = [
        'seat', 'maintenance_type', 'status', 'scheduled_date',
        'assigned_to', 'performed_by', 'cost'
    ]
    list_filter = [
        'maintenance_type', 'status', 'scheduled_date',
        'requires_follow_up'
    ]
    search_fields = ['seat__seat_number', 'description']
    readonly_fields = ['created_at', 'updated_at']
    date_hierarchy = 'scheduled_date'
    ordering = ['-scheduled_date']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('seat', 'maintenance_type', 'status', 'description')
        }),
        ('Scheduling', {
            'fields': ('scheduled_date', 'started_at', 'completed_at')
        }),
        ('Personnel', {
            'fields': ('assigned_to', 'performed_by')
        }),
        ('Work Details', {
            'fields': ('issues_found', 'actions_taken', 'parts_used', 'cost')
        }),
        ('Follow-up', {
            'fields': ('requires_follow_up', 'follow_up_date', 'follow_up_notes')
        }),
    )


@admin.register(SeatUsageStatistics)
class SeatUsageStatisticsAdmin(admin.ModelAdmin):
    list_display = [
        'seat', 'date', 'total_bookings', 'successful_checkins',
        'utilization_rate', 'average_session_duration', 'unique_users'
    ]
    list_filter = ['date', 'seat__library']
    search_fields = ['seat__seat_number']
    readonly_fields = ['created_at', 'updated_at']
    date_hierarchy = 'date'
    ordering = ['-date', 'seat']
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False