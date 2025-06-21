"""
Seat models for Smart Lib
"""
from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator
from django.contrib.auth import get_user_model
from apps.core.models import BaseModel, TimeStampedModel
from apps.core.utils import generate_unique_code, generate_qr_code
from datetime import timedelta
import uuid

User = get_user_model()


class Seat(BaseModel):
    """
    Model representing individual seats in the library
    """
    SEAT_TYPES = [
        ('INDIVIDUAL', 'Individual Study'),
        ('GROUP', 'Group Study'),
        ('COMPUTER', 'Computer Workstation'),
        ('SILENT', 'Silent Study'),
        ('DISCUSSION', 'Discussion Area'),
        ('PREMIUM', 'Premium Seat'),
        ('ACCESSIBLE', 'Accessible Seat'),
    ]
    
    STATUS_CHOICES = [
        ('AVAILABLE', 'Available'),
        ('OCCUPIED', 'Occupied'),
        ('RESERVED', 'Reserved'),
        ('MAINTENANCE', 'Under Maintenance'),
        ('OUT_OF_ORDER', 'Out of Order'),
    ]
    
    # Basic Information
    library = models.ForeignKey('library.Library', on_delete=models.CASCADE, related_name='seats')
    floor = models.ForeignKey('library.LibraryFloor', on_delete=models.CASCADE, related_name='seats')
    section = models.ForeignKey('library.LibrarySection', on_delete=models.CASCADE, related_name='seats')
    
    seat_number = models.CharField(max_length=20)
    seat_code = models.CharField(max_length=30, unique=True, blank=True)
    seat_type = models.CharField(max_length=15, choices=SEAT_TYPES, default='INDIVIDUAL')
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='AVAILABLE')
    
    # Physical Properties
    has_power_outlet = models.BooleanField(default=True)
    has_ethernet = models.BooleanField(default=False)
    has_monitor = models.BooleanField(default=False)
    has_whiteboard = models.BooleanField(default=False)
    is_near_window = models.BooleanField(default=False)
    is_accessible = models.BooleanField(default=False)
    
    # Position and Layout
    x_coordinate = models.DecimalField(max_digits=8, decimal_places=2, null=True, blank=True)
    y_coordinate = models.DecimalField(max_digits=8, decimal_places=2, null=True, blank=True)
    rotation = models.IntegerField(default=0)  # Rotation in degrees
    
    # Booking Settings
    is_bookable = models.BooleanField(default=True)
    requires_approval = models.BooleanField(default=False)
    is_premium = models.BooleanField(default=False)
    max_booking_duration_hours = models.PositiveIntegerField(default=8)
    
    # Statistics
    total_bookings = models.PositiveIntegerField(default=0)
    total_usage_hours = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    average_rating = models.DecimalField(max_digits=3, decimal_places=2, default=0.00)
    last_cleaned = models.DateTimeField(null=True, blank=True)
    
    # Metadata
    description = models.TextField(blank=True)
    features = models.JSONField(default=list, blank=True)
    maintenance_notes = models.TextField(blank=True)
    
    class Meta:
        db_table = 'seats_seat'
        unique_together = ['library', 'seat_number']
        ordering = ['library', 'floor', 'section', 'seat_number']
        indexes = [
            models.Index(fields=['library', 'status']),
            models.Index(fields=['seat_type', 'status']),
            models.Index(fields=['is_bookable', 'status']),
        ]
    
    def __str__(self):
        return f"{self.library.name} - {self.seat_number} ({self.seat_code})"
    
    def save(self, *args, **kwargs):
        if not self.seat_code:
            self.seat_code = f"{self.library.code}-{generate_unique_code('S', 4)}"
        super().save(*args, **kwargs)
    
    @property
    def is_available(self):
        """Check if seat is available for booking"""
        return self.status == 'AVAILABLE' and self.is_bookable and not self.is_deleted
    
    @property
    def current_booking(self):
        """Get current active booking for this seat"""
        from django.utils import timezone
        now = timezone.now()
        
        return self.bookings.filter(
            booking_date=now.date(),
            start_time__lte=now.time(),
            end_time__gte=now.time(),
            status__in=['CONFIRMED', 'CHECKED_IN'],
            is_deleted=False
        ).first()
    
    def get_availability_for_date(self, date):
        """Get availability slots for a specific date"""
        from django.utils import timezone
        
        # Get all bookings for the date
        bookings = self.bookings.filter(
            booking_date=date,
            status__in=['CONFIRMED', 'CHECKED_IN'],
            is_deleted=False
        ).order_by('start_time')
        
        # Generate available time slots
        library_config = self.library.configuration
        opening_time = self.library.opening_time
        closing_time = self.library.closing_time
        
        available_slots = []
        current_time = opening_time
        
        for booking in bookings:
            if current_time < booking.start_time:
                available_slots.append({
                    'start_time': current_time,
                    'end_time': booking.start_time,
                    'duration_minutes': (
                        timezone.datetime.combine(date, booking.start_time) -
                        timezone.datetime.combine(date, current_time)
                    ).total_seconds() / 60
                })
            current_time = max(current_time, booking.end_time)
        
        # Add final slot if there's time left
        if current_time < closing_time:
            available_slots.append({
                'start_time': current_time,
                'end_time': closing_time,
                'duration_minutes': (
                    timezone.datetime.combine(date, closing_time) -
                    timezone.datetime.combine(date, current_time)
                ).total_seconds() / 60
            })
        
        return available_slots
    
    def can_user_book(self, user, start_time, end_time, booking_date):
        """Check if user can book this seat for given time"""
        if not self.is_available:
            return False, "Seat is not available"
        
        # Check if seat is already booked for this time
        conflicting_bookings = self.bookings.filter(
            booking_date=booking_date,
            status__in=['CONFIRMED', 'CHECKED_IN'],
            is_deleted=False
        ).filter(
            models.Q(start_time__lt=end_time) & models.Q(end_time__gt=start_time)
        )
        
        if conflicting_bookings.exists():
            return False, "Seat is already booked for this time"
        
        # Check user's daily booking limit
        library_config = self.library.configuration
        user_bookings_today = SeatBooking.objects.filter(
            user=user,
            booking_date=booking_date,
            status__in=['CONFIRMED', 'CHECKED_IN'],
            is_deleted=False
        ).count()
        
        if user_bookings_today >= library_config.max_daily_bookings_per_user:
            return False, f"Daily booking limit ({library_config.max_daily_bookings_per_user}) exceeded"
        
        # Check booking duration
        duration_hours = (
            timezone.datetime.combine(booking_date, end_time) -
            timezone.datetime.combine(booking_date, start_time)
        ).total_seconds() / 3600
        
        if duration_hours > self.max_booking_duration_hours:
            return False, f"Booking duration exceeds maximum ({self.max_booking_duration_hours} hours)"
        
        # Check if premium seat requires subscription
        if self.is_premium and not hasattr(user, 'current_subscription'):
            return False, "Premium seat requires active subscription"
        
        return True, "Seat can be booked"


class SeatBooking(BaseModel):
    """
    Model for seat bookings
    """
    BOOKING_STATUS = [
        ('PENDING', 'Pending Approval'),
        ('CONFIRMED', 'Confirmed'),
        ('CHECKED_IN', 'Checked In'),
        ('COMPLETED', 'Completed'),
        ('CANCELLED', 'Cancelled'),
        ('NO_SHOW', 'No Show'),
        ('EXPIRED', 'Expired'),
    ]
    
    BOOKING_TYPES = [
        ('REGULAR', 'Regular Booking'),
        ('RECURRING', 'Recurring Booking'),
        ('GROUP', 'Group Booking'),
        ('PRIORITY', 'Priority Booking'),
    ]
    
    # Basic Information
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='seat_bookings')
    seat = models.ForeignKey(Seat, on_delete=models.CASCADE, related_name='bookings')
    booking_code = models.CharField(max_length=30, unique=True, blank=True)
    
    # Booking Details
    booking_type = models.CharField(max_length=15, choices=BOOKING_TYPES, default='REGULAR')
    booking_date = models.DateField()
    start_time = models.TimeField()
    end_time = models.TimeField()
    status = models.CharField(max_length=15, choices=BOOKING_STATUS, default='CONFIRMED')
    
    # Check-in/Check-out
    actual_start_time = models.DateTimeField(null=True, blank=True)
    actual_end_time = models.DateTimeField(null=True, blank=True)
    checked_in_at = models.DateTimeField(null=True, blank=True)
    checked_out_at = models.DateTimeField(null=True, blank=True)
    
    # QR Code and Security
    qr_code_data = models.TextField(blank=True)
    qr_code_expires_at = models.DateTimeField(null=True, blank=True)
    access_token = models.CharField(max_length=100, blank=True)
    
    # Booking Management
    auto_cancel_at = models.DateTimeField(null=True, blank=True)
    reminder_sent = models.BooleanField(default=False)
    late_cancellation = models.BooleanField(default=False)
    
    # Group Booking (if applicable)
    group_booking_id = models.UUIDField(null=True, blank=True)
    group_size = models.PositiveIntegerField(default=1)
    group_leader = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='led_group_bookings'
    )
    
    # Recurring Booking (if applicable)
    parent_booking = models.ForeignKey(
        'self',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='recurring_instances'
    )
    recurrence_pattern = models.JSONField(default=dict, blank=True)
    
    # Additional Information
    purpose = models.CharField(max_length=200, blank=True)
    special_requirements = models.TextField(blank=True)
    notes = models.TextField(blank=True)
    
    # Penalties and Points
    penalty_points = models.PositiveIntegerField(default=0)
    loyalty_points_earned = models.PositiveIntegerField(default=0)
    
    class Meta:
        db_table = 'seats_booking'
        ordering = ['-booking_date', '-start_time']
        indexes = [
            models.Index(fields=['user', 'booking_date']),
            models.Index(fields=['seat', 'booking_date']),
            models.Index(fields=['status', 'booking_date']),
            models.Index(fields=['booking_date', 'start_time']),
        ]
    
    def __str__(self):
        return f"{self.user.get_full_name()} - {self.seat.seat_number} on {self.booking_date}"
    
    def save(self, *args, **kwargs):
        if not self.booking_code:
            self.booking_code = generate_unique_code('BK', 8)
        
        # Set auto-cancel time
        if not self.auto_cancel_at and self.status == 'CONFIRMED':
            from django.utils import timezone
            library_config = self.seat.library.configuration
            booking_datetime = timezone.datetime.combine(self.booking_date, self.start_time)
            self.auto_cancel_at = booking_datetime + timedelta(
                minutes=library_config.auto_cancel_no_show_minutes
            )
        
        super().save(*args, **kwargs)
    
    @property
    def duration_hours(self):
        """Calculate booking duration in hours"""
        from django.utils import timezone
        start_datetime = timezone.datetime.combine(self.booking_date, self.start_time)
        end_datetime = timezone.datetime.combine(self.booking_date, self.end_time)
        return (end_datetime - start_datetime).total_seconds() / 3600
    
    @property
    def actual_duration_hours(self):
        """Calculate actual usage duration in hours"""
        if self.actual_start_time and self.actual_end_time:
            return (self.actual_end_time - self.actual_start_time).total_seconds() / 3600
        return 0
    
    @property
    def is_active(self):
        """Check if booking is currently active"""
        from django.utils import timezone
        now = timezone.now()
        booking_start = timezone.datetime.combine(self.booking_date, self.start_time)
        booking_end = timezone.datetime.combine(self.booking_date, self.end_time)
        
        return (
            self.status in ['CONFIRMED', 'CHECKED_IN'] and
            booking_start <= now <= booking_end
        )
    
    @property
    def can_check_in(self):
        """Check if user can check in"""
        from django.utils import timezone
        now = timezone.now()
        booking_start = timezone.datetime.combine(self.booking_date, self.start_time)
        
        # Allow early check-in based on library configuration
        library_config = self.seat.library.configuration
        early_checkin_time = booking_start - timedelta(minutes=library_config.early_checkin_minutes)
        
        return (
            self.status == 'CONFIRMED' and
            early_checkin_time <= now <= booking_start + timedelta(hours=1)
        )
    
    @property
    def can_check_out(self):
        """Check if user can check out"""
        return self.status == 'CHECKED_IN'
    
    def generate_qr_code(self):
        """Generate QR code for check-in"""
        from django.utils import timezone
        from apps.core.utils import generate_secure_token
        
        # Generate access token
        self.access_token = generate_secure_token()
        
        # Set QR code expiry
        library_config = self.seat.library.configuration
        self.qr_code_expires_at = timezone.now() + timedelta(
            minutes=library_config.qr_code_expiry_minutes
        )
        
        # Create QR code data
        qr_data = {
            'booking_id': str(self.id),
            'booking_code': self.booking_code,
            'access_token': self.access_token,
            'seat_code': self.seat.seat_code,
            'user_id': str(self.user.id),
            'expires_at': self.qr_code_expires_at.isoformat()
        }
        
        import json
        self.qr_code_data = json.dumps(qr_data)
        self.save()
        
        return qr_data
    
    def check_in(self, check_in_method='QR'):
        """Check in to the seat"""
        from django.utils import timezone
        
        if not self.can_check_in:
            return False, "Cannot check in at this time"
        
        self.status = 'CHECKED_IN'
        self.checked_in_at = timezone.now()
        self.actual_start_time = timezone.now()
        
        # Update seat status
        self.seat.status = 'OCCUPIED'
        self.seat.save()
        
        self.save()
        
        # Log activity
        from apps.core.models import ActivityLog
        ActivityLog.objects.create(
            user=self.user,
            activity_type='SEAT_CHECKIN',
            description=f'Checked in to seat {self.seat.seat_number}',
            metadata={
                'booking_id': str(self.id),
                'seat_code': self.seat.seat_code,
                'check_in_method': check_in_method,
            }
        )
        
        return True, "Checked in successfully"
    
    def check_out(self, check_out_method='QR'):
        """Check out from the seat"""
        from django.utils import timezone
        
        if not self.can_check_out:
            return False, "Cannot check out at this time"
        
        self.status = 'COMPLETED'
        self.checked_out_at = timezone.now()
        self.actual_end_time = timezone.now()
        
        # Update seat status
        self.seat.status = 'AVAILABLE'
        self.seat.save()
        
        # Award loyalty points
        library_config = self.seat.library.configuration
        points = library_config.booking_completion_points
        self.loyalty_points_earned = points
        
        # Add points to user profile
        if hasattr(self.user, 'profile'):
            self.user.profile.add_loyalty_points(points, 'Seat booking completion')
        
        self.save()
        
        # Log activity
        from apps.core.models import ActivityLog
        ActivityLog.objects.create(
            user=self.user,
            activity_type='SEAT_CHECKOUT',
            description=f'Checked out from seat {self.seat.seat_number}',
            metadata={
                'booking_id': str(self.id),
                'seat_code': self.seat.seat_code,
                'check_out_method': check_out_method,
                'duration_hours': self.actual_duration_hours,
                'points_earned': points,
            }
        )
        
        return True, "Checked out successfully"
    
    def cancel_booking(self, reason='User cancelled'):
        """Cancel the booking"""
        from django.utils import timezone
        
        if self.status not in ['CONFIRMED', 'PENDING']:
            return False, "Cannot cancel booking in current status"
        
        # Check if it's a late cancellation
        now = timezone.now()
        booking_start = timezone.datetime.combine(self.booking_date, self.start_time)
        hours_before = (booking_start - now).total_seconds() / 3600
        
        library_config = self.seat.library.configuration
        if hours_before < 2:  # Less than 2 hours before
            self.late_cancellation = True
            penalty_points = library_config.late_cancellation_penalty_points
            self.penalty_points = penalty_points
            
            # Deduct points from user profile
            if hasattr(self.user, 'profile'):
                self.user.profile.loyalty_points = max(
                    0, self.user.profile.loyalty_points - penalty_points
                )
                self.user.profile.save()
        
        self.status = 'CANCELLED'
        self.save()
        
        # Log activity
        from apps.core.models import ActivityLog
        ActivityLog.objects.create(
            user=self.user,
            activity_type='SEAT_BOOKING',
            description=f'Cancelled booking for seat {self.seat.seat_number}',
            metadata={
                'booking_id': str(self.id),
                'seat_code': self.seat.seat_code,
                'reason': reason,
                'late_cancellation': self.late_cancellation,
                'penalty_points': self.penalty_points,
            }
        )
        
        return True, "Booking cancelled successfully"


class SeatBookingWaitlist(BaseModel):
    """
    Model for seat booking waitlist
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='seat_waitlist')
    seat = models.ForeignKey(Seat, on_delete=models.CASCADE, related_name='waitlist')
    booking_date = models.DateField()
    preferred_start_time = models.TimeField()
    preferred_end_time = models.TimeField()
    
    # Flexibility options
    flexible_timing = models.BooleanField(default=False)
    acceptable_duration_hours = models.PositiveIntegerField(default=2)
    
    # Status
    is_active = models.BooleanField(default=True)
    notified_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField()
    
    # Priority
    priority_score = models.PositiveIntegerField(default=0)
    
    class Meta:
        db_table = 'seats_booking_waitlist'
        ordering = ['-priority_score', 'created_at']
        indexes = [
            models.Index(fields=['seat', 'booking_date', 'is_active']),
            models.Index(fields=['user', 'is_active']),
        ]
    
    def __str__(self):
        return f"{self.user.get_full_name()} - Waitlist for {self.seat.seat_number}"


class SeatReview(BaseModel):
    """
    Model for seat reviews and ratings
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='seat_reviews')
    seat = models.ForeignKey(Seat, on_delete=models.CASCADE, related_name='reviews')
    booking = models.ForeignKey(
        SeatBooking,
        on_delete=models.CASCADE,
        related_name='review',
        null=True,
        blank=True
    )
    
    # Ratings
    overall_rating = models.PositiveIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)]
    )
    comfort_rating = models.PositiveIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)],
        null=True, blank=True
    )
    cleanliness_rating = models.PositiveIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)],
        null=True, blank=True
    )
    noise_level_rating = models.PositiveIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)],
        null=True, blank=True
    )
    facilities_rating = models.PositiveIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)],
        null=True, blank=True
    )
    
    # Review Content
    title = models.CharField(max_length=200, blank=True)
    review_text = models.TextField()
    
    # Issues Reported
    reported_issues = models.JSONField(default=list, blank=True)
    
    # Moderation
    is_approved = models.BooleanField(default=False)
    approved_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='approved_seat_reviews'
    )
    
    class Meta:
        db_table = 'seats_review'
        unique_together = ['user', 'seat', 'booking']
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.seat.seat_number} - {self.user.get_full_name()} ({self.overall_rating}★)"


class SeatMaintenanceLog(BaseModel):
    """
    Model for tracking seat maintenance activities
    """
    MAINTENANCE_TYPES = [
        ('CLEANING', 'Cleaning'),
        ('REPAIR', 'Repair'),
        ('INSPECTION', 'Inspection'),
        ('UPGRADE', 'Upgrade'),
        ('REPLACEMENT', 'Replacement'),
    ]
    
    STATUS_CHOICES = [
        ('SCHEDULED', 'Scheduled'),
        ('IN_PROGRESS', 'In Progress'),
        ('COMPLETED', 'Completed'),
        ('CANCELLED', 'Cancelled'),
    ]
    
    seat = models.ForeignKey(Seat, on_delete=models.CASCADE, related_name='maintenance_logs')
    maintenance_type = models.CharField(max_length=15, choices=MAINTENANCE_TYPES)
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='SCHEDULED')
    
    # Scheduling
    scheduled_date = models.DateTimeField()
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    # Personnel
    assigned_to = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='assigned_maintenance'
    )
    performed_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='performed_maintenance'
    )
    
    # Details
    description = models.TextField()
    issues_found = models.TextField(blank=True)
    actions_taken = models.TextField(blank=True)
    parts_used = models.JSONField(default=list, blank=True)
    cost = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    
    # Follow-up
    requires_follow_up = models.BooleanField(default=False)
    follow_up_date = models.DateField(null=True, blank=True)
    follow_up_notes = models.TextField(blank=True)
    
    class Meta:
        db_table = 'seats_maintenance_log'
        ordering = ['-scheduled_date']
    
    def __str__(self):
        return f"{self.seat.seat_number} - {self.get_maintenance_type_display()} ({self.status})"


class SeatUsageStatistics(TimeStampedModel):
    """
    Model for tracking seat usage statistics
    """
    seat = models.ForeignKey(Seat, on_delete=models.CASCADE, related_name='usage_statistics')
    date = models.DateField()
    
    # Usage Metrics
    total_bookings = models.PositiveIntegerField(default=0)
    successful_checkins = models.PositiveIntegerField(default=0)
    no_shows = models.PositiveIntegerField(default=0)
    cancellations = models.PositiveIntegerField(default=0)
    
    # Time Metrics
    total_booked_hours = models.DecimalField(max_digits=8, decimal_places=2, default=0.00)
    total_used_hours = models.DecimalField(max_digits=8, decimal_places=2, default=0.00)
    average_session_duration = models.DecimalField(max_digits=6, decimal_places=2, default=0.00)
    
    # Utilization
    utilization_rate = models.DecimalField(max_digits=5, decimal_places=2, default=0.00)
    peak_usage_hour = models.TimeField(null=True, blank=True)
    
    # User Metrics
    unique_users = models.PositiveIntegerField(default=0)
    repeat_users = models.PositiveIntegerField(default=0)
    
    class Meta:
        db_table = 'seats_usage_statistics'
        unique_together = ['seat', 'date']
        ordering = ['seat', '-date']
    
    def __str__(self):
        return f"{self.seat.seat_number} - {self.date}"