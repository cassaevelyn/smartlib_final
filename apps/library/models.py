"""
Library models for Smart Lib
"""
from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator
from apps.core.models import BaseModel, TimeStampedModel
from apps.core.utils import generate_unique_code
import uuid


class Library(BaseModel):
    """
    Model representing a library location
    """
    LIBRARY_TYPES = [
        ('MAIN', 'Main Library'),
        ('BRANCH', 'Branch Library'),
        ('STUDY_CENTER', 'Study Center'),
        ('DIGITAL_HUB', 'Digital Hub'),
    ]
    
    STATUS_CHOICES = [
        ('ACTIVE', 'Active'),
        ('MAINTENANCE', 'Under Maintenance'),
        ('CLOSED', 'Temporarily Closed'),
        ('RENOVATION', 'Under Renovation'),
    ]
    
    name = models.CharField(max_length=200)
    code = models.CharField(max_length=20, unique=True, blank=True)
    library_type = models.CharField(max_length=15, choices=LIBRARY_TYPES, default='BRANCH')
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='ACTIVE')
    
    # Location Information
    address = models.TextField()
    city = models.CharField(max_length=100)
    postal_code = models.CharField(max_length=20, blank=True)
    latitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    longitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    
    # Contact Information
    phone_number = models.CharField(max_length=20, blank=True)
    email = models.EmailField(blank=True)
    website = models.URLField(blank=True)
    
    # Operating Hours
    opening_time = models.TimeField()
    closing_time = models.TimeField()
    is_24_hours = models.BooleanField(default=False)
    
    # Capacity and Features
    total_capacity = models.PositiveIntegerField(default=0)
    total_seats = models.PositiveIntegerField(default=0)
    total_study_rooms = models.PositiveIntegerField(default=0)
    has_wifi = models.BooleanField(default=True)
    has_printing = models.BooleanField(default=True)
    has_scanning = models.BooleanField(default=True)
    has_cafeteria = models.BooleanField(default=False)
    has_parking = models.BooleanField(default=False)
    
    # Images and Media
    main_image = models.ImageField(upload_to='libraries/images/', blank=True)
    gallery_images = models.JSONField(default=list, blank=True)
    floor_plan = models.FileField(upload_to='libraries/floor_plans/', blank=True)
    
    # Settings
    allow_booking = models.BooleanField(default=True)
    booking_advance_days = models.PositiveIntegerField(default=7)
    max_booking_duration_hours = models.PositiveIntegerField(default=8)
    auto_cancel_minutes = models.PositiveIntegerField(default=30)
    
    # Statistics
    total_visits = models.PositiveIntegerField(default=0)
    average_rating = models.DecimalField(max_digits=3, decimal_places=2, default=0.00)
    total_reviews = models.PositiveIntegerField(default=0)
    
    # Metadata
    description = models.TextField(blank=True)
    amenities = models.JSONField(default=list, blank=True)
    rules = models.JSONField(default=list, blank=True)
    
    class Meta:
        db_table = 'library_library'
        ordering = ['name']
        indexes = [
            models.Index(fields=['status', 'library_type']),
            models.Index(fields=['city']),
            models.Index(fields=['is_deleted', 'status']),
        ]
    
    def __str__(self):
        return f"{self.name} ({self.code})"
    
    def save(self, *args, **kwargs):
        if not self.code:
            self.code = generate_unique_code('LIB', 4)
        super().save(*args, **kwargs)
    
    @property
    def is_open(self):
        """Check if library is currently open"""
        if self.status != 'ACTIVE':
            return False
        
        if self.is_24_hours:
            return True
        
        from django.utils import timezone
        now = timezone.now().time()
        return self.opening_time <= now <= self.closing_time
    

    @property
    def occupancy_display(self):
        """Formatted occupancy rate (e.g., '85.5%') for admin display"""
        rate = self.get_occupancy_rate()  # Reuse your existing method
        return f"{rate:.1f}%"  # Format to 1 decimal place
    
    
    @property
    def available_seats(self):
        """Get number of available seats"""
        from apps.seats.models import Seat
        return Seat.objects.filter(
            library=self,
            status='AVAILABLE',
            is_deleted=False
        ).count()
    
    @property
    def occupied_seats(self):
        """Get number of occupied seats"""
        from apps.seats.models import Seat
        return Seat.objects.filter(
            library=self,
            status='OCCUPIED',
            is_deleted=False
        ).count()
    
    def get_occupancy_rate(self):
        """Calculate current occupancy rate"""
        if self.total_seats == 0:
            return 0
        return (self.occupied_seats / self.total_seats) * 100
    
    def can_user_access(self, user):
        """Check if user can access this library"""
        if user.is_super_admin:
            return True
        
        if user.role == 'ADMIN':
            admin_profile = getattr(user, 'admin_profile', None)
            return admin_profile and admin_profile.managed_library == self
        
        # Check user library access
        return user.library_access.filter(
            library=self,
            is_active=True
        ).exists()


class LibraryFloor(BaseModel):
    """
    Model representing floors within a library
    """
    library = models.ForeignKey(Library, on_delete=models.CASCADE, related_name='floors')
    floor_number = models.IntegerField()
    floor_name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    
    # Capacity
    total_seats = models.PositiveIntegerField(default=0)
    study_rooms = models.PositiveIntegerField(default=0)
    
    # Features
    has_silent_zone = models.BooleanField(default=False)
    has_group_study = models.BooleanField(default=False)
    has_computer_lab = models.BooleanField(default=False)
    has_printer = models.BooleanField(default=False)
    has_restroom = models.BooleanField(default=False)
    
    # Layout
    floor_plan_image = models.ImageField(upload_to='libraries/floor_plans/', blank=True)
    layout_data = models.JSONField(default=dict, blank=True)  # Store seat positions, etc.
    
    class Meta:
        db_table = 'library_floor'
        unique_together = ['library', 'floor_number']
        ordering = ['library', 'floor_number']
    
    def __str__(self):
        return f"{self.library.name} - {self.floor_name}"
    
    @property
    def available_seats(self):
        """Get available seats on this floor"""
        return self.seats.filter(status='AVAILABLE', is_deleted=False).count()
    
    @property
    def occupancy_rate(self):
        """Calculate floor occupancy rate"""
        if self.total_seats == 0:
            return 0
        occupied = self.seats.filter(status='OCCUPIED', is_deleted=False).count()
        return (occupied / self.total_seats) * 100


class LibrarySection(BaseModel):
    """
    Model representing sections within a library floor
    """
    SECTION_TYPES = [
        ('SILENT', 'Silent Study'),
        ('GROUP', 'Group Study'),
        ('COMPUTER', 'Computer Lab'),
        ('READING', 'Reading Area'),
        ('DISCUSSION', 'Discussion Area'),
        ('PRIVATE', 'Private Study Rooms'),
        ('GENERAL', 'General Seating'),
    ]
    
    floor = models.ForeignKey(LibraryFloor, on_delete=models.CASCADE, related_name='sections')
    name = models.CharField(max_length=100)
    section_type = models.CharField(max_length=15, choices=SECTION_TYPES)
    description = models.TextField(blank=True)
    
    # Capacity
    total_seats = models.PositiveIntegerField(default=0)
    max_occupancy = models.PositiveIntegerField(default=0)
    
    # Features
    has_power_outlets = models.BooleanField(default=True)
    has_ethernet = models.BooleanField(default=False)
    has_whiteboard = models.BooleanField(default=False)
    has_projector = models.BooleanField(default=False)
    noise_level = models.CharField(
        max_length=10,
        choices=[('SILENT', 'Silent'), ('LOW', 'Low'), ('MODERATE', 'Moderate')],
        default='LOW'
    )
    
    # Booking Settings
    requires_booking = models.BooleanField(default=True)
    advance_booking_hours = models.PositiveIntegerField(default=24)
    max_booking_duration = models.PositiveIntegerField(default=4)  # hours
    
    # Layout
    layout_coordinates = models.JSONField(default=dict, blank=True)
    
    class Meta:
        db_table = 'library_section'
        ordering = ['floor', 'name']
    
    def __str__(self):
        return f"{self.floor.library.name} - {self.floor.floor_name} - {self.name}"
    
    @property
    def available_seats(self):
        """Get available seats in this section"""
        return self.seats.filter(status='AVAILABLE', is_deleted=False).count()
    
    def is_section_full(self):
        """Check if section is at capacity"""
        current_occupancy = self.seats.filter(status='OCCUPIED', is_deleted=False).count()
        return current_occupancy >= self.max_occupancy


class LibraryAmenity(BaseModel):
    """
    Model for library amenities and facilities
    """
    AMENITY_TYPES = [
        ('FACILITY', 'Facility'),
        ('SERVICE', 'Service'),
        ('EQUIPMENT', 'Equipment'),
        ('COMFORT', 'Comfort'),
    ]
    
    library = models.ForeignKey(Library, on_delete=models.CASCADE, related_name='library_amenities')
    name = models.CharField(max_length=100)
    amenity_type = models.CharField(max_length=15, choices=AMENITY_TYPES)
    description = models.TextField(blank=True)
    icon = models.CharField(max_length=50, blank=True)  # Icon class or name
    is_available = models.BooleanField(default=True)
    is_premium = models.BooleanField(default=False)  # Requires premium subscription
    
    class Meta:
        db_table = 'library_amenity'
        unique_together = ['library', 'name']
    
    def __str__(self):
        return f"{self.library.name} - {self.name}"


class LibraryOperatingHours(BaseModel):
    """
    Model for detailed operating hours (different hours for different days)
    """
    DAYS_OF_WEEK = [
        (0, 'Monday'),
        (1, 'Tuesday'),
        (2, 'Wednesday'),
        (3, 'Thursday'),
        (4, 'Friday'),
        (5, 'Saturday'),
        (6, 'Sunday'),
    ]
    
    library = models.ForeignKey(Library, on_delete=models.CASCADE, related_name='operating_hours')
    day_of_week = models.IntegerField(choices=DAYS_OF_WEEK)
    opening_time = models.TimeField()
    closing_time = models.TimeField()
    is_closed = models.BooleanField(default=False)
    is_24_hours = models.BooleanField(default=False)
    
    class Meta:
        db_table = 'library_operating_hours'
        unique_together = ['library', 'day_of_week']
        ordering = ['library', 'day_of_week']
    
    def __str__(self):
        day_name = dict(self.DAYS_OF_WEEK)[self.day_of_week]
        if self.is_closed:
            return f"{self.library.name} - {day_name}: Closed"
        elif self.is_24_hours:
            return f"{self.library.name} - {day_name}: 24 Hours"
        else:
            return f"{self.library.name} - {day_name}: {self.opening_time} - {self.closing_time}"


class LibraryHoliday(BaseModel):
    """
    Model for library holidays and special closures
    """
    HOLIDAY_TYPES = [
        ('NATIONAL', 'National Holiday'),
        ('RELIGIOUS', 'Religious Holiday'),
        ('MAINTENANCE', 'Maintenance'),
        ('SPECIAL', 'Special Event'),
        ('EMERGENCY', 'Emergency Closure'),
    ]
    
    library = models.ForeignKey(Library, on_delete=models.CASCADE, related_name='holidays')
    name = models.CharField(max_length=200)
    holiday_type = models.CharField(max_length=15, choices=HOLIDAY_TYPES)
    start_date = models.DateField()
    end_date = models.DateField()
    description = models.TextField(blank=True)
    is_recurring = models.BooleanField(default=False)
    
    class Meta:
        db_table = 'library_holiday'
        ordering = ['library', 'start_date']
    
    def __str__(self):
        return f"{self.library.name} - {self.name} ({self.start_date})"
    
    def is_active_today(self):
        """Check if holiday is active today"""
        from django.utils import timezone
        today = timezone.now().date()
        return self.start_date <= today <= self.end_date


class LibraryReview(BaseModel):
    """
    Model for library reviews and ratings
    """
    library = models.ForeignKey(Library, on_delete=models.CASCADE, related_name='reviews')
    user = models.ForeignKey('accounts.User', on_delete=models.CASCADE, related_name='library_reviews')
    rating = models.PositiveIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)]
    )
    title = models.CharField(max_length=200, blank=True)
    review_text = models.TextField()
    
    # Review Categories
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
    staff_rating = models.PositiveIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)],
        null=True, blank=True
    )
    
    # Moderation
    is_approved = models.BooleanField(default=False)
    approved_by = models.ForeignKey(
        'accounts.User',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='approved_library_reviews'
    )
    approved_at = models.DateTimeField(null=True, blank=True)
    
    # Interaction
    helpful_count = models.PositiveIntegerField(default=0)
    reported_count = models.PositiveIntegerField(default=0)
    
    class Meta:
        db_table = 'library_review'
        unique_together = ['library', 'user']
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.library.name} - {self.user.get_full_name()} ({self.rating}★)"


class LibraryStatistics(TimeStampedModel):
    """
    Model for storing library statistics and analytics
    """
    library = models.ForeignKey(Library, on_delete=models.CASCADE, related_name='statistics')
    date = models.DateField()
    
    # Daily Statistics
    total_visitors = models.PositiveIntegerField(default=0)
    unique_visitors = models.PositiveIntegerField(default=0)
    total_bookings = models.PositiveIntegerField(default=0)
    successful_checkins = models.PositiveIntegerField(default=0)
    no_shows = models.PositiveIntegerField(default=0)
    cancellations = models.PositiveIntegerField(default=0)
    
    # Utilization
    peak_occupancy = models.PositiveIntegerField(default=0)
    average_occupancy = models.DecimalField(max_digits=5, decimal_places=2, default=0.00)
    peak_hour = models.TimeField(null=True, blank=True)
    
    # Duration Statistics
    average_session_duration = models.DurationField(null=True, blank=True)
    total_study_hours = models.DecimalField(max_digits=8, decimal_places=2, default=0.00)
    
    # Revenue (if applicable)
    subscription_revenue = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    penalty_revenue = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    
    class Meta:
        db_table = 'library_statistics'
        unique_together = ['library', 'date']
        ordering = ['library', '-date']
    
    def __str__(self):
        return f"{self.library.name} - {self.date}"


class LibraryNotification(BaseModel):
    """
    Model for library-specific notifications and announcements
    """
    NOTIFICATION_TYPES = [
        ('ANNOUNCEMENT', 'General Announcement'),
        ('MAINTENANCE', 'Maintenance Notice'),
        ('EVENT', 'Event Notification'),
        ('CLOSURE', 'Closure Notice'),
        ('POLICY', 'Policy Update'),
        ('EMERGENCY', 'Emergency Alert'),
    ]
    
    PRIORITY_LEVELS = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('URGENT', 'Urgent'),
    ]
    
    library = models.ForeignKey(Library, on_delete=models.CASCADE, related_name='notifications')
    title = models.CharField(max_length=200)
    message = models.TextField()
    notification_type = models.CharField(max_length=15, choices=NOTIFICATION_TYPES)
    priority = models.CharField(max_length=10, choices=PRIORITY_LEVELS, default='MEDIUM')
    
    # Targeting
    target_all_users = models.BooleanField(default=True)
    target_user_roles = models.JSONField(default=list, blank=True)  # ['STUDENT', 'ADMIN']
    
    # Scheduling
    start_date = models.DateTimeField()
    end_date = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    
    # Display Settings
    show_on_dashboard = models.BooleanField(default=True)
    show_on_booking = models.BooleanField(default=False)
    requires_acknowledgment = models.BooleanField(default=False)
    
    # Statistics
    views_count = models.PositiveIntegerField(default=0)
    acknowledgments_count = models.PositiveIntegerField(default=0)
    
    class Meta:
        db_table = 'library_notification'
        ordering = ['-priority', '-created_at']
        indexes = [
            models.Index(fields=['library', 'is_active', 'start_date']),
            models.Index(fields=['notification_type', 'priority']),
        ]
    
    def __str__(self):
        return f"{self.library.name} - {self.title}"
    
    def is_currently_active(self):
        """Check if notification is currently active"""
        from django.utils import timezone
        now = timezone.now()
        
        if not self.is_active:
            return False
        
        if now < self.start_date:
            return False
        
        if self.end_date and now > self.end_date:
            return False
        
        return True


class LibraryConfiguration(BaseModel):
    """
    Model for library-specific configuration settings
    """
    library = models.OneToOneField(
        Library,
        on_delete=models.CASCADE,
        related_name='configuration'
    )
    
    # Booking Settings
    max_advance_booking_days = models.PositiveIntegerField(default=7)
    max_daily_bookings_per_user = models.PositiveIntegerField(default=1)
    max_booking_duration_hours = models.PositiveIntegerField(default=8)
    min_booking_duration_minutes = models.PositiveIntegerField(default=30)
    auto_cancel_no_show_minutes = models.PositiveIntegerField(default=30)
    
    # Check-in/Check-out Settings
    early_checkin_minutes = models.PositiveIntegerField(default=15)
    late_checkout_grace_minutes = models.PositiveIntegerField(default=15)
    qr_code_expiry_minutes = models.PositiveIntegerField(default=15)
    
    # Penalty Settings
    no_show_penalty_points = models.PositiveIntegerField(default=10)
    late_cancellation_penalty_points = models.PositiveIntegerField(default=5)
    overstay_penalty_per_hour = models.PositiveIntegerField(default=5)
    
    # Loyalty Settings
    booking_completion_points = models.PositiveIntegerField(default=10)
    review_submission_points = models.PositiveIntegerField(default=5)
    referral_points = models.PositiveIntegerField(default=25)
    
    # Notification Settings
    reminder_hours_before = models.JSONField(default=list, blank=True)  # [24, 2, 0.5]
    send_booking_confirmations = models.BooleanField(default=True)
    send_checkin_reminders = models.BooleanField(default=True)
    send_checkout_reminders = models.BooleanField(default=True)
    
    # Feature Flags
    enable_seat_selection = models.BooleanField(default=True)
    enable_recurring_bookings = models.BooleanField(default=False)
    enable_group_bookings = models.BooleanField(default=False)
    enable_waitlist = models.BooleanField(default=True)
    enable_reviews = models.BooleanField(default=True)
    
    # Integration Settings
    integration_settings = models.JSONField(default=dict, blank=True)
    
    class Meta:
        db_table = 'library_configuration'
    
    def __str__(self):
        return f"{self.library.name} - Configuration"