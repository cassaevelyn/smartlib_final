"""
Event models for Smart Lib
"""
from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator
from django.contrib.auth import get_user_model
from apps.core.models import BaseModel, TimeStampedModel
from apps.core.utils import generate_unique_code, generate_qr_code
from datetime import timedelta
import uuid

User = get_user_model()


class EventCategory(BaseModel):
    """
    Model for event categories
    """
    name = models.CharField(max_length=100, unique=True)
    code = models.CharField(max_length=20, unique=True, blank=True)
    description = models.TextField(blank=True)
    icon = models.CharField(max_length=50, blank=True)
    color = models.CharField(max_length=7, default='#007bff')  # Hex color
    is_active = models.BooleanField(default=True)
    sort_order = models.PositiveIntegerField(default=0)
    
    class Meta:
        db_table = 'events_category'
        ordering = ['sort_order', 'name']
        verbose_name_plural = 'Event Categories'
    
    def __str__(self):
        return self.name
    
    def save(self, *args, **kwargs):
        if not self.code:
            self.code = generate_unique_code('EC', 3)
        super().save(*args, **kwargs)
    
    @property
    def events_count(self):
        return self.events.filter(is_deleted=False).count()


class EventSpeaker(BaseModel):
    """
    Model for event speakers/presenters
    """
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    title = models.CharField(max_length=200, blank=True)  # Dr., Prof., etc.
    organization = models.CharField(max_length=200, blank=True)
    bio = models.TextField(blank=True)
    expertise = models.JSONField(default=list, blank=True)  # Areas of expertise
    
    # Contact Information
    email = models.EmailField(blank=True)
    phone = models.CharField(max_length=20, blank=True)
    website = models.URLField(blank=True)
    linkedin = models.URLField(blank=True)
    
    # Media
    photo = models.ImageField(upload_to='speakers/photos/', blank=True)
    
    # Statistics
    total_events = models.PositiveIntegerField(default=0)
    average_rating = models.DecimalField(max_digits=3, decimal_places=2, default=0.00)
    
    class Meta:
        db_table = 'events_speaker'
        ordering = ['last_name', 'first_name']
    
    def __str__(self):
        full_name = f"{self.first_name} {self.last_name}"
        if self.title:
            return f"{self.title} {full_name}"
        return full_name
    
    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"


class Event(BaseModel):
    """
    Model for library events
    """
    EVENT_TYPES = [
        ('WORKSHOP', 'Workshop'),
        ('SEMINAR', 'Seminar'),
        ('LECTURE', 'Lecture'),
        ('CONFERENCE', 'Conference'),
        ('TRAINING', 'Training Session'),
        ('BOOK_CLUB', 'Book Club'),
        ('STUDY_GROUP', 'Study Group'),
        ('EXAM_PREP', 'Exam Preparation'),
        ('NETWORKING', 'Networking Event'),
        ('CULTURAL', 'Cultural Event'),
        ('COMPETITION', 'Competition'),
        ('ORIENTATION', 'Orientation'),
    ]
    
    EVENT_STATUS = [
        ('DRAFT', 'Draft'),
        ('PUBLISHED', 'Published'),
        ('REGISTRATION_OPEN', 'Registration Open'),
        ('REGISTRATION_CLOSED', 'Registration Closed'),
        ('IN_PROGRESS', 'In Progress'),
        ('COMPLETED', 'Completed'),
        ('CANCELLED', 'Cancelled'),
        ('POSTPONED', 'Postponed'),
    ]
    
    REGISTRATION_TYPES = [
        ('FREE', 'Free Registration'),
        ('PAID', 'Paid Registration'),
        ('INVITATION_ONLY', 'Invitation Only'),
        ('FIRST_COME_FIRST_SERVE', 'First Come First Serve'),
        ('APPROVAL_REQUIRED', 'Approval Required'),
    ]
    
    # Basic Information
    title = models.CharField(max_length=300)
    slug = models.SlugField(max_length=350, unique=True, blank=True)
    event_code = models.CharField(max_length=30, unique=True, blank=True)
    category = models.ForeignKey(EventCategory, on_delete=models.PROTECT, related_name='events')
    event_type = models.CharField(max_length=15, choices=EVENT_TYPES, default='WORKSHOP')
    status = models.CharField(max_length=20, choices=EVENT_STATUS, default='DRAFT')
    
    # Content
    description = models.TextField()
    agenda = models.TextField(blank=True)
    learning_objectives = models.JSONField(default=list, blank=True)
    prerequisites = models.TextField(blank=True)
    materials_provided = models.JSONField(default=list, blank=True)
    
    # Speakers and Organizers
    speakers = models.ManyToManyField(EventSpeaker, related_name='events', blank=True)
    organizer = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='organized_events'
    )
    co_organizers = models.ManyToManyField(
        User,
        related_name='co_organized_events',
        blank=True
    )
    
    # Scheduling
    start_date = models.DateField()
    end_date = models.DateField()
    start_time = models.TimeField()
    end_time = models.TimeField()
    timezone = models.CharField(max_length=50, default='Asia/Karachi')
    is_recurring = models.BooleanField(default=False)
    recurrence_pattern = models.JSONField(default=dict, blank=True)
    
    # Location
    library = models.ForeignKey('library.Library', on_delete=models.CASCADE, related_name='events')
    venue_details = models.TextField(blank=True)  # Room number, floor, etc.
    is_online = models.BooleanField(default=False)
    online_meeting_link = models.URLField(blank=True)
    online_meeting_password = models.CharField(max_length=100, blank=True)
    
    # Registration
    registration_type = models.CharField(max_length=25, choices=REGISTRATION_TYPES, default='FREE')
    registration_fee = models.DecimalField(max_digits=8, decimal_places=2, default=0.00)
    max_participants = models.PositiveIntegerField(default=50)
    min_participants = models.PositiveIntegerField(default=1)
    registration_deadline = models.DateTimeField()
    early_bird_deadline = models.DateTimeField(null=True, blank=True)
    early_bird_discount = models.DecimalField(max_digits=5, decimal_places=2, default=0.00)
    
    # Eligibility
    target_audience = models.JSONField(default=list, blank=True)  # ['STUDENT', 'FACULTY', 'PUBLIC']
    required_role = models.CharField(max_length=20, blank=True)  # Specific user role required
    required_subscription = models.BooleanField(default=False)  # Premium subscription required
    
    # Media and Resources
    banner_image = models.ImageField(upload_to='events/banners/', blank=True)
    thumbnail = models.ImageField(upload_to='events/thumbnails/', blank=True)
    gallery_images = models.JSONField(default=list, blank=True)
    attachments = models.JSONField(default=list, blank=True)  # PDFs, documents
    
    # Features
    has_certificate = models.BooleanField(default=False)
    certificate_template = models.FileField(upload_to='events/certificates/', blank=True)
    has_feedback_form = models.BooleanField(default=True)
    requires_attendance_tracking = models.BooleanField(default=True)
    
    # Statistics
    total_registrations = models.PositiveIntegerField(default=0)
    total_attendees = models.PositiveIntegerField(default=0)
    average_rating = models.DecimalField(max_digits=3, decimal_places=2, default=0.00)
    total_feedback = models.PositiveIntegerField(default=0)
    
    # Notifications
    send_reminders = models.BooleanField(default=True)
    reminder_hours = models.JSONField(default=list, blank=True)  # [24, 2] hours before
    
    # Metadata
    tags = models.JSONField(default=list, blank=True)
    external_links = models.JSONField(default=dict, blank=True)
    additional_info = models.JSONField(default=dict, blank=True)
    
    class Meta:
        db_table = 'events_event'
        ordering = ['-start_date', '-start_time']
        indexes = [
            models.Index(fields=['start_date', 'start_time']),
            models.Index(fields=['status', 'registration_deadline']),
            models.Index(fields=['library', 'start_date']),
            models.Index(fields=['category', 'event_type']),
        ]
    
    def __str__(self):
        return f"{self.title} ({self.event_code})"
    
    def save(self, *args, **kwargs):
        if not self.event_code:
            self.event_code = generate_unique_code('EV', 6)
        
        if not self.slug:
            from django.utils.text import slugify
            self.slug = slugify(self.title)
        
        super().save(*args, **kwargs)
    
    @property
    def is_registration_open(self):
        """Check if registration is currently open"""
        from django.utils import timezone
        now = timezone.now()
        return (
            self.status == 'REGISTRATION_OPEN' and
            now <= self.registration_deadline and
            self.total_registrations < self.max_participants
        )
    
    @property
    def is_full(self):
        """Check if event is at capacity"""
        return self.total_registrations >= self.max_participants
    
    @property
    def available_spots(self):
        """Get number of available spots"""
        return max(0, self.max_participants - self.total_registrations)
    
    @property
    def duration_hours(self):
        """Calculate event duration in hours"""
        from django.utils import timezone
        start_datetime = timezone.datetime.combine(self.start_date, self.start_time)
        end_datetime = timezone.datetime.combine(self.end_date, self.end_time)
        return (end_datetime - start_datetime).total_seconds() / 3600
    
    @property
    def speakers_list(self):
        """Get comma-separated list of speakers"""
        return ", ".join([speaker.full_name for speaker in self.speakers.all()])
    
    def can_user_register(self, user):
        """Check if user can register for this event"""
        if not self.is_registration_open:
            return False, "Registration is not open"
        
        if self.is_full:
            return False, "Event is full"
        
        # Check if user already registered
        if self.registrations.filter(user=user, status__in=['CONFIRMED', 'ATTENDED'], is_deleted=False).exists():
            return False, "You are already registered for this event"
        
        # Check target audience
        if self.target_audience and user.role not in self.target_audience:
            return False, "This event is not open to your user type"
        
        # Check required role
        if self.required_role and user.role != self.required_role:
            return False, f"This event requires {self.required_role} role"
        
        # Check subscription requirement
        if self.required_subscription and not hasattr(user, 'current_subscription'):
            return False, "This event requires an active subscription"
        
        # Check library access
        if not self.library.can_user_access(user):
            return False, "You don't have access to this library"
        
        return True, "You can register for this event"
    
    def get_registration_fee_for_user(self, user):
        """Get registration fee for specific user (considering early bird)"""
        from django.utils import timezone
        
        if self.registration_type == 'FREE':
            return 0.00
        
        base_fee = self.registration_fee
        
        # Apply early bird discount
        if (self.early_bird_deadline and 
            timezone.now() <= self.early_bird_deadline and 
            self.early_bird_discount > 0):
            discount_amount = base_fee * (self.early_bird_discount / 100)
            return base_fee - discount_amount
        
        return base_fee


class EventRegistration(BaseModel):
    """
    Model for event registrations
    """
    REGISTRATION_STATUS = [
        ('PENDING', 'Pending Approval'),
        ('CONFIRMED', 'Confirmed'),
        ('WAITLISTED', 'Waitlisted'),
        ('CANCELLED', 'Cancelled'),
        ('ATTENDED', 'Attended'),
        ('NO_SHOW', 'No Show'),
        ('REFUNDED', 'Refunded'),
    ]
    
    PAYMENT_STATUS = [
        ('PENDING', 'Payment Pending'),
        ('COMPLETED', 'Payment Completed'),
        ('FAILED', 'Payment Failed'),
        ('REFUNDED', 'Refunded'),
        ('NOT_REQUIRED', 'Not Required'),
    ]
    
    # Basic Information
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='event_registrations')
    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name='registrations')
    registration_code = models.CharField(max_length=30, unique=True, blank=True)
    status = models.CharField(max_length=15, choices=REGISTRATION_STATUS, default='CONFIRMED')
    
    # Registration Details
    registration_date = models.DateTimeField(auto_now_add=True)
    registration_fee_paid = models.DecimalField(max_digits=8, decimal_places=2, default=0.00)
    payment_status = models.CharField(max_length=15, choices=PAYMENT_STATUS, default='NOT_REQUIRED')
    payment_reference = models.CharField(max_length=100, blank=True)
    
    # Attendance Tracking
    check_in_time = models.DateTimeField(null=True, blank=True)
    check_out_time = models.DateTimeField(null=True, blank=True)
    attendance_duration = models.DurationField(null=True, blank=True)
    qr_code_data = models.TextField(blank=True)
    qr_code_expires_at = models.DateTimeField(null=True, blank=True)
    
    # Additional Information
    dietary_requirements = models.TextField(blank=True)
    special_needs = models.TextField(blank=True)
    emergency_contact = models.CharField(max_length=200, blank=True)
    how_did_you_hear = models.CharField(max_length=200, blank=True)
    expectations = models.TextField(blank=True)
    
    # Certificates and Feedback
    certificate_issued = models.BooleanField(default=False)
    certificate_file = models.FileField(upload_to='certificates/', blank=True)
    feedback_submitted = models.BooleanField(default=False)
    
    # Notifications
    reminder_sent = models.BooleanField(default=False)
    confirmation_sent = models.BooleanField(default=False)
    
    class Meta:
        db_table = 'events_registration'
        unique_together = ['user', 'event']
        ordering = ['-registration_date']
        indexes = [
            models.Index(fields=['user', 'status']),
            models.Index(fields=['event', 'status']),
            models.Index(fields=['registration_date']),
        ]
    
    def __str__(self):
        return f"{self.user.get_full_name()} - {self.event.title} ({self.status})"
    
    def save(self, *args, **kwargs):
        if not self.registration_code:
            self.registration_code = generate_unique_code('ER', 8)
        super().save(*args, **kwargs)
    
    @property
    def can_check_in(self):
        """Check if user can check in to the event"""
        from django.utils import timezone
        now = timezone.now()
        event_start = timezone.datetime.combine(self.event.start_date, self.event.start_time)
        
        # Allow check-in 30 minutes before event starts
        check_in_window = event_start - timedelta(minutes=30)
        
        return (
            self.status == 'CONFIRMED' and
            now >= check_in_window and
            not self.check_in_time
        )
    
    @property
    def can_check_out(self):
        """Check if user can check out from the event"""
        return self.status == 'ATTENDED' and self.check_in_time and not self.check_out_time
    
    def generate_qr_code(self):
        """Generate QR code for event check-in"""
        from django.utils import timezone
        from apps.core.utils import generate_secure_token
        
        # Generate QR code data
        qr_data = {
            'registration_id': str(self.id),
            'registration_code': self.registration_code,
            'event_id': str(self.event.id),
            'event_code': self.event.event_code,
            'user_id': str(self.user.id),
            'access_token': generate_secure_token()[:16],
            'generated_at': timezone.now().isoformat()
        }
        
        import json
        self.qr_code_data = json.dumps(qr_data)
        self.qr_code_expires_at = timezone.now() + timedelta(hours=24)
        self.save()
        
        return qr_data
    
    def check_in(self, check_in_method='QR'):
        """Check in to the event"""
        from django.utils import timezone
        
        if not self.can_check_in:
            return False, "Cannot check in at this time"
        
        self.status = 'ATTENDED'
        self.check_in_time = timezone.now()
        self.save()
        
        # Update event statistics
        self.event.total_attendees += 1
        self.event.save()
        
        # Log activity
        from apps.core.models import ActivityLog
        ActivityLog.objects.create(
            user=self.user,
            activity_type='EVENT_ATTEND',
            description=f'Checked in to event: {self.event.title}',
            metadata={
                'registration_id': str(self.id),
                'event_id': str(self.event.id),
                'event_title': self.event.title,
                'check_in_method': check_in_method,
            }
        )
        
        return True, "Checked in successfully"
    
    def check_out(self, check_out_method='QR'):
        """Check out from the event"""
        from django.utils import timezone
        
        if not self.can_check_out:
            return False, "Cannot check out at this time"
        
        self.check_out_time = timezone.now()
        if self.check_in_time:
            self.attendance_duration = self.check_out_time - self.check_in_time
        
        self.save()
        
        # Award loyalty points for attendance
        if hasattr(self.user, 'profile'):
            points = 25  # Points for event attendance
            self.user.profile.add_loyalty_points(points, f'Event attendance: {self.event.title}')
        
        return True, "Checked out successfully"
    
    def cancel_registration(self, reason='User cancelled'):
        """Cancel the registration"""
        if self.status not in ['CONFIRMED', 'PENDING']:
            return False, "Cannot cancel registration in current status"
        
        self.status = 'CANCELLED'
        self.save()
        
        # Update event statistics
        self.event.total_registrations = max(0, self.event.total_registrations - 1)
        self.event.save()
        
        return True, "Registration cancelled successfully"


class EventFeedback(BaseModel):
    """
    Model for event feedback and ratings
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='event_feedback')
    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name='feedback')
    registration = models.OneToOneField(
        EventRegistration,
        on_delete=models.CASCADE,
        related_name='feedback'
    )
    
    # Ratings
    overall_rating = models.PositiveIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)]
    )
    content_rating = models.PositiveIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)],
        null=True, blank=True
    )
    speaker_rating = models.PositiveIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)],
        null=True, blank=True
    )
    organization_rating = models.PositiveIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)],
        null=True, blank=True
    )
    venue_rating = models.PositiveIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)],
        null=True, blank=True
    )
    
    # Feedback Content
    what_you_liked = models.TextField(blank=True)
    what_could_improve = models.TextField(blank=True)
    additional_comments = models.TextField(blank=True)
    would_recommend = models.BooleanField(default=True)
    would_attend_similar = models.BooleanField(default=True)
    
    # Suggestions
    future_topics = models.TextField(blank=True)
    preferred_format = models.CharField(max_length=100, blank=True)
    preferred_duration = models.CharField(max_length=100, blank=True)
    
    class Meta:
        db_table = 'events_feedback'
        unique_together = ['user', 'event']
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.event.title} - {self.user.get_full_name()} ({self.overall_rating}★)"


class EventWaitlist(BaseModel):
    """
    Model for event waitlist when events are full
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='event_waitlist')
    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name='waitlist')
    position = models.PositiveIntegerField()
    notified = models.BooleanField(default=False)
    notification_sent_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField()
    
    class Meta:
        db_table = 'events_waitlist'
        unique_together = ['user', 'event']
        ordering = ['position']
    
    def __str__(self):
        return f"{self.user.get_full_name()} - {self.event.title} (Position: {self.position})"


class EventResource(BaseModel):
    """
    Model for event resources and materials
    """
    RESOURCE_TYPES = [
        ('PRESENTATION', 'Presentation'),
        ('DOCUMENT', 'Document'),
        ('VIDEO', 'Video'),
        ('AUDIO', 'Audio'),
        ('LINK', 'External Link'),
        ('READING_MATERIAL', 'Reading Material'),
        ('ASSIGNMENT', 'Assignment'),
        ('CERTIFICATE', 'Certificate Template'),
    ]
    
    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name='resources')
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    resource_type = models.CharField(max_length=20, choices=RESOURCE_TYPES)
    
    # File or Link
    file = models.FileField(upload_to='events/resources/', blank=True)
    external_link = models.URLField(blank=True)
    
    # Access Control
    is_public = models.BooleanField(default=False)  # Available to all or only attendees
    available_before_event = models.BooleanField(default=False)
    available_after_event = models.BooleanField(default=True)
    
    # Metadata
    file_size = models.PositiveIntegerField(null=True, blank=True)
    download_count = models.PositiveIntegerField(default=0)
    
    class Meta:
        db_table = 'events_resource'
        ordering = ['resource_type', 'title']
    
    def __str__(self):
        return f"{self.event.title} - {self.title}"


class EventStatistics(TimeStampedModel):
    """
    Model for tracking event statistics and analytics
    """
    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name='statistics')
    date = models.DateField()
    
    # Registration Statistics
    new_registrations = models.PositiveIntegerField(default=0)
    total_registrations = models.PositiveIntegerField(default=0)
    cancellations = models.PositiveIntegerField(default=0)
    
    # Attendance Statistics
    attendees = models.PositiveIntegerField(default=0)
    no_shows = models.PositiveIntegerField(default=0)
    attendance_rate = models.DecimalField(max_digits=5, decimal_places=2, default=0.00)
    
    # Engagement Statistics
    average_attendance_duration = models.DurationField(null=True, blank=True)
    feedback_submissions = models.PositiveIntegerField(default=0)
    average_rating = models.DecimalField(max_digits=3, decimal_places=2, default=0.00)
    
    # Resource Usage
    resource_downloads = models.PositiveIntegerField(default=0)
    
    class Meta:
        db_table = 'events_statistics'
        unique_together = ['event', 'date']
        ordering = ['event', '-date']
    
    def __str__(self):
        return f"{self.event.title} - {self.date}"


class EventSeries(BaseModel):
    """
    Model for event series (multiple related events)
    """
    name = models.CharField(max_length=200)
    description = models.TextField()
    organizer = models.ForeignKey(User, on_delete=models.CASCADE, related_name='event_series')
    events = models.ManyToManyField(Event, related_name='series', blank=True)
    
    # Media
    banner_image = models.ImageField(upload_to='events/series/', blank=True)
    
    # Settings
    is_active = models.BooleanField(default=True)
    requires_series_registration = models.BooleanField(default=False)
    series_fee = models.DecimalField(max_digits=8, decimal_places=2, default=0.00)
    
    class Meta:
        db_table = 'events_series'
        ordering = ['name']
        verbose_name_plural = 'Event Series'
    
    def __str__(self):
        return self.name
    
    @property
    def total_events(self):
        return self.events.count()
    
    @property
    def upcoming_events(self):
        from django.utils import timezone
        return self.events.filter(
            start_date__gte=timezone.now().date(),
            is_deleted=False
        ).order_by('start_date', 'start_time')


class EventNotification(BaseModel):
    """
    Model for event-specific notifications and announcements
    """
    NOTIFICATION_TYPES = [
        ('REMINDER', 'Event Reminder'),
        ('UPDATE', 'Event Update'),
        ('CANCELLATION', 'Event Cancellation'),
        ('POSTPONEMENT', 'Event Postponement'),
        ('VENUE_CHANGE', 'Venue Change'),
        ('SPEAKER_CHANGE', 'Speaker Change'),
        ('GENERAL', 'General Announcement'),
    ]
    
    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name='notifications')
    notification_type = models.CharField(max_length=15, choices=NOTIFICATION_TYPES)
    title = models.CharField(max_length=200)
    message = models.TextField()
    
    # Targeting
    send_to_all_registrants = models.BooleanField(default=True)
    send_to_attendees_only = models.BooleanField(default=False)
    send_to_waitlist = models.BooleanField(default=False)
    
    # Scheduling
    send_immediately = models.BooleanField(default=True)
    scheduled_send_time = models.DateTimeField(null=True, blank=True)
    
    # Status
    is_sent = models.BooleanField(default=False)
    sent_at = models.DateTimeField(null=True, blank=True)
    recipients_count = models.PositiveIntegerField(default=0)
    
    class Meta:
        db_table = 'events_notification'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.event.title} - {self.title}"