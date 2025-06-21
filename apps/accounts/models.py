"""
User models for Smart Lib
"""
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import RegexValidator
from apps.core.models import BaseModel, TimeStampedModel
from apps.core.utils import generate_unique_code, hash_sensitive_data
import uuid


class User(AbstractUser):
    """
    Custom User model for Smart Lib
    """
    USER_ROLES = [
        ('STUDENT', 'Student'),
        ('ADMIN', 'Library Admin'),
        ('SUPER_ADMIN', 'Super Admin'),
    ]
    
    GENDER_CHOICES = [
        ('M', 'Male'),
        ('F', 'Female'),
        ('O', 'Other'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    phone_number = models.CharField(
        max_length=15,
        validators=[RegexValidator(r'^\+?1?\d{9,15}$', 'Enter a valid phone number.')],
        blank=True
    )
    
    # ICAP CA specific fields
    crn = models.CharField(
        max_length=20,
        unique=True,
        validators=[RegexValidator(r'^ICAP-CA-\d{4}-\d{4}$', 'Enter valid CRN format: ICAP-CA-YYYY-####')],
        help_text='ICAP CA Registration Number (e.g., ICAP-CA-2023-1234)'
    )
    student_id = models.CharField(max_length=20, unique=True, blank=True)
    
    # Personal Information
    date_of_birth = models.DateField(null=True, blank=True)
    gender = models.CharField(max_length=1, choices=GENDER_CHOICES, blank=True)
    address = models.TextField(blank=True)
    city = models.CharField(max_length=100, blank=True)
    
    # Role and Status
    role = models.CharField(max_length=15, choices=USER_ROLES, default='STUDENT')
    is_verified = models.BooleanField(default=False)  # Email verification status
    
    # Profile
    avatar = models.ImageField(upload_to='avatars/%Y/%m/', blank=True)
    bio = models.TextField(max_length=500, blank=True)
    
    # Preferences
    preferred_language = models.CharField(max_length=10, default='en')
    notification_preferences = models.JSONField(default=dict, blank=True)
    
    # Tracking
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    login_count = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Subscription
    current_subscription = models.ForeignKey(
        'subscriptions.UserSubscription',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='current_users'
    )
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'crn', 'first_name', 'last_name']
    
    class Meta:
        db_table = 'accounts_user'
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['crn']),
            models.Index(fields=['role', 'is_verified']),
            models.Index(fields=['is_active', 'is_verified']),
        ]
    
    def __str__(self):
        return f"{self.get_full_name()} ({self.crn})"
    
    def save(self, *args, **kwargs):
        if not self.student_id:
            self.student_id = generate_unique_code('SL', 6)
        
        # Set is_active to False for new users until email verification
        if not self.pk:
            self.is_active = False
            
        super().save(*args, **kwargs)
    
    @property
    def full_name(self):
        return self.get_full_name()
    
    @property
    def is_student(self):
        return self.role == 'STUDENT'
    
    @property
    def is_admin(self):
        return self.role in ['ADMIN', 'SUPER_ADMIN']
    
    @property
    def is_super_admin(self):
        return self.role == 'SUPER_ADMIN'
    
    @property
    def has_active_subscription(self):
        """Check if user has an active subscription"""
        if not self.current_subscription:
            return False
        return self.current_subscription.is_active
    
    @property
    def has_admin_profile(self):
        """Check if user has an admin profile"""
        return hasattr(self, 'admin_profile')
    
    def can_access_library(self, library):
        """Check if user can access a specific library"""
        if self.is_super_admin:
            return True
        if self.role == 'ADMIN':
            return hasattr(self, 'admin_profile') and self.admin_profile.managed_library == library
        if self.is_student:
            return library in self.accessible_libraries.all()
        return False
    
    def get_notification_preferences(self):
        """Get user notification preferences with defaults"""
        defaults = {
            'email_notifications': True,
            'booking_reminders': True,
            'event_notifications': True,
            'book_due_reminders': True,
            'loyalty_updates': True,
        }
        return {**defaults, **self.notification_preferences}


class UserProfile(BaseModel):
    """
    Extended profile information for users
    """
    EDUCATION_LEVELS = [
        ('FOUNDATION', 'Foundation'),
        ('INTERMEDIATE', 'Intermediate'),
        ('ADVANCED', 'Advanced'),
        ('FINAL', 'Final'),
    ]
    
    STUDY_TIMES = [
        ('MORNING', 'Morning'),
        ('AFTERNOON', 'Afternoon'),
        ('EVENING', 'Evening'),
        ('NIGHT', 'Night'),
        ('FLEXIBLE', 'Flexible'),
    ]
    
    SEAT_TYPES = [
        ('INDIVIDUAL', 'Individual Study'),
        ('GROUP', 'Group Study'),
        ('COMPUTER', 'Computer Workstation'),
        ('SILENT', 'Silent Study'),
        ('WINDOW', 'Window Seat'),
        ('ANY', 'Any Type'),
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    
    # Academic Information
    education_level = models.CharField(max_length=20, choices=EDUCATION_LEVELS, blank=True, null=True)
    enrollment_year = models.PositiveIntegerField(blank=True, null=True)
    expected_completion_year = models.PositiveIntegerField(blank=True, null=True)
    study_subjects = models.JSONField(default=list, blank=True)
    
    # Emergency Contact
    emergency_contact_name = models.CharField(max_length=100, blank=True)
    emergency_contact_phone = models.CharField(max_length=20, blank=True)
    emergency_contact_relation = models.CharField(max_length=50, blank=True)
    
    # Preferences
    preferred_study_time = models.CharField(max_length=20, choices=STUDY_TIMES, blank=True, null=True)
    preferred_seat_type = models.CharField(max_length=20, choices=SEAT_TYPES, blank=True, null=True)
    
    # Statistics
    loyalty_points = models.PositiveIntegerField(default=0)
    total_study_hours = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    books_read = models.PositiveIntegerField(default=0)
    events_attended = models.PositiveIntegerField(default=0)
    
    class Meta:
        db_table = 'accounts_user_profile'
    
    def __str__(self):
        return f"Profile for {self.user.get_full_name()}"
    
    def add_loyalty_points(self, points, reason, reference_id=None):
        """Add loyalty points and create a transaction record"""
        self.loyalty_points += points
        self.save()
        
        # Create transaction record
        LoyaltyTransaction.objects.create(
            user=self.user,
            points=points,
            transaction_type='EARNED',
            description=reason,
            reference_id=reference_id,
            created_by=self.user
        )
        
        return True
    
    def deduct_loyalty_points(self, points, reason, reference_id=None):
        """Deduct loyalty points if available and create a transaction record"""
        if self.loyalty_points < points:
            return False
        
        self.loyalty_points -= points
        self.save()
        
        # Create transaction record
        LoyaltyTransaction.objects.create(
            user=self.user,
            points=points,
            transaction_type='SPENT',
            description=reason,
            reference_id=reference_id,
            created_by=self.user
        )
        
        return True


class LoyaltyTransaction(BaseModel):
    """
    Model to track loyalty points transactions
    """
    TRANSACTION_TYPES = [
        ('EARNED', 'Points Earned'),
        ('SPENT', 'Points Spent'),
        ('EXPIRED', 'Points Expired'),
        ('ADJUSTED', 'Points Adjusted'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='loyalty_transactions')
    points = models.IntegerField()  # Can be positive (earned) or negative (spent)
    transaction_type = models.CharField(max_length=10, choices=TRANSACTION_TYPES)
    description = models.CharField(max_length=255)
    reference_id = models.CharField(max_length=100, blank=True, null=True)  # Reference to related entity (booking, reservation, etc.)
    
    class Meta:
        db_table = 'accounts_loyalty_transaction'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.user.get_full_name()} - {self.points} points ({self.transaction_type})"


class UserSession(BaseModel):
    """
    Model to track user sessions
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sessions')
    session_key = models.CharField(max_length=40)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    device_info = models.JSONField(default=dict, blank=True)
    is_active = models.BooleanField(default=True)
    last_activity = models.DateTimeField(auto_now=True)
    logout_time = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'accounts_user_session'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.user.get_full_name()} - {self.created_at}"
    
    def end_session(self):
        """End the session"""
        from django.utils import timezone
        self.is_active = False
        self.logout_time = timezone.now()
        self.save()


class UserVerification(BaseModel):
    """
    Model for user verification tokens (email verification, password reset, etc.)
    """
    VERIFICATION_TYPES = [
        ('EMAIL', 'Email Verification'),
        ('PASSWORD_RESET', 'Password Reset'),
        ('ACCOUNT_ACTIVATION', 'Account Activation'),
        ('PHONE', 'Phone Verification'),
        ('OTP', 'One-Time Password'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='verifications')
    verification_type = models.CharField(max_length=20, choices=VERIFICATION_TYPES)
    token = models.CharField(max_length=100)
    code = models.CharField(max_length=6, blank=True, null=True)  # For numeric OTP codes
    is_verified = models.BooleanField(default=False)
    verified_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField()
    attempts = models.PositiveIntegerField(default=0)
    max_attempts = models.PositiveIntegerField(default=5)
    last_resend_attempt = models.DateTimeField(null=True, blank=True)  # For rate limiting
    
    class Meta:
        db_table = 'accounts_user_verification'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.user.get_full_name()} - {self.verification_type}"
    
    def is_expired(self):
        """Check if token is expired"""
        from django.utils import timezone
        return timezone.now() > self.expires_at
    
    def can_attempt(self):
        """Check if user can attempt verification"""
        return self.attempts < self.max_attempts
    
    def can_resend(self):
        """Check if user can resend verification email"""
        from django.utils import timezone
        if not self.last_resend_attempt:
            return True
        
        # Check if last attempt was more than 1 hour ago or attempts are less than 5
        one_hour_ago = timezone.now() - timezone.timedelta(hours=1)
        return self.last_resend_attempt < one_hour_ago or self.attempts < 5
    
    def verify(self):
        """Mark as verified"""
        from django.utils import timezone
        self.is_verified = True
        self.verified_at = timezone.now()
        self.save()


class UserPreference(BaseModel):
    """
    Model for user preferences
    """
    PREFERENCE_CATEGORIES = [
        ('NOTIFICATION', 'Notification Preferences'),
        ('DISPLAY', 'Display Preferences'),
        ('PRIVACY', 'Privacy Preferences'),
        ('ACCESSIBILITY', 'Accessibility Preferences'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='preferences')
    category = models.CharField(max_length=20, choices=PREFERENCE_CATEGORIES)
    key = models.CharField(max_length=50)
    value = models.JSONField()
    
    class Meta:
        db_table = 'accounts_user_preference'
        unique_together = ['user', 'category', 'key']
    
    def __str__(self):
        return f"{self.user.get_full_name()} - {self.key}"


class UserLibraryAccess(BaseModel):
    """
    Model to track user access to libraries
    """
    ACCESS_TYPES = [
        ('STANDARD', 'Standard Access'),
        ('EXTENDED', 'Extended Access'),
        ('PREMIUM', 'Premium Access'),
        ('RESTRICTED', 'Restricted Access'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='library_access')
    library = models.ForeignKey('library.Library', on_delete=models.CASCADE, related_name='user_access')
    access_type = models.CharField(max_length=15, choices=ACCESS_TYPES, default='STANDARD')
    is_active = models.BooleanField(default=True)
    granted_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='granted_access')
    granted_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    notes = models.TextField(blank=True)  # Added field for application notes
    
    class Meta:
        db_table = 'accounts_user_library_access'
        unique_together = ['user', 'library']
    
    def __str__(self):
        return f"{self.user.get_full_name()} - {self.library.name}"
    
    @property
    def is_expired(self):
        """Check if access is expired"""
        if not self.expires_at:
            return False
        from django.utils import timezone
        return timezone.now() > self.expires_at


class AdminProfile(BaseModel):
    """
    Extended profile for admin users
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='admin_profile')
    managed_library = models.ForeignKey('library.Library', on_delete=models.SET_NULL, null=True, blank=True, related_name='admins')
    permissions = models.JSONField(default=dict, blank=True)
    
    # Specific permissions
    can_manage_events = models.BooleanField(default=False)
    can_manage_books = models.BooleanField(default=False)
    can_view_analytics = models.BooleanField(default=False)
    
    class Meta:
        db_table = 'accounts_admin_profile'
    
    def __str__(self):
        return f"Admin Profile for {self.user.get_full_name()}"