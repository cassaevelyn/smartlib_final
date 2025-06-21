"""
Core models that provide base functionality for other apps
"""
from django.db import models
import uuid


class TimeStampedModel(models.Model):
    """
    Abstract base model that provides self-updating created and modified fields
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        abstract = True


class SoftDeleteModel(models.Model):
    """
    Abstract base model that provides soft delete functionality
    """
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        abstract = True
        
    def soft_delete(self):
        """Soft delete the object"""
        from django.utils import timezone
        self.is_deleted = True
        self.deleted_at = timezone.now()
        self.save()
        
    def restore(self):
        """Restore the soft deleted object"""
        self.is_deleted = False
        self.deleted_at = None
        self.save()


class AuditModel(models.Model):
    """
    Abstract base model that provides audit trail functionality
    """
    created_by = models.ForeignKey(
        'accounts.User', 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='%(class)s_created'
    )
    updated_by = models.ForeignKey(
        'accounts.User', 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='%(class)s_updated'
    )
    
    class Meta:
        abstract = True


class BaseModel(TimeStampedModel, SoftDeleteModel, AuditModel):
    """
    Base model that combines all common functionality
    """
    class Meta:
        abstract = True


class ActivityLog(TimeStampedModel):
    """
    Model to track user activities across the system
    """
    ACTIVITY_TYPES = [
        ('LOGIN', 'User Login'),
        ('LOGOUT', 'User Logout'),
        ('SEAT_BOOK', 'Seat Booking'),
        ('SEAT_CHECKIN', 'Seat Check-in'),
        ('SEAT_CHECKOUT', 'Seat Check-out'),
        ('BOOK_RESERVE', 'Book Reservation'),
        ('BOOK_PICKUP', 'Book Pickup'),
        ('BOOK_RETURN', 'Book Return'),
        ('EVENT_REGISTER', 'Event Registration'),
        ('EVENT_ATTEND', 'Event Attendance'),
        ('SUBSCRIPTION_PURCHASE', 'Subscription Purchase'),
        ('PROFILE_UPDATE', 'Profile Update'),
        ('PASSWORD_CHANGE', 'Password Change'),
    ]
    
    user = models.ForeignKey('accounts.User', on_delete=models.CASCADE, related_name='activity_logs')
    activity_type = models.CharField(max_length=25, choices=ACTIVITY_TYPES)
    description = models.TextField()
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['activity_type', '-created_at']),
        ]
    
    def __str__(self):
        return f"{self.user.username} - {self.get_activity_type_display()} at {self.created_at}"


class SystemConfiguration(TimeStampedModel):
    """
    Model to store system-wide configuration settings
    """
    key = models.CharField(max_length=100, unique=True)
    value = models.TextField()
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        ordering = ['key']
    
    def __str__(self):
        return f"{self.key}: {self.value[:50]}"


class FileUpload(TimeStampedModel):
    """
    Model to handle file uploads with metadata
    """
    FILE_TYPES = [
        ('IMAGE', 'Image'),
        ('DOCUMENT', 'Document'),
        ('BOOK_COVER', 'Book Cover'),
        ('EVENT_BANNER', 'Event Banner'),
        ('LIBRARY_IMAGE', 'Library Image'),
        ('USER_AVATAR', 'User Avatar'),
    ]
    
    file = models.FileField(upload_to='uploads/%Y/%m/%d/')
    original_name = models.CharField(max_length=255)
    file_type = models.CharField(max_length=20, choices=FILE_TYPES)
    file_size = models.PositiveIntegerField()  # Size in bytes
    mime_type = models.CharField(max_length=100)
    uploaded_by = models.ForeignKey('accounts.User', on_delete=models.CASCADE, related_name='uploaded_files')
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.original_name} ({self.get_file_type_display()})"
    
    @property
    def file_size_mb(self):
        """Return file size in MB"""
        return round(self.file_size / (1024 * 1024), 2)