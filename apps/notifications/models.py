"""
Models for notifications app
"""
from django.db import models
from django.contrib.auth import get_user_model
from apps.core.models import TimeStampedModel

User = get_user_model()


class Notification(TimeStampedModel):
    """
    Model for user notifications
    """
    NOTIFICATION_TYPES = [
        ('SUCCESS', 'Success'),
        ('INFO', 'Information'),
        ('WARNING', 'Warning'),
        ('ERROR', 'Error'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    title = models.CharField(max_length=200)
    message = models.TextField()
    type = models.CharField(max_length=10, choices=NOTIFICATION_TYPES, default='INFO')
    is_read = models.BooleanField(default=False)
    action_url = models.CharField(max_length=255, blank=True, null=True)
    metadata = models.JSONField(default=dict, blank=True)
    
    class Meta:
        db_table = 'notifications_notification'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['user', 'is_read']),
        ]
    
    def __str__(self):
        return f"{self.user.username} - {self.title} ({self.created_at})"
    
    @classmethod
    def create_notification(cls, user, title, message, notification_type='INFO', action_url=None, metadata=None):
        """
        Create a new notification for a user
        """
        return cls.objects.create(
            user=user,
            title=title,
            message=message,
            type=notification_type,
            action_url=action_url,
            metadata=metadata or {}
        )