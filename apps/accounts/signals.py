"""
Signals for accounts app
"""
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.contrib.auth.signals import user_logged_in, user_logged_out
from apps.core.models import ActivityLog
from apps.core.utils import get_user_ip
from .models import User, UserProfile, AdminProfile, UserLibraryAccess


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """Create user profile when user is created"""
    if created:
        UserProfile.objects.get_or_create(user=instance)
        
        # Create admin profile for admin users
        if instance.role in ['ADMIN', 'SUPER_ADMIN']:
            AdminProfile.objects.get_or_create(user=instance)


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    """Save user profile when user is saved"""
    if hasattr(instance, 'profile'):
        instance.profile.save()


@receiver(user_logged_in)
def log_user_login(sender, request, user, **kwargs):
    """Log user login activity"""
    ActivityLog.objects.create(
        user=user,
        activity_type='LOGIN',
        description=f'User logged in from {get_user_ip(request)}',
        ip_address=get_user_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', ''),
        metadata={
            'login_method': 'web',
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
        }
    )


@receiver(user_logged_out)
def log_user_logout(sender, request, user, **kwargs):
    """Log user logout activity"""
    if user:
        ActivityLog.objects.create(
            user=user,
            activity_type='LOGOUT',
            description=f'User logged out from {get_user_ip(request)}',
            ip_address=get_user_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            metadata={
                'logout_method': 'web',
            }
        )


@receiver(post_save, sender=UserLibraryAccess)
def handle_library_access_changes(sender, instance, created, **kwargs):
    """Handle library access changes and notifications"""
    user = instance.user
    
    # Log activity if this is a new approval
    if created and instance.is_active:
        ActivityLog.objects.create(
            user=user,
            activity_type='PROFILE_UPDATE',
            description=f'Granted access to library: {instance.library.name}',
            metadata={
                'library_id': str(instance.library.id),
                'library_name': instance.library.name,
                'granted_by': instance.granted_by.full_name if instance.granted_by else 'System',
            }
        )

    # Notify admins about new library access applications
    if created and not instance.is_active:
        try:
            # Import here to avoid circular imports
            from apps.notifications.models import Notification
            
            # Get the library associated with the application
            library = instance.library
            
            # Find all admins for this library
            admin_users = User.objects.filter(
                models.Q(role='SUPER_ADMIN') | 
                models.Q(
                    role='ADMIN',
                    admin_profile__managed_library=library
                )
            )
            
            # Notify each admin
            for admin in admin_users:
                Notification.objects.create(
                    user=admin,
                    title='New Library Access Application',
                    message=f'{user.full_name} has applied for access to {library.name}',
                    notification_type='APPLICATION',
                    action_url=f'/admin/accounts/userlibraryaccess/{instance.id}/change/',
                    metadata={
                        'user_id': str(user.id),
                        'user_name': user.full_name,
                        'library_id': str(library.id),
                        'library_name': library.name,
                        'application_id': str(instance.id)
                    }
                )
            
            # Log the application activity
            ActivityLog.objects.create(
                user=user,
                activity_type='PROFILE_UPDATE',
                description=f'Applied for access to library: {library.name}',
                metadata={
                    'library_id': str(library.id),
                    'library_name': library.name,
                    'application_id': str(instance.id)
                }
            )
        except Exception as e:
            # Log the error but don't break the signal
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Error notifying admins about library access application: {e}")