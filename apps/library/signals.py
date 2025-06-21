"""
Signals for library app
"""
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.db.models import Avg
from apps.core.models import ActivityLog
from .models import Library, LibraryReview, LibraryConfiguration


@receiver(post_save, sender=Library)
def create_library_configuration(sender, instance, created, **kwargs):
    """Create default configuration when library is created"""
    if created:
        LibraryConfiguration.objects.get_or_create(
            library=instance,
            defaults={
                'created_by': instance.created_by
            }
        )


@receiver(post_save, sender=LibraryReview)
def update_library_rating(sender, instance, created, **kwargs):
    """Update library average rating when review is created or updated"""
    if instance.is_approved:
        library = instance.library
        
        # Calculate new average rating
        avg_rating = LibraryReview.objects.filter(
            library=library,
            is_approved=True,
            is_deleted=False
        ).aggregate(avg_rating=Avg('rating'))['avg_rating']
        
        # Count total reviews
        total_reviews = LibraryReview.objects.filter(
            library=library,
            is_approved=True,
            is_deleted=False
        ).count()
        
        # Update library
        library.average_rating = round(avg_rating or 0, 2)
        library.total_reviews = total_reviews
        library.save()


@receiver(pre_save, sender=LibraryReview)
def log_review_approval(sender, instance, **kwargs):
    """Log when review gets approved"""
    if instance.pk:
        try:
            old_instance = LibraryReview.objects.get(pk=instance.pk)
            if not old_instance.is_approved and instance.is_approved:
                # Review was just approved
                ActivityLog.objects.create(
                    user=instance.user,
                    activity_type='PROFILE_UPDATE',
                    description=f'Library review approved for {instance.library.name}',
                    metadata={
                        'library_id': str(instance.library.id),
                        'library_name': instance.library.name,
                        'rating': instance.rating,
                        'approved_by': instance.approved_by.get_full_name() if instance.approved_by else 'System',
                    }
                )
        except LibraryReview.DoesNotExist:
            pass