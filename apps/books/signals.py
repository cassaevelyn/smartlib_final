"""
Signals for books app
"""
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.db.models import Avg
from apps.core.models import ActivityLog
from .models import Book, BookReservation, BookReview


@receiver(post_save, sender=BookReservation)
def update_book_statistics(sender, instance, created, **kwargs):
    """Update book statistics when reservation is created or updated"""
    if created:
        # Increment total reservations
        instance.book.total_reservations += 1
        
        # Update available copies for physical books
        if instance.reservation_type == 'PHYSICAL':
            instance.book.available_copies = max(0, instance.book.available_copies - 1)
        
        instance.book.save()
        
        # Log reservation activity
        ActivityLog.objects.create(
            user=instance.user,
            activity_type='BOOK_RESERVE',
            description=f'Reserved book: {instance.book.title}',
            metadata={
                'reservation_id': str(instance.id),
                'book_id': str(instance.book.id),
                'book_title': instance.book.title,
                'reservation_type': instance.reservation_type,
            }
        )
    
    # Update checkout count when status changes to CHECKED_OUT
    if instance.status == 'CHECKED_OUT':
        try:
            old_instance = BookReservation.objects.get(pk=instance.pk)
            if old_instance.status != 'CHECKED_OUT':
                instance.book.total_checkouts += 1
                instance.book.save()
        except BookReservation.DoesNotExist:
            pass


@receiver(post_save, sender=BookReview)
def update_book_rating(sender, instance, created, **kwargs):
    """Update book average rating when review is created or updated"""
    if instance.is_approved:
        book = instance.book
        
        # Calculate new average rating
        avg_rating = BookReview.objects.filter(
            book=book,
            is_approved=True,
            is_deleted=False
        ).aggregate(avg_rating=Avg('overall_rating'))['avg_rating']
        
        # Count total reviews
        total_reviews = BookReview.objects.filter(
            book=book,
            is_approved=True,
            is_deleted=False
        ).count()
        
        # Update book
        book.average_rating = round(avg_rating or 0, 2)
        book.total_reviews = total_reviews
        book.save()


@receiver(pre_save, sender=BookReservation)
def track_reservation_status_changes(sender, instance, **kwargs):
    """Track reservation status changes"""
    if instance.pk:
        try:
            old_instance = BookReservation.objects.get(pk=instance.pk)
            
            # Track status changes
            if old_instance.status != instance.status:
                ActivityLog.objects.create(
                    user=instance.user,
                    activity_type='BOOK_RESERVE',
                    description=f'Reservation status changed from {old_instance.status} to {instance.status}',
                    metadata={
                        'reservation_id': str(instance.id),
                        'book_id': str(instance.book.id),
                        'book_title': instance.book.title,
                        'old_status': old_instance.status,
                        'new_status': instance.status,
                    }
                )
                
                # Handle specific status changes
                if instance.status == 'RETURNED' and old_instance.status == 'CHECKED_OUT':
                    # Book returned - update availability
                    if instance.reservation_type == 'PHYSICAL':
                        instance.book.available_copies += 1
                        instance.book.save()
                        
                elif instance.status == 'CANCELLED':
                    # Reservation cancelled - update availability
                    if instance.reservation_type == 'PHYSICAL' and old_instance.status in ['CONFIRMED', 'READY_FOR_PICKUP']:
                        instance.book.available_copies += 1
                        instance.book.save()
                        
        except BookReservation.DoesNotExist:
            pass


@receiver(pre_save, sender=BookReview)
def log_review_approval(sender, instance, **kwargs):
    """Log when review gets approved"""
    if instance.pk:
        try:
            old_instance = BookReview.objects.get(pk=instance.pk)
            if not old_instance.is_approved and instance.is_approved:
                # Review was just approved
                ActivityLog.objects.create(
                    user=instance.user,
                    activity_type='PROFILE_UPDATE',
                    description=f'Book review approved for {instance.book.title}',
                    metadata={
                        'book_id': str(instance.book.id),
                        'book_title': instance.book.title,
                        'rating': instance.overall_rating,
                        'approved_by': instance.approved_by.get_full_name() if instance.approved_by else 'System',
                    }
                )
        except BookReview.DoesNotExist:
            pass