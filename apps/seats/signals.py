"""
Signals for seats app
"""
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.db.models import Avg
from apps.core.models import ActivityLog
from .models import Seat, SeatBooking, SeatReview


@receiver(post_save, sender=SeatBooking)
def update_seat_statistics(sender, instance, created, **kwargs):
    """Update seat statistics when booking is created or updated"""
    if created:
        # Increment total bookings
        instance.seat.total_bookings += 1
        instance.seat.save()
        
        # Log booking activity
        ActivityLog.objects.create(
            user=instance.user,
            activity_type='SEAT_BOOK',
            description=f'Booked seat {instance.seat.seat_number} for {instance.booking_date}',
            metadata={
                'booking_id': str(instance.id),
                'seat_code': instance.seat.seat_code,
                'booking_date': instance.booking_date.isoformat(),
                'start_time': instance.start_time.isoformat(),
                'end_time': instance.end_time.isoformat(),
            }
        )
    
    # Update seat usage hours when booking is completed
    if instance.status == 'COMPLETED' and instance.actual_duration_hours > 0:
        instance.seat.total_usage_hours += instance.actual_duration_hours
        instance.seat.save()


@receiver(post_save, sender=SeatReview)
def update_seat_rating(sender, instance, created, **kwargs):
    """Update seat average rating when review is created or updated"""
    if instance.is_approved:
        seat = instance.seat
        
        # Calculate new average rating
        avg_rating = SeatReview.objects.filter(
            seat=seat,
            is_approved=True,
            is_deleted=False
        ).aggregate(avg_rating=Avg('overall_rating'))['avg_rating']
        
        # Update seat
        seat.average_rating = round(avg_rating or 0, 2)
        seat.save()


@receiver(pre_save, sender=SeatBooking)
def track_booking_status_changes(sender, instance, **kwargs):
    """Track booking status changes"""
    if instance.pk:
        try:
            old_instance = SeatBooking.objects.get(pk=instance.pk)
            
            # Track status changes
            if old_instance.status != instance.status:
                ActivityLog.objects.create(
                    user=instance.user,
                    activity_type='SEAT_BOOKING',
                    description=f'Booking status changed from {old_instance.status} to {instance.status}',
                    metadata={
                        'booking_id': str(instance.id),
                        'seat_code': instance.seat.seat_code,
                        'old_status': old_instance.status,
                        'new_status': instance.status,
                    }
                )
                
                # Update seat status based on booking status
                if instance.status == 'CHECKED_IN':
                    instance.seat.status = 'OCCUPIED'
                    instance.seat.save()
                elif old_instance.status == 'CHECKED_IN' and instance.status in ['COMPLETED', 'CANCELLED']:
                    instance.seat.status = 'AVAILABLE'
                    instance.seat.save()
                    
        except SeatBooking.DoesNotExist:
            pass