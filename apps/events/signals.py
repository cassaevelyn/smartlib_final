"""
Signals for events app
"""
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.db.models import Avg
from apps.core.models import ActivityLog
from .models import Event, EventRegistration, EventFeedback


@receiver(post_save, sender=EventRegistration)
def update_event_statistics(sender, instance, created, **kwargs):
    """Update event statistics when registration is created or updated"""
    if created:
        # Log registration activity
        ActivityLog.objects.create(
            user=instance.user,
            activity_type='EVENT_REGISTER',
            description=f'Registered for event: {instance.event.title}',
            metadata={
                'registration_id': str(instance.id),
                'event_id': str(instance.event.id),
                'event_title': instance.event.title,
                'registration_fee': float(instance.registration_fee_paid),
            }
        )


@receiver(post_save, sender=EventFeedback)
def update_event_rating(sender, instance, created, **kwargs):
    """Update event average rating when feedback is created or updated"""
    event = instance.event
    
    # Calculate new average rating
    avg_rating = EventFeedback.objects.filter(
        event=event,
        is_deleted=False
    ).aggregate(avg_rating=Avg('overall_rating'))['avg_rating']
    
    # Count total feedback
    total_feedback = EventFeedback.objects.filter(
        event=event,
        is_deleted=False
    ).count()
    
    # Update event
    event.average_rating = round(avg_rating or 0, 2)
    event.total_feedback = total_feedback
    event.save()
    
    # Update speaker ratings
    for speaker in event.speakers.all():
        speaker_avg = EventFeedback.objects.filter(
            event__speakers=speaker,
            is_deleted=False
        ).aggregate(avg_rating=Avg('speaker_rating'))['avg_rating']
        
        if speaker_avg:
            speaker.average_rating = round(speaker_avg, 2)
            speaker.save()


@receiver(pre_save, sender=EventRegistration)
def track_registration_status_changes(sender, instance, **kwargs):
    """Track registration status changes"""
    if instance.pk:
        try:
            old_instance = EventRegistration.objects.get(pk=instance.pk)
            
            # Track status changes
            if old_instance.status != instance.status:
                ActivityLog.objects.create(
                    user=instance.user,
                    activity_type='EVENT_REGISTER',
                    description=f'Registration status changed from {old_instance.status} to {instance.status}',
                    metadata={
                        'registration_id': str(instance.id),
                        'event_id': str(instance.event.id),
                        'event_title': instance.event.title,
                        'old_status': old_instance.status,
                        'new_status': instance.status,
                    }
                )
                
                # Handle specific status changes
                if instance.status == 'ATTENDED' and old_instance.status == 'CONFIRMED':
                    # User checked in - award loyalty points
                    if hasattr(instance.user, 'profile'):
                        points = 25  # Points for event attendance
                        instance.user.profile.add_loyalty_points(
                            points, f'Event attendance: {instance.event.title}'
                        )
                        
        except EventRegistration.DoesNotExist:
            pass


@receiver(post_save, sender=Event)
def update_speaker_statistics(sender, instance, **kwargs):
    """Update speaker statistics when event is saved"""
    if not kwargs.get('created', False):  # Only for updates, not creation
        for speaker in instance.speakers.all():
            # Count total events for speaker
            total_events = Event.objects.filter(
                speakers=speaker,
                status='COMPLETED',
                is_deleted=False
            ).count()
            
            speaker.total_events = total_events
            speaker.save()