"""
Celery tasks for events app
"""
from celery import shared_task
from django.utils import timezone
from django.db.models import Count, Avg, Sum
from datetime import timedelta, date
from .models import Event, EventRegistration, EventStatistics, EventNotification
import logging

logger = logging.getLogger(__name__)


@shared_task
def process_event_reminders():
    """Send event reminders to registered users"""
    try:
        from apps.core.utils import send_notification_email
        
        now = timezone.now()
        reminders_sent = 0
        
        # Find events that need reminders
        upcoming_events = Event.objects.filter(
            status__in=['REGISTRATION_OPEN', 'REGISTRATION_CLOSED'],
            send_reminders=True,
            is_deleted=False
        )
        
        for event in upcoming_events:
            event_start = timezone.datetime.combine(event.start_date, event.start_time)
            
            # Check each reminder hour
            for reminder_hours in event.reminder_hours:
                reminder_time = event_start - timedelta(hours=reminder_hours)
                
                # Send reminder if it's time (within 30 minutes window)
                if abs((now - reminder_time).total_seconds()) <= 1800:  # 30 minutes
                    registrations = EventRegistration.objects.filter(
                        event=event,
                        status__in=['CONFIRMED', 'ATTENDED'],
                        reminder_sent=False,
                        is_deleted=False
                    ).select_related('user')
                    
                    for registration in registrations:
                        try:
                            subject = f"Smart Lib - Event Reminder: {event.title}"
                            message = f"""
                            Dear {registration.user.get_full_name()},
                            
                            This is a reminder for your upcoming event:
                            
                            Event: {event.title}
                            Date: {event.start_date}
                            Time: {event.start_time} - {event.end_time}
                            Location: {event.library.name}
                            {f"Venue: {event.venue_details}" if event.venue_details else ""}
                            {f"Online Link: {event.online_meeting_link}" if event.is_online else ""}
                            
                            Please arrive on time. Don't forget to bring any required materials.
                            
                            Best regards,
                            Smart Lib Team
                            """
                            
                            html_message = f"""
                            <h2>Event Reminder</h2>
                            <p>Dear {registration.user.get_full_name()},</p>
                            <p>This is a reminder for your upcoming event:</p>
                            <div style="background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0;">
                                <h3>{event.title}</h3>
                                <p><strong>Date:</strong> {event.start_date}</p>
                                <p><strong>Time:</strong> {event.start_time} - {event.end_time}</p>
                                <p><strong>Location:</strong> {event.library.name}</p>
                                {f"<p><strong>Venue:</strong> {event.venue_details}</p>" if event.venue_details else ""}
                                {f"<p><strong>Online Link:</strong> <a href='{event.online_meeting_link}'>Join Meeting</a></p>" if event.is_online else ""}
                            </div>
                            <p>Please arrive on time. Don't forget to bring any required materials.</p>
                            <p>Best regards,<br>Smart Lib Team</p>
                            """
                            
                            send_notification_email(
                                to_email=registration.user.email,
                                subject=subject,
                                message=message,
                                html_message=html_message
                            )
                            
                            registration.reminder_sent = True
                            registration.save()
                            reminders_sent += 1
                            
                        except Exception as e:
                            logger.error(f"Error sending reminder for registration {registration.id}: {e}")
                            continue
        
        logger.info(f"Sent {reminders_sent} event reminders")
        return f"Sent {reminders_sent} reminders"
        
    except Exception as e:
        logger.error(f"Error sending event reminders: {e}")
        return f"Error: {e}"


@shared_task
def process_no_shows():
    """Mark registrations as no-show for events that have started"""
    try:
        now = timezone.now()
        no_shows_processed = 0
        
        # Find events that started more than 30 minutes ago
        cutoff_time = now - timedelta(minutes=30)
        
        events_started = Event.objects.filter(
            status__in=['IN_PROGRESS', 'COMPLETED'],
            is_deleted=False
        )
        
        for event in events_started:
            event_start = timezone.datetime.combine(event.start_date, event.start_time)
            
            if event_start <= cutoff_time:
                # Mark confirmed registrations as no-show
                no_shows = EventRegistration.objects.filter(
                    event=event,
                    status='CONFIRMED',
                    is_deleted=False
                )
                
                for registration in no_shows:
                    registration.status = 'NO_SHOW'
                    registration.save()
                    no_shows_processed += 1
                    
                    # Log activity
                    from apps.core.models import ActivityLog
                    ActivityLog.objects.create(
                        user=registration.user,
                        activity_type='EVENT_REGISTER',
                        description=f'Marked as no-show for event: {event.title}',
                        metadata={
                            'registration_id': str(registration.id),
                            'event_id': str(event.id),
                            'event_title': event.title,
                        }
                    )
        
        logger.info(f"Processed {no_shows_processed} no-shows")
        return f"Processed {no_shows_processed} no-shows"
        
    except Exception as e:
        logger.error(f"Error processing no-shows: {e}")
        return f"Error: {e}"


@shared_task
def update_event_status():
    """Update event status based on current time"""
    try:
        now = timezone.now()
        updated_count = 0
        
        # Mark events as in progress
        events_to_start = Event.objects.filter(
            status='REGISTRATION_CLOSED',
            start_date=now.date(),
            start_time__lte=now.time(),
            is_deleted=False
        )
        
        for event in events_to_start:
            event.status = 'IN_PROGRESS'
            event.save()
            updated_count += 1
        
        # Mark events as completed
        events_to_complete = Event.objects.filter(
            status='IN_PROGRESS',
            end_date__lt=now.date(),
            is_deleted=False
        )
        
        for event in events_to_complete:
            event.status = 'COMPLETED'
            event.save()
            updated_count += 1
        
        # Close registration for events reaching deadline
        events_to_close = Event.objects.filter(
            status='REGISTRATION_OPEN',
            registration_deadline__lt=now,
            is_deleted=False
        )
        
        for event in events_to_close:
            event.status = 'REGISTRATION_CLOSED'
            event.save()
            updated_count += 1
        
        logger.info(f"Updated status for {updated_count} events")
        return f"Updated {updated_count} events"
        
    except Exception as e:
        logger.error(f"Error updating event status: {e}")
        return f"Error: {e}"


@shared_task
def generate_daily_event_statistics():
    """Generate daily statistics for all events"""
    try:
        yesterday = timezone.now().date() - timedelta(days=1)
        events_processed = 0
        
        for event in Event.objects.filter(is_deleted=False):
            try:
                # Check if statistics already exist for yesterday
                if EventStatistics.objects.filter(
                    event=event,
                    date=yesterday
                ).exists():
                    continue
                
                # Get registrations for yesterday
                registrations = EventRegistration.objects.filter(
                    event=event,
                    registration_date__date=yesterday,
                    is_deleted=False
                )
                
                # Calculate statistics
                new_registrations = registrations.count()
                total_registrations = EventRegistration.objects.filter(
                    event=event,
                    registration_date__date__lte=yesterday,
                    is_deleted=False
                ).count()
                
                cancellations = EventRegistration.objects.filter(
                    event=event,
                    status='CANCELLED',
                    updated_at__date=yesterday,
                    is_deleted=False
                ).count()
                
                attendees = EventRegistration.objects.filter(
                    event=event,
                    status='ATTENDED',
                    check_in_time__date=yesterday,
                    is_deleted=False
                ).count()
                
                no_shows = EventRegistration.objects.filter(
                    event=event,
                    status='NO_SHOW',
                    updated_at__date=yesterday,
                    is_deleted=False
                ).count()
                
                # Calculate attendance rate
                total_expected = attendees + no_shows
                attendance_rate = (attendees / total_expected * 100) if total_expected > 0 else 0
                
                # Calculate average attendance duration
                attended_registrations = EventRegistration.objects.filter(
                    event=event,
                    status='ATTENDED',
                    attendance_duration__isnull=False,
                    check_in_time__date=yesterday,
                    is_deleted=False
                )
                
                avg_duration = None
                if attended_registrations.exists():
                    total_duration = sum([
                        reg.attendance_duration.total_seconds()
                        for reg in attended_registrations
                    ])
                    avg_duration = timedelta(seconds=total_duration / attended_registrations.count())
                
                # Get feedback submissions for the day
                feedback_submissions = event.feedback.filter(
                    created_at__date=yesterday,
                    is_deleted=False
                ).count()
                
                # Calculate average rating for the day
                daily_feedback = event.feedback.filter(
                    created_at__date=yesterday,
                    is_deleted=False
                )
                avg_rating = daily_feedback.aggregate(
                    avg=Avg('overall_rating')
                )['avg'] or 0
                
                # Create statistics record
                EventStatistics.objects.create(
                    event=event,
                    date=yesterday,
                    new_registrations=new_registrations,
                    total_registrations=total_registrations,
                    cancellations=cancellations,
                    attendees=attendees,
                    no_shows=no_shows,
                    attendance_rate=attendance_rate,
                    average_attendance_duration=avg_duration,
                    feedback_submissions=feedback_submissions,
                    average_rating=avg_rating,
                    resource_downloads=0,  # This would be tracked separately
                )
                
                events_processed += 1
                
            except Exception as e:
                logger.error(f"Error generating statistics for event {event.title}: {e}")
                continue
        
        logger.info(f"Generated daily statistics for {events_processed} events")
        return f"Processed {events_processed} events"
        
    except Exception as e:
        logger.error(f"Error in generate_daily_event_statistics: {e}")
        return f"Error: {e}"


@shared_task
def send_event_notifications():
    """Send scheduled event notifications"""
    try:
        from apps.core.utils import send_notification_email
        
        now = timezone.now()
        notifications_sent = 0
        
        # Find notifications ready to be sent
        pending_notifications = EventNotification.objects.filter(
            is_sent=False,
            is_deleted=False
        ).filter(
            models.Q(send_immediately=True) |
            models.Q(scheduled_send_time__lte=now)
        )
        
        for notification in pending_notifications:
            try:
                # Get recipients based on targeting
                recipients = []
                
                if notification.send_to_all_registrants:
                    recipients.extend(
                        EventRegistration.objects.filter(
                            event=notification.event,
                            status__in=['CONFIRMED', 'ATTENDED'],
                            is_deleted=False
                        ).values_list('user__email', flat=True)
                    )
                
                if notification.send_to_attendees_only:
                    recipients.extend(
                        EventRegistration.objects.filter(
                            event=notification.event,
                            status='ATTENDED',
                            is_deleted=False
                        ).values_list('user__email', flat=True)
                    )
                
                if notification.send_to_waitlist:
                    recipients.extend(
                        notification.event.waitlist.filter(
                            is_deleted=False
                        ).values_list('user__email', flat=True)
                    )
                
                # Remove duplicates
                recipients = list(set(recipients))
                
                # Send notifications
                for email in recipients:
                    try:
                        send_notification_email(
                            to_email=email,
                            subject=notification.title,
                            message=notification.message
                        )
                        notifications_sent += 1
                    except Exception as e:
                        logger.error(f"Error sending notification to {email}: {e}")
                        continue
                
                # Mark as sent
                notification.is_sent = True
                notification.sent_at = now
                notification.recipients_count = len(recipients)
                notification.save()
                
            except Exception as e:
                logger.error(f"Error processing notification {notification.id}: {e}")
                continue
        
        logger.info(f"Sent {notifications_sent} event notifications")
        return f"Sent {notifications_sent} notifications"
        
    except Exception as e:
        logger.error(f"Error sending event notifications: {e}")
        return f"Error: {e}"


@shared_task
def process_waitlist():
    """Process event waitlist when spots become available"""
    try:
        from apps.core.utils import send_notification_email
        
        notifications_sent = 0
        
        # Find events with available spots and active waitlist
        events_with_waitlist = Event.objects.filter(
            status='REGISTRATION_OPEN',
            waitlist__isnull=False,
            is_deleted=False
        ).distinct()
        
        for event in events_with_waitlist:
            available_spots = event.available_spots
            
            if available_spots > 0:
                # Get waitlist entries in order
                waitlist_entries = event.waitlist.filter(
                    notified=False,
                    expires_at__gt=timezone.now(),
                    is_deleted=False
                ).order_by('position')[:available_spots]
                
                for entry in waitlist_entries:
                    try:
                        subject = f"Smart Lib - Spot Available: {event.title}"
                        message = f"""
                        Dear {entry.user.get_full_name()},
                        
                        Great news! A spot has become available for the event you're waitlisted for:
                        
                        Event: {event.title}
                        Date: {event.start_date}
                        Time: {event.start_time} - {event.end_time}
                        
                        You have 24 hours to register for this event. Please log in to your account to complete your registration.
                        
                        Best regards,
                        Smart Lib Team
                        """
                        
                        send_notification_email(
                            to_email=entry.user.email,
                            subject=subject,
                            message=message
                        )
                        
                        entry.notified = True
                        entry.notification_sent_at = timezone.now()
                        entry.save()
                        notifications_sent += 1
                        
                    except Exception as e:
                        logger.error(f"Error notifying waitlist entry {entry.id}: {e}")
                        continue
        
        logger.info(f"Sent {notifications_sent} waitlist notifications")
        return f"Sent {notifications_sent} waitlist notifications"
        
    except Exception as e:
        logger.error(f"Error processing waitlist: {e}")
        return f"Error: {e}"


@shared_task
def cleanup_expired_waitlist():
    """Clean up expired waitlist entries"""
    try:
        now = timezone.now()
        expired_entries = EventWaitlist.objects.filter(
            expires_at__lt=now,
            is_deleted=False
        )
        
        count = expired_entries.count()
        expired_entries.update(is_deleted=True)
        
        logger.info(f"Cleaned up {count} expired waitlist entries")
        return f"Cleaned up {count} expired waitlist entries"
        
    except Exception as e:
        logger.error(f"Error cleaning up expired waitlist: {e}")
        return f"Error: {e}"


@shared_task
def generate_event_certificates():
    """Generate certificates for completed events"""
    try:
        certificates_generated = 0
        
        # Find completed events with certificates enabled
        completed_events = Event.objects.filter(
            status='COMPLETED',
            has_certificate=True,
            is_deleted=False
        )
        
        for event in completed_events:
            # Find attended registrations without certificates
            registrations = EventRegistration.objects.filter(
                event=event,
                status='ATTENDED',
                certificate_issued=False,
                is_deleted=False
            )
            
            for registration in registrations:
                try:
                    # Generate certificate (this would integrate with a certificate generation service)
                    # For now, just mark as issued
                    registration.certificate_issued = True
                    registration.save()
                    certificates_generated += 1
                    
                    # Send notification
                    from apps.core.utils import send_notification_email
                    
                    subject = f"Smart Lib - Certificate Available: {event.title}"
                    message = f"""
                    Dear {registration.user.get_full_name()},
                    
                    Congratulations! Your certificate for attending "{event.title}" is now available.
                    
                    You can download your certificate from your account dashboard.
                    
                    Best regards,
                    Smart Lib Team
                    """
                    
                    send_notification_email(
                        to_email=registration.user.email,
                        subject=subject,
                        message=message
                    )
                    
                except Exception as e:
                    logger.error(f"Error generating certificate for registration {registration.id}: {e}")
                    continue
        
        logger.info(f"Generated {certificates_generated} certificates")
        return f"Generated {certificates_generated} certificates"
        
    except Exception as e:
        logger.error(f"Error generating certificates: {e}")
        return f"Error: {e}"