"""
Celery tasks for notifications app
"""
from celery import shared_task
from django.utils import timezone
from datetime import timedelta
import logging
from .models import Notification
from apps.seats.models import SeatBooking
from apps.books.models import BookReservation

logger = logging.getLogger(__name__)


@shared_task
def send_booking_reminders():
    """Send reminders for upcoming seat bookings"""
    try:
        from apps.core.utils import send_notification_email
        
        now = timezone.now()
        reminder_times = [
            now + timedelta(hours=24),  # 24 hours before
            now + timedelta(hours=2),   # 2 hours before
        ]
        
        reminders_sent = 0
        
        for reminder_time in reminder_times:
            # Find bookings that need reminders
            bookings = SeatBooking.objects.filter(
                status='CONFIRMED',
                reminder_sent=False,
                booking_date=reminder_time.date(),
                start_time__hour=reminder_time.hour,
                is_deleted=False
            ).select_related('user', 'seat', 'seat__library')
            
            for booking in bookings:
                try:
                    # Create notification
                    Notification.create_notification(
                        user=booking.user,
                        title='Upcoming Seat Booking Reminder',
                        message=f'Your seat booking for {booking.seat.seat_number} at {booking.seat.library.name} is scheduled for {booking.booking_date} at {booking.start_time}.',
                        notification_type='INFO',
                        action_url='/my-bookings',
                        metadata={
                            'booking_id': str(booking.id),
                            'seat_id': str(booking.seat.id),
                            'status': booking.status
                        }
                    )
                    
                    # Send email
                    subject = f"Smart Lib - Booking Reminder"
                    message = f"""
                    Dear {booking.user.get_full_name()},
                    
                    This is a reminder for your upcoming seat booking:
                    
                    Library: {booking.seat.library.name}
                    Seat: {booking.seat.seat_number}
                    Date: {booking.booking_date}
                    Time: {booking.start_time} - {booking.end_time}
                    
                    Please arrive on time to avoid cancellation.
                    
                    Best regards,
                    Smart Lib Team
                    """
                    
                    send_notification_email(
                        to_email=booking.user.email,
                        subject=subject,
                        message=message
                    )
                    
                    booking.reminder_sent = True
                    booking.save()
                    reminders_sent += 1
                    
                except Exception as e:
                    logger.error(f"Error sending reminder for booking {booking.id}: {e}")
                    continue
        
        logger.info(f"Sent {reminders_sent} booking reminders")
        return f"Sent {reminders_sent} reminders"
        
    except Exception as e:
        logger.error(f"Error sending booking reminders: {e}")
        return f"Error: {e}"


@shared_task
def send_due_date_reminders():
    """Send reminders for books due soon"""
    try:
        from apps.core.utils import send_notification_email
        
        now = timezone.now()
        due_soon = now + timedelta(days=2)  # Books due in 2 days
        
        # Find reservations with books due soon
        reservations = BookReservation.objects.filter(
            status='CHECKED_OUT',
            due_date__date=due_soon.date(),
            is_deleted=False
        ).select_related('user', 'book')
        
        reminders_sent = 0
        
        for reservation in reservations:
            try:
                # Create notification
                Notification.create_notification(
                    user=reservation.user,
                    title='Book Due Soon',
                    message=f'Your book "{reservation.book.title}" is due in 2 days. Please return it on time to avoid late fees.',
                    notification_type='WARNING',
                    action_url='/my-reservations',
                    metadata={
                        'reservation_id': str(reservation.id),
                        'book_id': str(reservation.book.id),
                        'status': reservation.status
                    }
                )
                
                # Send email
                subject = f"Smart Lib - Book Due Soon"
                message = f"""
                Dear {reservation.user.get_full_name()},
                
                Your book is due for return soon:
                
                Book: {reservation.book.title}
                Due Date: {reservation.due_date.strftime('%Y-%m-%d')}
                
                Please return the book on time to avoid late fees.
                You can renew the book if eligible.
                
                Best regards,
                Smart Lib Team
                """
                
                send_notification_email(
                    to_email=reservation.user.email,
                    subject=subject,
                    message=message
                )
                
                reminders_sent += 1
                
            except Exception as e:
                logger.error(f"Error sending due date reminder for reservation {reservation.id}: {e}")
                continue
        
        logger.info(f"Sent {reminders_sent} due date reminders")
        return f"Sent {reminders_sent} due date reminders"
        
    except Exception as e:
        logger.error(f"Error sending due date reminders: {e}")
        return f"Error: {e}"


@shared_task
def clean_old_notifications():
    """Delete old read notifications"""
    try:
        # Delete read notifications older than 30 days
        cutoff_date = timezone.now() - timedelta(days=30)
        old_notifications = Notification.objects.filter(
            is_read=True,
            created_at__lt=cutoff_date
        )
        
        count = old_notifications.count()
        old_notifications.delete()
        
        logger.info(f"Deleted {count} old notifications")
        return f"Deleted {count} old notifications"
        
    except Exception as e:
        logger.error(f"Error cleaning old notifications: {e}")
        return f"Error: {e}"