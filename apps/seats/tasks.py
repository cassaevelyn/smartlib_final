"""
Celery tasks for seats app
"""
from celery import shared_task
from django.utils import timezone
from django.db.models import Count, Avg, Sum
from datetime import timedelta, date
from .models import Seat, SeatBooking, SeatUsageStatistics
import logging

logger = logging.getLogger(__name__)


@shared_task
def process_expired_bookings():
    """Process expired bookings and mark as no-show"""
    try:
        now = timezone.now()
        
        # Find bookings that should be auto-cancelled
        expired_bookings = SeatBooking.objects.filter(
            status='CONFIRMED',
            auto_cancel_at__lt=now,
            is_deleted=False
        )
        
        no_show_count = 0
        for booking in expired_bookings:
            # Mark as no-show
            booking.status = 'NO_SHOW'
            
            # Apply penalty points
            library_config = booking.seat.library.configuration
            penalty_points = library_config.no_show_penalty_points
            booking.penalty_points = penalty_points
            
            # Deduct points from user profile
            if hasattr(booking.user, 'profile'):
                booking.user.profile.loyalty_points = max(
                    0, booking.user.profile.loyalty_points - penalty_points
                )
                booking.user.profile.save()
            
            # Make seat available
            booking.seat.status = 'AVAILABLE'
            booking.seat.save()
            
            booking.save()
            no_show_count += 1
            
            # Log activity
            from apps.core.models import ActivityLog
            ActivityLog.objects.create(
                user=booking.user,
                activity_type='SEAT_BOOKING',
                description=f'Booking marked as no-show for seat {booking.seat.seat_number}',
                metadata={
                    'booking_id': str(booking.id),
                    'seat_code': booking.seat.seat_code,
                    'penalty_points': penalty_points,
                }
            )
        
        logger.info(f"Processed {no_show_count} expired bookings")
        return f"Processed {no_show_count} expired bookings"
        
    except Exception as e:
        logger.error(f"Error processing expired bookings: {e}")
        return f"Error: {e}"


@shared_task
def generate_daily_seat_statistics():
    """Generate daily statistics for all seats"""
    try:
        yesterday = timezone.now().date() - timedelta(days=1)
        seats_processed = 0
        
        for seat in Seat.objects.filter(is_deleted=False):
            try:
                # Check if statistics already exist for yesterday
                if SeatUsageStatistics.objects.filter(
                    seat=seat,
                    date=yesterday
                ).exists():
                    continue
                
                # Get bookings for yesterday
                bookings = SeatBooking.objects.filter(
                    seat=seat,
                    booking_date=yesterday,
                    is_deleted=False
                )
                
                # Calculate statistics
                total_bookings = bookings.count()
                successful_checkins = bookings.filter(
                    status__in=['CHECKED_IN', 'COMPLETED']
                ).count()
                no_shows = bookings.filter(status='NO_SHOW').count()
                cancellations = bookings.filter(status='CANCELLED').count()
                
                # Calculate time metrics
                total_booked_hours = sum([
                    booking.duration_hours for booking in bookings
                ])
                
                completed_bookings = bookings.filter(status='COMPLETED')
                total_used_hours = sum([
                    booking.actual_duration_hours for booking in completed_bookings
                    if booking.actual_duration_hours
                ])
                
                avg_session_duration = (
                    total_used_hours / completed_bookings.count()
                    if completed_bookings.count() > 0 else 0
                )
                
                # Calculate utilization rate (assuming 12 hours available per day)
                available_hours = 12  # This should come from library operating hours
                utilization_rate = (total_used_hours / available_hours * 100) if available_hours > 0 else 0
                
                # Get unique users
                unique_users = bookings.values('user').distinct().count()
                
                # Create statistics record
                SeatUsageStatistics.objects.create(
                    seat=seat,
                    date=yesterday,
                    total_bookings=total_bookings,
                    successful_checkins=successful_checkins,
                    no_shows=no_shows,
                    cancellations=cancellations,
                    total_booked_hours=total_booked_hours,
                    total_used_hours=total_used_hours,
                    average_session_duration=avg_session_duration,
                    utilization_rate=utilization_rate,
                    unique_users=unique_users,
                )
                
                seats_processed += 1
                
            except Exception as e:
                logger.error(f"Error generating statistics for seat {seat.seat_number}: {e}")
                continue
        
        logger.info(f"Generated daily statistics for {seats_processed} seats")
        return f"Processed {seats_processed} seats"
        
    except Exception as e:
        logger.error(f"Error in generate_daily_seat_statistics: {e}")
        return f"Error: {e}"


@shared_task
def send_booking_reminders():
    """Send reminders for upcoming bookings"""
    try:
        from apps.core.utils import send_notification_email
        
        now = timezone.now()
        reminder_times = [
            now + timedelta(hours=24),  # 24 hours before
            now + timedelta(hours=2),   # 2 hours before
            now + timedelta(minutes=30) # 30 minutes before
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
                    # Calculate hours until booking
                    booking_datetime = timezone.datetime.combine(
                        booking.booking_date, booking.start_time
                    )
                    hours_until = (booking_datetime - now).total_seconds() / 3600
                    
                    if 0 < hours_until <= 24:  # Send reminder if within 24 hours
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
                        
                        html_message = f"""
                        <h2>Booking Reminder</h2>
                        <p>Dear {booking.user.get_full_name()},</p>
                        <p>This is a reminder for your upcoming seat booking:</p>
                        <ul>
                            <li><strong>Library:</strong> {booking.seat.library.name}</li>
                            <li><strong>Seat:</strong> {booking.seat.seat_number}</li>
                            <li><strong>Date:</strong> {booking.booking_date}</li>
                            <li><strong>Time:</strong> {booking.start_time} - {booking.end_time}</li>
                        </ul>
                        <p>Please arrive on time to avoid cancellation.</p>
                        <p>Best regards,<br>Smart Lib Team</p>
                        """
                        
                        send_notification_email(
                            to_email=booking.user.email,
                            subject=subject,
                            message=message,
                            html_message=html_message
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
def cleanup_expired_qr_codes():
    """Clean up expired QR codes"""
    try:
        now = timezone.now()
        expired_bookings = SeatBooking.objects.filter(
            qr_code_expires_at__lt=now,
            qr_code_data__isnull=False,
            is_deleted=False
        )
        
        count = expired_bookings.count()
        expired_bookings.update(
            qr_code_data='',
            qr_code_expires_at=None,
            access_token=''
        )
        
        logger.info(f"Cleaned up {count} expired QR codes")
        return f"Cleaned up {count} expired QR codes"
        
    except Exception as e:
        logger.error(f"Error cleaning up expired QR codes: {e}")
        return f"Error: {e}"


@shared_task
def process_waitlist_notifications():
    """Process waitlist and notify users when seats become available"""
    try:
        from apps.core.utils import send_notification_email
        from .models import SeatBookingWaitlist
        
        today = timezone.now().date()
        notifications_sent = 0
        
        # Get active waitlist entries for today
        waitlist_entries = SeatBookingWaitlist.objects.filter(
            booking_date=today,
            is_active=True,
            notified_at__isnull=True,
            is_deleted=False
        ).select_related('user', 'seat').order_by('-priority_score', 'created_at')
        
        for entry in waitlist_entries:
            try:
                # Check if seat is now available for the requested time
                seat = entry.seat
                can_book, message = seat.can_user_book(
                    entry.user,
                    entry.preferred_start_time,
                    entry.preferred_end_time,
                    entry.booking_date
                )
                
                if can_book:
                    # Send notification
                    subject = "Smart Lib - Seat Available!"
                    message = f"""
                    Dear {entry.user.get_full_name()},
                    
                    Great news! The seat you were waiting for is now available:
                    
                    Seat: {seat.seat_number}
                    Library: {seat.library.name}
                    Date: {entry.booking_date}
                    Time: {entry.preferred_start_time} - {entry.preferred_end_time}
                    
                    Please book it soon as it may be taken by others.
                    
                    Best regards,
                    Smart Lib Team
                    """
                    
                    send_notification_email(
                        to_email=entry.user.email,
                        subject=subject,
                        message=message
                    )
                    
                    entry.notified_at = timezone.now()
                    entry.save()
                    notifications_sent += 1
                    
            except Exception as e:
                logger.error(f"Error processing waitlist entry {entry.id}: {e}")
                continue
        
        logger.info(f"Sent {notifications_sent} waitlist notifications")
        return f"Sent {notifications_sent} waitlist notifications"
        
    except Exception as e:
        logger.error(f"Error processing waitlist notifications: {e}")
        return f"Error: {e}"


@shared_task
def update_seat_maintenance_status():
    """Update seat status based on maintenance schedules"""
    try:
        from .models import SeatMaintenanceLog
        
        now = timezone.now()
        updated_seats = 0
        
        # Find scheduled maintenance that should start
        scheduled_maintenance = SeatMaintenanceLog.objects.filter(
            status='SCHEDULED',
            scheduled_date__lte=now,
            is_deleted=False
        )
        
        for maintenance in scheduled_maintenance:
            try:
                # Update maintenance status
                maintenance.status = 'IN_PROGRESS'
                maintenance.started_at = now
                maintenance.save()
                
                # Update seat status
                maintenance.seat.status = 'MAINTENANCE'
                maintenance.seat.save()
                
                updated_seats += 1
                
            except Exception as e:
                logger.error(f"Error updating maintenance {maintenance.id}: {e}")
                continue
        
        logger.info(f"Updated {updated_seats} seats for maintenance")
        return f"Updated {updated_seats} seats for maintenance"
        
    except Exception as e:
        logger.error(f"Error updating seat maintenance status: {e}")
        return f"Error: {e}"