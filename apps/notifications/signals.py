"""
Signals for notifications app
"""
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from apps.seats.models import SeatBooking
from apps.books.models import BookReservation
from apps.events.models import EventRegistration
from .models import Notification

User = get_user_model()


@receiver(post_save, sender=SeatBooking)
def create_seat_booking_notification(sender, instance, created, **kwargs):
    """Create notification when a seat booking is created or updated"""
    if created:
        # New booking notification
        Notification.create_notification(
            user=instance.user,
            title='Seat Booking Confirmed',
            message=f'Your booking for seat {instance.seat.seat_number} on {instance.booking_date} has been confirmed.',
            notification_type='SUCCESS',
            action_url='/my-bookings',
            metadata={
                'booking_id': str(instance.id),
                'seat_id': str(instance.seat.id),
                'status': instance.status
            }
        )
    elif instance.status == 'CHECKED_IN' and instance.checked_in_at:
        # Check-in notification
        Notification.create_notification(
            user=instance.user,
            title='Seat Check-in Successful',
            message=f'You have successfully checked in to seat {instance.seat.seat_number}.',
            notification_type='SUCCESS',
            action_url='/my-bookings',
            metadata={
                'booking_id': str(instance.id),
                'seat_id': str(instance.seat.id),
                'status': instance.status
            }
        )
    elif instance.status == 'COMPLETED' and instance.checked_out_at:
        # Check-out notification
        Notification.create_notification(
            user=instance.user,
            title='Seat Check-out Completed',
            message=f'You have successfully checked out from seat {instance.seat.seat_number}.',
            notification_type='INFO',
            action_url='/my-bookings',
            metadata={
                'booking_id': str(instance.id),
                'seat_id': str(instance.seat.id),
                'status': instance.status
            }
        )
    elif instance.status == 'CANCELLED':
        # Cancellation notification
        Notification.create_notification(
            user=instance.user,
            title='Seat Booking Cancelled',
            message=f'Your booking for seat {instance.seat.seat_number} on {instance.booking_date} has been cancelled.',
            notification_type='INFO',
            action_url='/my-bookings',
            metadata={
                'booking_id': str(instance.id),
                'seat_id': str(instance.seat.id),
                'status': instance.status
            }
        )
    elif instance.status == 'NO_SHOW':
        # No-show notification
        Notification.create_notification(
            user=instance.user,
            title='Booking Marked as No-Show',
            message=f'Your booking for seat {instance.seat.seat_number} on {instance.booking_date} was marked as no-show.',
            notification_type='WARNING',
            action_url='/my-bookings',
            metadata={
                'booking_id': str(instance.id),
                'seat_id': str(instance.seat.id),
                'status': instance.status
            }
        )


@receiver(post_save, sender=BookReservation)
def create_book_reservation_notification(sender, instance, created, **kwargs):
    """Create notification when a book reservation is created or updated"""
    if created:
        # New reservation notification
        Notification.create_notification(
            user=instance.user,
            title='Book Reservation Confirmed',
            message=f'Your reservation for "{instance.book.title}" has been confirmed.',
            notification_type='SUCCESS',
            action_url='/my-reservations',
            metadata={
                'reservation_id': str(instance.id),
                'book_id': str(instance.book.id),
                'status': instance.status
            }
        )
    elif instance.status == 'READY_FOR_PICKUP':
        # Ready for pickup notification
        Notification.create_notification(
            user=instance.user,
            title='Book Ready for Pickup',
            message=f'Your reserved book "{instance.book.title}" is ready for pickup.',
            notification_type='INFO',
            action_url='/my-reservations',
            metadata={
                'reservation_id': str(instance.id),
                'book_id': str(instance.book.id),
                'status': instance.status
            }
        )
    elif instance.status == 'OVERDUE':
        # Overdue notification
        Notification.create_notification(
            user=instance.user,
            title='Book Overdue',
            message=f'Your book "{instance.book.title}" is overdue. Please return it as soon as possible.',
            notification_type='WARNING',
            action_url='/my-reservations',
            metadata={
                'reservation_id': str(instance.id),
                'book_id': str(instance.book.id),
                'status': instance.status
            }
        )
    elif instance.status == 'RETURNED':
        # Return notification
        Notification.create_notification(
            user=instance.user,
            title='Book Returned',
            message=f'You have successfully returned "{instance.book.title}".',
            notification_type='SUCCESS',
            action_url='/my-reservations',
            metadata={
                'reservation_id': str(instance.id),
                'book_id': str(instance.book.id),
                'status': instance.status
            }
        )


@receiver(post_save, sender=EventRegistration)
def create_event_registration_notification(sender, instance, created, **kwargs):
    """Create notification when an event registration is created or updated"""
    if created:
        # New registration notification
        Notification.create_notification(
            user=instance.user,
            title='Event Registration Confirmed',
            message=f'Your registration for "{instance.event.title}" has been confirmed.',
            notification_type='SUCCESS',
            action_url='/my-events',
            metadata={
                'registration_id': str(instance.id),
                'event_id': str(instance.event.id),
                'status': instance.status
            }
        )
    elif instance.status == 'ATTENDED':
        # Attendance notification
        Notification.create_notification(
            user=instance.user,
            title='Event Attendance Recorded',
            message=f'Your attendance at "{instance.event.title}" has been recorded.',
            notification_type='SUCCESS',
            action_url='/my-events',
            metadata={
                'registration_id': str(instance.id),
                'event_id': str(instance.event.id),
                'status': instance.status
            }
        )
    elif instance.status == 'CANCELLED':
        # Cancellation notification
        Notification.create_notification(
            user=instance.user,
            title='Event Registration Cancelled',
            message=f'Your registration for "{instance.event.title}" has been cancelled.',
            notification_type='INFO',
            action_url='/my-events',
            metadata={
                'registration_id': str(instance.id),
                'event_id': str(instance.event.id),
                'status': instance.status
            }
        )
    elif instance.certificate_issued and instance.certificate_file:
        # Certificate notification
        Notification.create_notification(
            user=instance.user,
            title='Event Certificate Available',
            message=f'Your certificate for "{instance.event.title}" is now available.',
            notification_type='INFO',
            action_url='/my-events',
            metadata={
                'registration_id': str(instance.id),
                'event_id': str(instance.event.id),
                'status': instance.status
            }
        )