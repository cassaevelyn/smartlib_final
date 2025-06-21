"""
Celery tasks for books app
"""
from celery import shared_task
from django.utils import timezone
from django.db.models import Count, Avg, Sum
from datetime import timedelta, date
from .models import Book, BookReservation, BookStatistics, BookDigitalAccess
import logging

logger = logging.getLogger(__name__)


@shared_task
def process_expired_reservations():
    """Process expired book reservations"""
    try:
        now = timezone.now()
        
        # Find reservations that have expired pickup deadline
        expired_pickups = BookReservation.objects.filter(
            status='CONFIRMED',
            pickup_deadline__lt=now,
            is_deleted=False
        )
        
        expired_count = 0
        for reservation in expired_pickups:
            reservation.status = 'EXPIRED'
            
            # Update book availability
            if reservation.reservation_type == 'PHYSICAL':
                reservation.book.available_copies += 1
                reservation.book.save()
            
            reservation.save()
            expired_count += 1
            
            # Log activity
            from apps.core.models import ActivityLog
            ActivityLog.objects.create(
                user=reservation.user,
                activity_type='BOOK_RESERVE',
                description=f'Book reservation expired: {reservation.book.title}',
                metadata={
                    'reservation_id': str(reservation.id),
                    'book_title': reservation.book.title,
                    'reason': 'Pickup deadline exceeded',
                }
            )
        
        # Find overdue books
        overdue_books = BookReservation.objects.filter(
            status='CHECKED_OUT',
            due_date__lt=now,
            is_deleted=False
        )
        
        overdue_count = 0
        for reservation in overdue_books:
            if reservation.status != 'OVERDUE':
                reservation.status = 'OVERDUE'
                reservation.save()
                overdue_count += 1
        
        logger.info(f"Processed {expired_count} expired reservations and {overdue_count} overdue books")
        return f"Processed {expired_count} expired reservations and {overdue_count} overdue books"
        
    except Exception as e:
        logger.error(f"Error processing expired reservations: {e}")
        return f"Error: {e}"


@shared_task
def send_reservation_reminders():
    """Send reminders for upcoming due dates and pickup deadlines"""
    try:
        from apps.core.utils import send_notification_email
        
        now = timezone.now()
        reminders_sent = 0
        
        # Pickup reminders (1 day before deadline)
        pickup_reminders = BookReservation.objects.filter(
            status='CONFIRMED',
            pickup_deadline__gte=now,
            pickup_deadline__lte=now + timedelta(hours=24),
            reminder_sent=False,
            is_deleted=False
        ).select_related('user', 'book', 'pickup_library')
        
        for reservation in pickup_reminders:
            try:
                subject = "Smart Lib - Book Ready for Pickup"
                message = f"""
                Dear {reservation.user.get_full_name()},
                
                Your reserved book is ready for pickup:
                
                Book: {reservation.book.title}
                Library: {reservation.pickup_library.name if reservation.pickup_library else reservation.book.library.name}
                Pickup Deadline: {reservation.pickup_deadline.strftime('%Y-%m-%d %H:%M')}
                
                Please collect your book before the deadline to avoid cancellation.
                
                Best regards,
                Smart Lib Team
                """
                
                send_notification_email(
                    to_email=reservation.user.email,
                    subject=subject,
                    message=message
                )
                
                reservation.reminder_sent = True
                reservation.save()
                reminders_sent += 1
                
            except Exception as e:
                logger.error(f"Error sending pickup reminder for reservation {reservation.id}: {e}")
                continue
        
        # Due date reminders (2 days before due)
        due_reminders = BookReservation.objects.filter(
            status='CHECKED_OUT',
            due_date__gte=now,
            due_date__lte=now + timedelta(days=2),
            reminder_sent=False,
            is_deleted=False
        ).select_related('user', 'book')
        
        for reservation in due_reminders:
            try:
                subject = "Smart Lib - Book Due Soon"
                message = f"""
                Dear {reservation.user.get_full_name()},
                
                Your book is due for return soon:
                
                Book: {reservation.book.title}
                Due Date: {reservation.due_date.strftime('%Y-%m-%d %H:%M')}
                
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
                
                reservation.reminder_sent = True
                reservation.save()
                reminders_sent += 1
                
            except Exception as e:
                logger.error(f"Error sending due reminder for reservation {reservation.id}: {e}")
                continue
        
        logger.info(f"Sent {reminders_sent} reservation reminders")
        return f"Sent {reminders_sent} reminders"
        
    except Exception as e:
        logger.error(f"Error sending reservation reminders: {e}")
        return f"Error: {e}"


@shared_task
def generate_daily_book_statistics():
    """Generate daily statistics for all books"""
    try:
        yesterday = timezone.now().date() - timedelta(days=1)
        books_processed = 0
        
        for book in Book.objects.filter(is_deleted=False):
            try:
                # Check if statistics already exist for yesterday
                if BookStatistics.objects.filter(
                    book=book,
                    date=yesterday
                ).exists():
                    continue
                
                # Get reservations for yesterday
                reservations = BookReservation.objects.filter(
                    book=book,
                    reservation_date__date=yesterday,
                    is_deleted=False
                )
                
                # Get digital access sessions for yesterday
                digital_sessions = BookDigitalAccess.objects.filter(
                    book=book,
                    started_at__date=yesterday,
                    is_deleted=False
                )
                
                # Calculate statistics
                total_reservations = reservations.count()
                total_checkouts = reservations.filter(status='CHECKED_OUT').count()
                total_returns = reservations.filter(status='RETURNED').count()
                digital_access_sessions = digital_sessions.count()
                
                # Get unique users
                unique_users = reservations.values('user').distinct().count()
                
                # Calculate average session duration for digital access
                avg_session_duration = None
                if digital_sessions.exists():
                    total_duration = sum([
                        session.total_time_spent.total_seconds()
                        for session in digital_sessions
                        if session.total_time_spent
                    ])
                    if total_duration > 0:
                        avg_session_duration = timedelta(seconds=total_duration / digital_sessions.count())
                
                # Get new reviews for the day
                new_reviews = book.reviews.filter(
                    created_at__date=yesterday,
                    is_deleted=False
                ).count()
                
                # Calculate average rating for the day
                daily_reviews = book.reviews.filter(
                    created_at__date=yesterday,
                    is_approved=True,
                    is_deleted=False
                )
                avg_daily_rating = daily_reviews.aggregate(
                    avg=Avg('overall_rating')
                )['avg'] or 0
                
                # Create statistics record
                BookStatistics.objects.create(
                    book=book,
                    date=yesterday,
                    views=0,  # This would be tracked separately
                    reservations=total_reservations,
                    checkouts=total_checkouts,
                    returns=total_returns,
                    digital_access_sessions=digital_access_sessions,
                    unique_users=unique_users,
                    average_session_duration=avg_session_duration,
                    new_reviews=new_reviews,
                    average_daily_rating=avg_daily_rating,
                )
                
                books_processed += 1
                
            except Exception as e:
                logger.error(f"Error generating statistics for book {book.title}: {e}")
                continue
        
        logger.info(f"Generated daily statistics for {books_processed} books")
        return f"Processed {books_processed} books"
        
    except Exception as e:
        logger.error(f"Error in generate_daily_book_statistics: {e}")
        return f"Error: {e}"


@shared_task
def cleanup_expired_digital_access():
    """Clean up expired digital access sessions"""
    try:
        now = timezone.now()
        expired_sessions = BookDigitalAccess.objects.filter(
            expires_at__lt=now,
            is_active=True,
            is_deleted=False
        )
        
        count = 0
        for session in expired_sessions:
            session.end_session()
            count += 1
        
        logger.info(f"Cleaned up {count} expired digital access sessions")
        return f"Cleaned up {count} expired sessions"
        
    except Exception as e:
        logger.error(f"Error cleaning up expired digital access: {e}")
        return f"Error: {e}"


@shared_task
def update_book_popularity():
    """Update book popularity based on recent activity"""
    try:
        from django.db.models import Q
        
        # Calculate popularity based on last 30 days
        thirty_days_ago = timezone.now() - timedelta(days=30)
        
        # Reset all books to not popular
        Book.objects.update(is_popular=False)
        
        # Find books with high activity in last 30 days
        popular_books = Book.objects.filter(
            is_deleted=False
        ).annotate(
            recent_reservations=Count(
                'reservations',
                filter=Q(reservations__reservation_date__gte=thirty_days_ago)
            ),
            recent_reviews=Count(
                'reviews',
                filter=Q(reviews__created_at__gte=thirty_days_ago)
            )
        ).filter(
            Q(recent_reservations__gte=5) |  # At least 5 reservations
            Q(recent_reviews__gte=3) |      # At least 3 reviews
            Q(average_rating__gte=4.0)      # High rating
        )
        
        # Mark as popular
        popular_count = popular_books.update(is_popular=True)
        
        logger.info(f"Updated popularity for {popular_count} books")
        return f"Updated {popular_count} popular books"
        
    except Exception as e:
        logger.error(f"Error updating book popularity: {e}")
        return f"Error: {e}"


@shared_task
def send_overdue_notices():
    """Send overdue notices for books"""
    try:
        from apps.core.utils import send_notification_email
        
        now = timezone.now()
        notices_sent = 0
        
        # Find overdue books
        overdue_reservations = BookReservation.objects.filter(
            status='OVERDUE',
            due_date__lt=now,
            is_deleted=False
        ).select_related('user', 'book')
        
        for reservation in overdue_reservations:
            try:
                days_overdue = (now.date() - reservation.due_date.date()).days
                
                # Send notice every 3 days
                if days_overdue % 3 == 0:
                    subject = f"Smart Lib - Overdue Book Notice ({days_overdue} days)"
                    message = f"""
                    Dear {reservation.user.get_full_name()},
                    
                    Your book is overdue:
                    
                    Book: {reservation.book.title}
                    Due Date: {reservation.due_date.strftime('%Y-%m-%d')}
                    Days Overdue: {days_overdue}
                    
                    Please return the book immediately to avoid additional penalties.
                    Late fees may apply.
                    
                    Best regards,
                    Smart Lib Team
                    """
                    
                    send_notification_email(
                        to_email=reservation.user.email,
                        subject=subject,
                        message=message
                    )
                    
                    reservation.overdue_notices_sent += 1
                    reservation.save()
                    notices_sent += 1
                
            except Exception as e:
                logger.error(f"Error sending overdue notice for reservation {reservation.id}: {e}")
                continue
        
        logger.info(f"Sent {notices_sent} overdue notices")
        return f"Sent {notices_sent} overdue notices"
        
    except Exception as e:
        logger.error(f"Error sending overdue notices: {e}")
        return f"Error: {e}"


@shared_task
def generate_book_recommendations():
    """Generate AI-based book recommendations for users"""
    try:
        from .models import BookRecommendation
        from django.contrib.auth import get_user_model
        
        User = get_user_model()
        recommendations_generated = 0
        
        # Simple recommendation algorithm based on user activity
        for user in User.objects.filter(is_active=True, is_approved=True):
            try:
                # Clear old recommendations
                BookRecommendation.objects.filter(
                    user=user,
                    expires_at__lt=timezone.now()
                ).delete()
                
                # Get user's reading history
                user_books = BookReservation.objects.filter(
                    user=user,
                    status='RETURNED',
                    is_deleted=False
                ).values_list('book__category', flat=True)
                
                if not user_books:
                    continue
                
                # Find popular books in same categories
                recommended_books = Book.objects.filter(
                    category__in=user_books,
                    is_deleted=False,
                    is_popular=True
                ).exclude(
                    reservations__user=user
                )[:5]
                
                for book in recommended_books:
                    BookRecommendation.objects.get_or_create(
                        user=user,
                        book=book,
                        recommendation_type='CATEGORY',
                        defaults={
                            'confidence_score': 0.7,
                            'reason': f'Based on your interest in {book.category.name}',
                            'expires_at': timezone.now() + timedelta(days=7),
                            'created_by': user
                        }
                    )
                    recommendations_generated += 1
                
            except Exception as e:
                logger.error(f"Error generating recommendations for user {user.id}: {e}")
                continue
        
        logger.info(f"Generated {recommendations_generated} book recommendations")
        return f"Generated {recommendations_generated} recommendations"
        
    except Exception as e:
        logger.error(f"Error generating book recommendations: {e}")
        return f"Error: {e}"