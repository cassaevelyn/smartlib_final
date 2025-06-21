"""
Celery tasks for library app
"""
from celery import shared_task
from django.utils import timezone
from django.db.models import Count, Avg, Sum
from datetime import timedelta, date
from .models import Library, LibraryStatistics, LibraryNotification
import logging

logger = logging.getLogger(__name__)


@shared_task
def generate_daily_library_statistics():
    """Generate daily statistics for all libraries"""
    try:
        yesterday = timezone.now().date() - timedelta(days=1)
        libraries_processed = 0
        
        for library in Library.objects.filter(is_deleted=False):
            try:
                # Check if statistics already exist for yesterday
                if LibraryStatistics.objects.filter(
                    library=library,
                    date=yesterday
                ).exists():
                    continue
                
                # Import here to avoid circular imports
                from apps.seats.models import SeatBooking
                from apps.accounts.models import User
                
                # Get bookings for yesterday
                bookings = SeatBooking.objects.filter(
                    seat__library=library,
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
                
                # Get unique visitors
                unique_visitors = bookings.values('user').distinct().count()
                
                # Calculate average session duration
                completed_bookings = bookings.filter(status='COMPLETED')
                if completed_bookings.exists():
                    total_duration = sum([
                        (booking.actual_end_time - booking.actual_start_time).total_seconds()
                        for booking in completed_bookings
                        if booking.actual_end_time and booking.actual_start_time
                    ])
                    avg_duration = timedelta(seconds=total_duration / completed_bookings.count())
                    total_hours = total_duration / 3600  # Convert to hours
                else:
                    avg_duration = None
                    total_hours = 0
                
                # Create statistics record
                LibraryStatistics.objects.create(
                    library=library,
                    date=yesterday,
                    total_visitors=unique_visitors,
                    unique_visitors=unique_visitors,
                    total_bookings=total_bookings,
                    successful_checkins=successful_checkins,
                    no_shows=no_shows,
                    cancellations=cancellations,
                    average_session_duration=avg_duration,
                    total_study_hours=total_hours,
                    # These would be calculated from actual data
                    peak_occupancy=0,
                    average_occupancy=0.0,
                    subscription_revenue=0.0,
                    penalty_revenue=0.0,
                )
                
                libraries_processed += 1
                
            except Exception as e:
                logger.error(f"Error generating statistics for library {library.name}: {e}")
                continue
        
        logger.info(f"Generated daily statistics for {libraries_processed} libraries")
        return f"Processed {libraries_processed} libraries"
        
    except Exception as e:
        logger.error(f"Error in generate_daily_library_statistics: {e}")
        return f"Error: {e}"


@shared_task
def cleanup_expired_notifications():
    """Clean up expired notifications"""
    try:
        now = timezone.now()
        expired_notifications = LibraryNotification.objects.filter(
            end_date__lt=now,
            is_active=True,
            is_deleted=False
        )
        
        count = expired_notifications.count()
        expired_notifications.update(is_active=False)
        
        logger.info(f"Deactivated {count} expired notifications")
        return f"Deactivated {count} expired notifications"
        
    except Exception as e:
        logger.error(f"Error cleaning up expired notifications: {e}")
        return f"Error: {e}"


@shared_task
def update_library_occupancy_stats():
    """Update real-time occupancy statistics for libraries"""
    try:
        from apps.seats.models import Seat
        
        libraries_updated = 0
        
        for library in Library.objects.filter(
            status='ACTIVE',
            is_deleted=False
        ):
            try:
                # Get current occupancy
                total_seats = library.total_seats
                occupied_seats = Seat.objects.filter(
                    library=library,
                    status='OCCUPIED',
                    is_deleted=False
                ).count()
                
                # Calculate occupancy rate
                occupancy_rate = (occupied_seats / total_seats * 100) if total_seats > 0 else 0
                
                # Update today's statistics if exists
                today = timezone.now().date()
                stats, created = LibraryStatistics.objects.get_or_create(
                    library=library,
                    date=today,
                    defaults={
                        'peak_occupancy': occupied_seats,
                        'average_occupancy': occupancy_rate,
                    }
                )
                
                if not created:
                    # Update peak occupancy if current is higher
                    if occupied_seats > stats.peak_occupancy:
                        stats.peak_occupancy = occupied_seats
                        stats.peak_hour = timezone.now().time()
                    
                    # Update average occupancy (simple moving average)
                    stats.average_occupancy = (stats.average_occupancy + occupancy_rate) / 2
                    stats.save()
                
                libraries_updated += 1
                
            except Exception as e:
                logger.error(f"Error updating occupancy for library {library.name}: {e}")
                continue
        
        logger.info(f"Updated occupancy stats for {libraries_updated} libraries")
        return f"Updated {libraries_updated} libraries"
        
    except Exception as e:
        logger.error(f"Error in update_library_occupancy_stats: {e}")
        return f"Error: {e}"


@shared_task
def send_library_maintenance_reminders():
    """Send maintenance reminders for libraries"""
    try:
        # This would integrate with a maintenance scheduling system
        # For now, we'll just log libraries that might need attention
        
        libraries_needing_attention = Library.objects.filter(
            status='ACTIVE',
            is_deleted=False
        ).annotate(
            recent_issues=Count('notifications', filter=models.Q(
                notifications__notification_type='MAINTENANCE',
                notifications__created_at__gte=timezone.now() - timedelta(days=30)
            ))
        ).filter(recent_issues__gt=3)
        
        for library in libraries_needing_attention:
            logger.warning(f"Library {library.name} may need maintenance attention - {library.recent_issues} issues in last 30 days")
        
        return f"Checked {Library.objects.count()} libraries for maintenance needs"
        
    except Exception as e:
        logger.error(f"Error in send_library_maintenance_reminders: {e}")
        return f"Error: {e}"


@shared_task
def generate_library_analytics_report():
    """Generate comprehensive analytics report for libraries"""
    try:
        from django.core.mail import send_mail
        from django.conf import settings
        
        # Calculate various metrics
        total_libraries = Library.objects.filter(is_deleted=False).count()
        active_libraries = Library.objects.filter(
            status='ACTIVE',
            is_deleted=False
        ).count()
        
        # Get statistics for last 30 days
        thirty_days_ago = timezone.now().date() - timedelta(days=30)
        recent_stats = LibraryStatistics.objects.filter(
            date__gte=thirty_days_ago
        ).aggregate(
            total_visitors=Sum('total_visitors'),
            total_bookings=Sum('total_bookings'),
            total_study_hours=Sum('total_study_hours'),
            avg_occupancy=Avg('average_occupancy')
        )
        
        # Top performing libraries
        top_libraries = Library.objects.filter(
            is_deleted=False
        ).order_by('-average_rating', '-total_reviews')[:5]
        
        # Generate report content
        report = f"""
        Library Analytics Report - {timezone.now().date()}
        
        Overview:
        - Total Libraries: {total_libraries}
        - Active Libraries: {active_libraries}
        
        Last 30 Days:
        - Total Visitors: {recent_stats['total_visitors'] or 0}
        - Total Bookings: {recent_stats['total_bookings'] or 0}
        - Total Study Hours: {recent_stats['total_study_hours'] or 0:.2f}
        - Average Occupancy: {recent_stats['avg_occupancy'] or 0:.2f}%
        
        Top Rated Libraries:
        """
        
        for i, library in enumerate(top_libraries, 1):
            report += f"\n{i}. {library.name} - {library.average_rating}★ ({library.total_reviews} reviews)"
        
        # Send report to admins (you would configure this based on your needs)
        logger.info("Generated library analytics report")
        
        return "Analytics report generated successfully"
        
    except Exception as e:
        logger.error(f"Error generating analytics report: {e}")
        return f"Error: {e}"