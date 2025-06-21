"""
Celery configuration for SmartLib
"""
import os
from celery import Celery
from django.conf import settings

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'smartlib.settings')

app = Celery('smartlib')

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django apps.
app.autodiscover_tasks()

# Celery Beat Schedule
app.conf.beat_schedule = {
    'process-expired-bookings': {
        'task': 'apps.seats.tasks.process_expired_bookings',
        'schedule': 60.0,  # Run every minute
    },
    'send-booking-reminders': {
        'task': 'apps.notifications.tasks.send_booking_reminders',
        'schedule': 300.0,  # Run every 5 minutes
    },
    'send-due-date-reminders': {
        'task': 'apps.notifications.tasks.send_due_date_reminders',
        'schedule': 3600.0,  # Run every hour
    },
    'clean-old-notifications': {
        'task': 'apps.notifications.tasks.clean_old_notifications',
        'schedule': 86400.0,  # Run daily
    },
    'process-expired-book-reservations': {
        'task': 'apps.books.tasks.process_expired_reservations',
        'schedule': 3600.0,  # Run every hour
    },
    'generate-daily-analytics': {
        'task': 'apps.analytics.tasks.generate_daily_analytics',
        'schedule': 86400.0,  # Run daily
    },
    'update-recommendations': {
        'task': 'apps.recommendations.tasks.update_user_recommendations',
        'schedule': 3600.0,  # Run every hour
    },
    # Subscription-related tasks
    'process-subscription-renewals': {
        'task': 'apps.subscriptions.tasks.process_subscription_renewals',
        'schedule': 3600.0,  # Run every hour
    },
    'update-expired-subscriptions': {
        'task': 'apps.subscriptions.tasks.update_expired_subscriptions',
        'schedule': 3600.0,  # Run every hour
    },
    'send-subscription-expiry-reminders': {
        'task': 'apps.subscriptions.tasks.send_subscription_expiry_reminders',
        'schedule': 86400.0,  # Run daily
    },
    # User-related tasks
    'cleanup-expired-sessions': {
        'task': 'apps.accounts.tasks.cleanup_expired_sessions',
        'schedule': 86400.0,  # Run daily
    },
    'cleanup-expired-verifications': {
        'task': 'apps.accounts.tasks.cleanup_expired_verifications',
        'schedule': 3600.0,  # Run every hour
    },
    'process-loyalty-points-expiry': {
        'task': 'apps.accounts.tasks.process_loyalty_points_expiry',
        'schedule': 86400.0,  # Run daily
    },
    'generate-user-statistics': {
        'task': 'apps.accounts.tasks.generate_user_statistics',
        'schedule': 86400.0,  # Run daily
    },
}

app.conf.timezone = settings.TIME_ZONE

@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')