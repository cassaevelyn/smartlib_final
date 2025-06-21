"""
Celery tasks for subscriptions app
"""
from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from .models import UserSubscription, SubscriptionTransaction
import logging

logger = logging.getLogger(__name__)


@shared_task
def process_subscription_renewals():
    """Process automatic subscription renewals"""
    try:
        # Find subscriptions that are about to expire in the next 24 hours
        expiry_threshold = timezone.now() + timedelta(hours=24)
        
        subscriptions_to_renew = UserSubscription.objects.filter(
            status='ACTIVE',
            is_auto_renew=True,
            end_date__lt=expiry_threshold,
            end_date__gt=timezone.now(),
            is_deleted=False
        ).select_related('user', 'plan')
        
        renewals_processed = 0
        
        for subscription in subscriptions_to_renew:
            try:
                # Calculate new dates
                start_date = subscription.end_date
                end_date = start_date + timedelta(days=subscription.plan.billing_period_days)
                
                # Create new subscription
                new_subscription = UserSubscription.objects.create(
                    user=subscription.user,
                    plan=subscription.plan,
                    start_date=start_date,
                    end_date=end_date,
                    status='ACTIVE',
                    is_auto_renew=subscription.is_auto_renew,
                    amount_paid=subscription.plan.discounted_price,
                    payment_status='COMPLETED',  # Assuming payment is processed automatically
                    payment_method=subscription.payment_method,
                    payment_reference=f"AUTO-RENEWAL-{subscription.subscription_code}",
                    created_by=subscription.user
                )
                
                # Create transaction record
                SubscriptionTransaction.objects.create(
                    user=subscription.user,
                    subscription=new_subscription,
                    transaction_type='RENEWAL',
                    amount=subscription.plan.discounted_price,
                    status='COMPLETED',
                    payment_method=subscription.payment_method,
                    payment_reference=f"AUTO-RENEWAL-{subscription.subscription_code}",
                    created_by=subscription.user
                )
                
                # Set as user's current subscription
                subscription.user.current_subscription = new_subscription
                subscription.user.save()
                
                renewals_processed += 1
                
                # Log activity
                from apps.core.models import ActivityLog
                ActivityLog.objects.create(
                    user=subscription.user,
                    activity_type='SUBSCRIPTION_RENEWAL',
                    description=f'Subscription automatically renewed: {subscription.plan.name}',
                    metadata={
                        'old_subscription_id': str(subscription.id),
                        'new_subscription_id': str(new_subscription.id),
                        'plan_id': str(subscription.plan.id),
                        'plan_name': subscription.plan.name,
                        'amount': float(subscription.plan.discounted_price),
                    }
                )
                
            except Exception as e:
                logger.error(f"Error renewing subscription {subscription.id}: {e}")
                continue
        
        logger.info(f"Processed {renewals_processed} subscription renewals")
        return f"Processed {renewals_processed} subscription renewals"
        
    except Exception as e:
        logger.error(f"Error in process_subscription_renewals: {e}")
        return f"Error: {e}"


@shared_task
def update_expired_subscriptions():
    """Update status of expired subscriptions"""
    try:
        now = timezone.now()
        
        # Find expired subscriptions
        expired_subscriptions = UserSubscription.objects.filter(
            status='ACTIVE',
            end_date__lt=now,
            is_deleted=False
        )
        
        expired_count = expired_subscriptions.count()
        expired_subscriptions.update(status='EXPIRED')
        
        logger.info(f"Updated {expired_count} expired subscriptions")
        return f"Updated {expired_count} expired subscriptions"
        
    except Exception as e:
        logger.error(f"Error in update_expired_subscriptions: {e}")
        return f"Error: {e}"


@shared_task
def send_subscription_expiry_reminders():
    """Send reminders for subscriptions about to expire"""
    try:
        from apps.core.utils import send_notification_email
        
        # Find subscriptions expiring in the next 3 days
        expiry_threshold = timezone.now() + timedelta(days=3)
        
        subscriptions = UserSubscription.objects.filter(
            status='ACTIVE',
            is_auto_renew=False,  # Only remind for non-auto-renew subscriptions
            end_date__lt=expiry_threshold,
            end_date__gt=timezone.now(),
            is_deleted=False
        ).select_related('user', 'plan')
        
        reminders_sent = 0
        
        for subscription in subscriptions:
            try:
                days_remaining = (subscription.end_date - timezone.now()).days
                
                subject = f"Smart Lib - Your Subscription Expires in {days_remaining} Days"
                message = f"""
                Dear {subscription.user.get_full_name()},
                
                Your {subscription.plan.name} subscription will expire in {days_remaining} days.
                
                To continue enjoying the benefits of your subscription, please renew before it expires.
                
                Subscription Details:
                - Plan: {subscription.plan.name}
                - Expires on: {subscription.end_date.strftime('%Y-%m-%d')}
                
                Best regards,
                Smart Lib Team
                """
                
                send_notification_email(
                    to_email=subscription.user.email,
                    subject=subject,
                    message=message
                )
                
                # Create notification
                from apps.notifications.models import Notification
                Notification.objects.create(
                    user=subscription.user,
                    title=f"Subscription Expiring Soon",
                    message=f"Your {subscription.plan.name} subscription expires in {days_remaining} days.",
                    type='WARNING',
                    action_url='/settings/subscriptions'
                )
                
                reminders_sent += 1
                
            except Exception as e:
                logger.error(f"Error sending reminder for subscription {subscription.id}: {e}")
                continue
        
        logger.info(f"Sent {reminders_sent} subscription expiry reminders")
        return f"Sent {reminders_sent} reminders"
        
    except Exception as e:
        logger.error(f"Error in send_subscription_expiry_reminders: {e}")
        return f"Error: {e}"