"""
Signals for subscriptions app
"""
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.utils import timezone
from apps.core.models import ActivityLog
from .models import UserSubscription, SubscriptionTransaction


@receiver(post_save, sender=UserSubscription)
def create_subscription_transaction(sender, instance, created, **kwargs):
    """Create transaction when subscription is created"""
    if created:
        # Create transaction record
        SubscriptionTransaction.objects.create(
            user=instance.user,
            subscription=instance,
            transaction_type='PURCHASE',
            amount=instance.amount_paid,
            status=instance.payment_status,
            payment_method=instance.payment_method,
            payment_reference=instance.payment_reference,
            created_by=instance.created_by
        )
        
        # Log activity
        ActivityLog.objects.create(
            user=instance.user,
            activity_type='SUBSCRIPTION_PURCHASE',
            description=f'Purchased {instance.plan.name} subscription',
            metadata={
                'subscription_id': str(instance.id),
                'plan_id': str(instance.plan.id),
                'plan_name': instance.plan.name,
                'amount': float(instance.amount_paid),
                'status': instance.status,
            }
        )


@receiver(pre_save, sender=UserSubscription)
def track_subscription_status_changes(sender, instance, **kwargs):
    """Track subscription status changes"""
    if instance.pk:
        try:
            old_instance = UserSubscription.objects.get(pk=instance.pk)
            
            # Track status changes
            if old_instance.status != instance.status:
                ActivityLog.objects.create(
                    user=instance.user,
                    activity_type='SUBSCRIPTION_UPDATE',
                    description=f'Subscription status changed from {old_instance.status} to {instance.status}',
                    metadata={
                        'subscription_id': str(instance.id),
                        'plan_id': str(instance.plan.id),
                        'plan_name': instance.plan.name,
                        'old_status': old_instance.status,
                        'new_status': instance.status,
                    }
                )
                
                # If subscription became active, update user's current_subscription reference
                if instance.status == 'ACTIVE' and old_instance.status != 'ACTIVE':
                    instance.user.current_subscription = instance
                    instance.user.save()
                
                # If subscription is no longer active, remove user's current_subscription reference
                elif old_instance.status == 'ACTIVE' and instance.status != 'ACTIVE':
                    if hasattr(instance.user, 'current_subscription') and instance.user.current_subscription == instance:
                        instance.user.current_subscription = None
                        instance.user.save()
                        
        except UserSubscription.DoesNotExist:
            pass


@receiver(post_save, sender=SubscriptionTransaction)
def update_subscription_payment_status(sender, instance, created, **kwargs):
    """Update subscription payment status when transaction is updated"""
    if not created and instance.status == 'COMPLETED' and instance.subscription.payment_status != 'COMPLETED':
        # Update subscription payment status
        subscription = instance.subscription
        subscription.payment_status = 'COMPLETED'
        
        # If this is a new subscription and payment is now complete, activate it
        if subscription.status == 'PENDING':
            subscription.status = 'ACTIVE'
            
        subscription.save()
        
        # Log activity
        ActivityLog.objects.create(
            user=instance.user,
            activity_type='PAYMENT_COMPLETED',
            description=f'Payment completed for {subscription.plan.name} subscription',
            metadata={
                'subscription_id': str(subscription.id),
                'transaction_id': str(instance.id),
                'amount': float(instance.amount),
                'payment_method': instance.payment_method,
            }
        )