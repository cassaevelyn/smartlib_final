"""
Models for subscription management
"""
from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone
from apps.core.models import BaseModel, TimeStampedModel
from apps.core.utils import generate_unique_code
import uuid

User = get_user_model()


class SubscriptionPlan(BaseModel):
    """
    Model for subscription plans
    """
    PLAN_TYPES = [
        ('BASIC', 'Basic'),
        ('STANDARD', 'Standard'),
        ('PREMIUM', 'Premium'),
        ('STUDENT', 'Student'),
        ('FACULTY', 'Faculty'),
    ]
    
    BILLING_PERIODS = [
        ('MONTHLY', 'Monthly'),
        ('QUARTERLY', 'Quarterly'),
        ('SEMI_ANNUAL', 'Semi-Annual'),
        ('ANNUAL', 'Annual'),
    ]
    
    name = models.CharField(max_length=100)
    code = models.CharField(max_length=20, unique=True, blank=True)
    plan_type = models.CharField(max_length=15, choices=PLAN_TYPES)
    description = models.TextField()
    features = models.JSONField(default=list)
    
    # Pricing
    price = models.DecimalField(max_digits=10, decimal_places=2)
    discount_percentage = models.DecimalField(max_digits=5, decimal_places=2, default=0.00)
    billing_period = models.CharField(max_length=15, choices=BILLING_PERIODS, default='MONTHLY')
    
    # Limits
    max_book_reservations = models.PositiveIntegerField(default=5)
    max_seat_bookings = models.PositiveIntegerField(default=1)
    max_event_registrations = models.PositiveIntegerField(default=3)
    max_concurrent_digital_access = models.PositiveIntegerField(default=1)
    
    # Access Control
    has_premium_seat_access = models.BooleanField(default=False)
    has_premium_book_access = models.BooleanField(default=False)
    has_premium_event_access = models.BooleanField(default=False)
    
    # Status
    is_active = models.BooleanField(default=True)
    is_featured = models.BooleanField(default=False)
    
    # Display
    color = models.CharField(max_length=7, default='#007bff')  # Hex color
    icon = models.CharField(max_length=50, blank=True)
    
    class Meta:
        db_table = 'subscriptions_plan'
        ordering = ['price', 'name']
    
    def __str__(self):
        return f"{self.name} ({self.get_plan_type_display()})"
    
    def save(self, *args, **kwargs):
        if not self.code:
            self.code = generate_unique_code('SUB', 4)
        super().save(*args, **kwargs)
    
    @property
    def discounted_price(self):
        """Calculate discounted price"""
        if self.discount_percentage > 0:
            discount_amount = (self.price * self.discount_percentage) / 100
            return self.price - discount_amount
        return self.price
    
    @property
    def billing_period_days(self):
        """Get billing period in days"""
        if self.billing_period == 'MONTHLY':
            return 30
        elif self.billing_period == 'QUARTERLY':
            return 90
        elif self.billing_period == 'SEMI_ANNUAL':
            return 180
        elif self.billing_period == 'ANNUAL':
            return 365
        return 30  # Default to monthly


class UserSubscription(BaseModel):
    """
    Model for user subscriptions
    """
    STATUS_CHOICES = [
        ('ACTIVE', 'Active'),
        ('EXPIRED', 'Expired'),
        ('CANCELLED', 'Cancelled'),
        ('PENDING', 'Pending'),
        ('TRIAL', 'Trial'),
    ]
    
    PAYMENT_STATUS = [
        ('PENDING', 'Pending'),
        ('COMPLETED', 'Completed'),
        ('FAILED', 'Failed'),
        ('REFUNDED', 'Refunded'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='subscriptions')
    plan = models.ForeignKey(SubscriptionPlan, on_delete=models.PROTECT, related_name='user_subscriptions')
    subscription_code = models.CharField(max_length=30, unique=True, blank=True)
    
    # Dates
    start_date = models.DateTimeField()
    end_date = models.DateTimeField()
    cancelled_at = models.DateTimeField(null=True, blank=True)
    
    # Status
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='PENDING')
    is_auto_renew = models.BooleanField(default=True)
    
    # Payment
    amount_paid = models.DecimalField(max_digits=10, decimal_places=2)
    payment_status = models.CharField(max_length=10, choices=PAYMENT_STATUS, default='PENDING')
    payment_method = models.CharField(max_length=50, blank=True)
    payment_reference = models.CharField(max_length=100, blank=True)
    
    # Metadata
    notes = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    
    class Meta:
        db_table = 'subscriptions_user_subscription'
        ordering = ['-start_date']
    
    def __str__(self):
        return f"{self.user.get_full_name()} - {self.plan.name} ({self.status})"
    
    def save(self, *args, **kwargs):
        if not self.subscription_code:
            self.subscription_code = generate_unique_code('SUB', 8)
        super().save(*args, **kwargs)
    
    @property
    def is_active(self):
        """Check if subscription is active"""
        now = timezone.now()
        return (
            self.status == 'ACTIVE' and
            self.start_date <= now and
            self.end_date > now
        )
    
    @property
    def days_remaining(self):
        """Get days remaining in subscription"""
        if not self.is_active:
            return 0
        now = timezone.now()
        delta = self.end_date - now
        return max(0, delta.days)
    
    @property
    def percentage_remaining(self):
        """Get percentage of subscription period remaining"""
        if not self.is_active:
            return 0
        total_days = (self.end_date - self.start_date).days
        if total_days <= 0:
            return 0
        remaining_days = self.days_remaining
        return (remaining_days / total_days) * 100
    
    def cancel(self):
        """Cancel subscription"""
        if self.status == 'ACTIVE':
            self.status = 'CANCELLED'
            self.cancelled_at = timezone.now()
            self.is_auto_renew = False
            self.save()
            return True
        return False
    
    def renew(self, days=None):
        """Renew subscription"""
        if not days:
            days = self.plan.billing_period_days
        
        self.start_date = self.end_date
        self.end_date = self.start_date + timezone.timedelta(days=days)
        self.status = 'ACTIVE'
        self.save()
        return True


class SubscriptionTransaction(BaseModel):
    """
    Model for subscription payment transactions
    """
    TRANSACTION_TYPES = [
        ('PURCHASE', 'Purchase'),
        ('RENEWAL', 'Renewal'),
        ('REFUND', 'Refund'),
        ('UPGRADE', 'Upgrade'),
        ('DOWNGRADE', 'Downgrade'),
    ]
    
    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('COMPLETED', 'Completed'),
        ('FAILED', 'Failed'),
        ('REFUNDED', 'Refunded'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='subscription_transactions')
    subscription = models.ForeignKey(UserSubscription, on_delete=models.CASCADE, related_name='transactions')
    transaction_code = models.CharField(max_length=30, unique=True, blank=True)
    transaction_type = models.CharField(max_length=10, choices=TRANSACTION_TYPES)
    
    # Amount
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=3, default='PKR')
    
    # Status
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='PENDING')
    
    # Payment Details
    payment_method = models.CharField(max_length=50, blank=True)
    payment_reference = models.CharField(max_length=100, blank=True)
    payment_gateway = models.CharField(max_length=50, blank=True)
    
    # Metadata
    notes = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    
    class Meta:
        db_table = 'subscriptions_transaction'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.transaction_code} - {self.user.get_full_name()} ({self.amount} {self.currency})"
    
    def save(self, *args, **kwargs):
        if not self.transaction_code:
            self.transaction_code = generate_unique_code('TRX', 8)
        super().save(*args, **kwargs)


class SubscriptionBenefit(BaseModel):
    """
    Model for subscription benefits
    """
    BENEFIT_TYPES = [
        ('FEATURE', 'Feature Access'),
        ('DISCOUNT', 'Discount'),
        ('LIMIT_INCREASE', 'Limit Increase'),
        ('PRIORITY', 'Priority Access'),
        ('REWARD', 'Reward'),
    ]
    
    name = models.CharField(max_length=100)
    description = models.TextField()
    benefit_type = models.CharField(max_length=15, choices=BENEFIT_TYPES)
    icon = models.CharField(max_length=50, blank=True)
    
    # Display
    is_highlighted = models.BooleanField(default=False)
    sort_order = models.PositiveIntegerField(default=0)
    
    class Meta:
        db_table = 'subscriptions_benefit'
        ordering = ['sort_order', 'name']
    
    def __str__(self):
        return f"{self.name} ({self.get_benefit_type_display()})"


class PlanBenefit(BaseModel):
    """
    Through model for plan benefits
    """
    plan = models.ForeignKey(SubscriptionPlan, on_delete=models.CASCADE, related_name='benefits')
    benefit = models.ForeignKey(SubscriptionBenefit, on_delete=models.CASCADE, related_name='plans')
    
    # Value for this benefit in this plan
    value = models.CharField(max_length=100, blank=True)
    is_available = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'subscriptions_plan_benefit'
        unique_together = ['plan', 'benefit']
        ordering = ['benefit__sort_order']
    
    def __str__(self):
        return f"{self.plan.name} - {self.benefit.name}"