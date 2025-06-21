"""
Serializers for subscriptions app
"""
from rest_framework import serializers
from django.utils import timezone
from apps.core.serializers import BaseModelSerializer
from .models import (
    SubscriptionPlan, UserSubscription, SubscriptionTransaction,
    SubscriptionBenefit, PlanBenefit
)


class SubscriptionBenefitSerializer(BaseModelSerializer):
    """Serializer for subscription benefits"""
    benefit_type_display = serializers.CharField(source='get_benefit_type_display', read_only=True)
    
    class Meta:
        model = SubscriptionBenefit
        fields = [
            'id', 'name', 'description', 'benefit_type', 'benefit_type_display',
            'icon', 'is_highlighted', 'sort_order', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']


class PlanBenefitSerializer(BaseModelSerializer):
    """Serializer for plan benefits"""
    benefit = SubscriptionBenefitSerializer(read_only=True)
    
    class Meta:
        model = PlanBenefit
        fields = [
            'id', 'benefit', 'value', 'is_available', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']


class SubscriptionPlanSerializer(BaseModelSerializer):
    """Serializer for subscription plans"""
    plan_type_display = serializers.CharField(source='get_plan_type_display', read_only=True)
    billing_period_display = serializers.CharField(source='get_billing_period_display', read_only=True)
    discounted_price = serializers.ReadOnlyField()
    billing_period_days = serializers.ReadOnlyField()
    benefits = PlanBenefitSerializer(many=True, read_only=True)
    
    class Meta:
        model = SubscriptionPlan
        fields = [
            'id', 'name', 'code', 'plan_type', 'plan_type_display',
            'description', 'features', 'price', 'discount_percentage',
            'discounted_price', 'billing_period', 'billing_period_display',
            'billing_period_days', 'max_book_reservations', 'max_seat_bookings',
            'max_event_registrations', 'max_concurrent_digital_access',
            'has_premium_seat_access', 'has_premium_book_access',
            'has_premium_event_access', 'is_active', 'is_featured',
            'color', 'icon', 'benefits', 'created_at'
        ]
        read_only_fields = ['id', 'code', 'created_at']


class UserSubscriptionSerializer(BaseModelSerializer):
    """Serializer for user subscriptions"""
    user_display = serializers.CharField(source='user.get_full_name', read_only=True)
    plan_display = serializers.CharField(source='plan.name', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    payment_status_display = serializers.CharField(source='get_payment_status_display', read_only=True)
    is_active = serializers.ReadOnlyField()
    days_remaining = serializers.ReadOnlyField()
    percentage_remaining = serializers.ReadOnlyField()
    
    class Meta:
        model = UserSubscription
        fields = [
            'id', 'user', 'user_display', 'plan', 'plan_display',
            'subscription_code', 'start_date', 'end_date', 'cancelled_at',
            'status', 'status_display', 'is_auto_renew', 'amount_paid',
            'payment_status', 'payment_status_display', 'payment_method',
            'payment_reference', 'notes', 'metadata', 'is_active',
            'days_remaining', 'percentage_remaining', 'created_at'
        ]
        read_only_fields = ['id', 'subscription_code', 'created_at']


class SubscriptionTransactionSerializer(BaseModelSerializer):
    """Serializer for subscription transactions"""
    user_display = serializers.CharField(source='user.get_full_name', read_only=True)
    transaction_type_display = serializers.CharField(source='get_transaction_type_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    
    class Meta:
        model = SubscriptionTransaction
        fields = [
            'id', 'user', 'user_display', 'subscription', 'transaction_code',
            'transaction_type', 'transaction_type_display', 'amount', 'currency',
            'status', 'status_display', 'payment_method', 'payment_reference',
            'payment_gateway', 'notes', 'metadata', 'created_at'
        ]
        read_only_fields = ['id', 'transaction_code', 'created_at']


class SubscriptionPurchaseSerializer(serializers.Serializer):
    """Serializer for purchasing a subscription"""
    plan_id = serializers.UUIDField(required=True)
    payment_method = serializers.CharField(required=True)
    payment_reference = serializers.CharField(required=False, allow_blank=True)
    start_date = serializers.DateTimeField(default=timezone.now)
    is_auto_renew = serializers.BooleanField(default=True)
    
    def validate_plan_id(self, value):
        try:
            plan = SubscriptionPlan.objects.get(id=value, is_active=True)
            self.context['plan'] = plan
            return value
        except SubscriptionPlan.DoesNotExist:
            raise serializers.ValidationError("Invalid or inactive subscription plan")
    
    def validate_start_date(self, value):
        if value < timezone.now():
            raise serializers.ValidationError("Start date cannot be in the past")
        return value


class SubscriptionCancelSerializer(serializers.Serializer):
    """Serializer for cancelling a subscription"""
    subscription_id = serializers.UUIDField(required=True)
    cancellation_reason = serializers.CharField(required=False, allow_blank=True)
    
    def validate_subscription_id(self, value):
        user = self.context['request'].user
        try:
            subscription = UserSubscription.objects.get(
                id=value,
                user=user,
                status='ACTIVE'
            )
            self.context['subscription'] = subscription
            return value
        except UserSubscription.DoesNotExist:
            raise serializers.ValidationError("Invalid or inactive subscription")


class SubscriptionRenewSerializer(serializers.Serializer):
    """Serializer for renewing a subscription"""
    subscription_id = serializers.UUIDField(required=True)
    payment_method = serializers.CharField(required=True)
    payment_reference = serializers.CharField(required=False, allow_blank=True)
    
    def validate_subscription_id(self, value):
        user = self.context['request'].user
        try:
            subscription = UserSubscription.objects.get(
                id=value,
                user=user
            )
            if subscription.status not in ['ACTIVE', 'EXPIRED']:
                raise serializers.ValidationError("Only active or expired subscriptions can be renewed")
            self.context['subscription'] = subscription
            return value
        except UserSubscription.DoesNotExist:
            raise serializers.ValidationError("Invalid subscription")