"""
Views for subscriptions app
"""
from rest_framework import generics, status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from django.utils import timezone
from django.db import transaction
from apps.core.permissions import IsAdminUser
from .models import (
    SubscriptionPlan, UserSubscription, SubscriptionTransaction,
    SubscriptionBenefit, PlanBenefit
)
from .serializers import (
    SubscriptionPlanSerializer, UserSubscriptionSerializer,
    SubscriptionTransactionSerializer, SubscriptionBenefitSerializer,
    SubscriptionPurchaseSerializer, SubscriptionCancelSerializer,
    SubscriptionRenewSerializer
)


class SubscriptionPlanListView(generics.ListAPIView):
    """List all active subscription plans"""
    serializer_class = SubscriptionPlanSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return SubscriptionPlan.objects.filter(
            is_active=True,
            is_deleted=False
        ).prefetch_related('benefits__benefit')


class SubscriptionPlanDetailView(generics.RetrieveAPIView):
    """Get details of a specific subscription plan"""
    serializer_class = SubscriptionPlanSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'id'
    
    def get_queryset(self):
        return SubscriptionPlan.objects.filter(
            is_active=True,
            is_deleted=False
        ).prefetch_related('benefits__benefit')


class UserSubscriptionListView(generics.ListAPIView):
    """List all subscriptions for the current user"""
    serializer_class = UserSubscriptionSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return UserSubscription.objects.filter(
            user=self.request.user,
            is_deleted=False
        ).select_related('plan')


class UserSubscriptionDetailView(generics.RetrieveAPIView):
    """Get details of a specific user subscription"""
    serializer_class = UserSubscriptionSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'id'
    
    def get_queryset(self):
        return UserSubscription.objects.filter(
            user=self.request.user,
            is_deleted=False
        ).select_related('plan')


class SubscriptionTransactionListView(generics.ListAPIView):
    """List all transactions for the current user"""
    serializer_class = SubscriptionTransactionSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return SubscriptionTransaction.objects.filter(
            user=self.request.user,
            is_deleted=False
        ).select_related('subscription', 'subscription__plan')


class SubscriptionBenefitListView(generics.ListAPIView):
    """List all subscription benefits"""
    serializer_class = SubscriptionBenefitSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return SubscriptionBenefit.objects.filter(
            is_deleted=False
        ).order_by('sort_order')


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def purchase_subscription(request):
    """Purchase a new subscription"""
    serializer = SubscriptionPurchaseSerializer(
        data=request.data,
        context={'request': request}
    )
    
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    plan = serializer.context['plan']
    user = request.user
    
    # Check if user already has an active subscription
    active_subscription = UserSubscription.objects.filter(
        user=user,
        status='ACTIVE',
        end_date__gt=timezone.now(),
        is_deleted=False
    ).first()
    
    if active_subscription:
        return Response(
            {'error': 'You already have an active subscription. Please cancel it before purchasing a new one.'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Calculate end date based on billing period
    start_date = serializer.validated_data['start_date']
    end_date = start_date + timezone.timedelta(days=plan.billing_period_days)
    
    # Calculate amount to pay (apply discount if any)
    amount_to_pay = plan.discounted_price
    
    with transaction.atomic():
        # Create subscription
        subscription = UserSubscription.objects.create(
            user=user,
            plan=plan,
            start_date=start_date,
            end_date=end_date,
            status='PENDING',  # Will be updated to ACTIVE when payment is confirmed
            is_auto_renew=serializer.validated_data['is_auto_renew'],
            amount_paid=amount_to_pay,
            payment_status='PENDING',
            payment_method=serializer.validated_data['payment_method'],
            payment_reference=serializer.validated_data.get('payment_reference', ''),
            created_by=user
        )
        
        # In a real-world scenario, you would integrate with a payment gateway here
        # For demo purposes, we'll simulate a successful payment
        subscription.payment_status = 'COMPLETED'
        subscription.status = 'ACTIVE'
        subscription.save()
        
        # Set as user's current subscription
        user.current_subscription = subscription
        user.save()
    
    return Response(
        UserSubscriptionSerializer(subscription).data,
        status=status.HTTP_201_CREATED
    )


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def cancel_subscription(request):
    """Cancel an active subscription"""
    serializer = SubscriptionCancelSerializer(
        data=request.data,
        context={'request': request}
    )
    
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    subscription = serializer.context['subscription']
    
    # Cancel the subscription
    if subscription.cancel():
        # Update metadata with cancellation reason
        if 'cancellation_reason' in serializer.validated_data:
            subscription.metadata = {
                **subscription.metadata,
                'cancellation_reason': serializer.validated_data['cancellation_reason']
            }
            subscription.save()
        
        return Response(
            {'message': 'Subscription cancelled successfully'},
            status=status.HTTP_200_OK
        )
    
    return Response(
        {'error': 'Failed to cancel subscription'},
        status=status.HTTP_400_BAD_REQUEST
    )


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def renew_subscription(request):
    """Renew an expired or active subscription"""
    serializer = SubscriptionRenewSerializer(
        data=request.data,
        context={'request': request}
    )
    
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    subscription = serializer.context['subscription']
    user = request.user
    plan = subscription.plan
    
    # Calculate new dates
    if subscription.status == 'ACTIVE':
        # If still active, extend from current end date
        start_date = subscription.end_date
    else:
        # If expired, start from now
        start_date = timezone.now()
    
    end_date = start_date + timezone.timedelta(days=plan.billing_period_days)
    
    # Calculate amount to pay
    amount_to_pay = plan.discounted_price
    
    with transaction.atomic():
        # Create a new subscription
        new_subscription = UserSubscription.objects.create(
            user=user,
            plan=plan,
            start_date=start_date,
            end_date=end_date,
            status='ACTIVE',
            is_auto_renew=subscription.is_auto_renew,
            amount_paid=amount_to_pay,
            payment_status='COMPLETED',  # Assuming payment is completed immediately
            payment_method=serializer.validated_data['payment_method'],
            payment_reference=serializer.validated_data.get('payment_reference', ''),
            created_by=user
        )
        
        # Create transaction record
        SubscriptionTransaction.objects.create(
            user=user,
            subscription=new_subscription,
            transaction_type='RENEWAL',
            amount=amount_to_pay,
            status='COMPLETED',
            payment_method=serializer.validated_data['payment_method'],
            payment_reference=serializer.validated_data.get('payment_reference', ''),
            created_by=user
        )
        
        # Set as user's current subscription
        user.current_subscription = new_subscription
        user.save()
    
    return Response(
        UserSubscriptionSerializer(new_subscription).data,
        status=status.HTTP_201_CREATED
    )


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_current_subscription(request):
    """Get the current active subscription for the user"""
    subscription = UserSubscription.objects.filter(
        user=request.user,
        status='ACTIVE',
        end_date__gt=timezone.now(),
        is_deleted=False
    ).select_related('plan').first()
    
    if not subscription:
        return Response(
            {'message': 'No active subscription found'},
            status=status.HTTP_404_NOT_FOUND
        )
    
    return Response(
        UserSubscriptionSerializer(subscription).data,
        status=status.HTTP_200_OK
    )