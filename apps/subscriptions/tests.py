"""
Tests for subscriptions app
"""
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APITestCase
from rest_framework import status
from datetime import timedelta
from .models import SubscriptionPlan, UserSubscription, SubscriptionTransaction

User = get_user_model()


class SubscriptionPlanModelTest(TestCase):
    """Test SubscriptionPlan model"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            crn='ICAP-CA-2023-1234',
            password='testpass123'
        )
        
        self.plan = SubscriptionPlan.objects.create(
            name='Premium Plan',
            plan_type='PREMIUM',
            description='Premium features for power users',
            price=1000.00,
            discount_percentage=10.00,
            billing_period='MONTHLY',
            max_book_reservations=10,
            max_seat_bookings=3,
            has_premium_seat_access=True,
            has_premium_book_access=True,
            created_by=self.user
        )
    
    def test_plan_creation(self):
        """Test plan is created correctly"""
        self.assertEqual(self.plan.name, 'Premium Plan')
        self.assertTrue(self.plan.code)  # Should auto-generate
        self.assertEqual(self.plan.plan_type, 'PREMIUM')
        self.assertEqual(self.plan.price, 1000.00)
    
    def test_discounted_price_calculation(self):
        """Test discounted price calculation"""
        expected_discount = 1000 * 0.1  # 10% of 1000
        expected_price = 1000 - expected_discount
        self.assertEqual(self.plan.discounted_price, expected_price)
    
    def test_billing_period_days(self):
        """Test billing period days calculation"""
        self.assertEqual(self.plan.billing_period_days, 30)  # Monthly
        
        self.plan.billing_period = 'QUARTERLY'
        self.assertEqual(self.plan.billing_period_days, 90)
        
        self.plan.billing_period = 'SEMI_ANNUAL'
        self.assertEqual(self.plan.billing_period_days, 180)
        
        self.plan.billing_period = 'ANNUAL'
        self.assertEqual(self.plan.billing_period_days, 365)


class UserSubscriptionModelTest(TestCase):
    """Test UserSubscription model"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            crn='ICAP-CA-2023-1234',
            password='testpass123'
        )
        
        self.plan = SubscriptionPlan.objects.create(
            name='Premium Plan',
            plan_type='PREMIUM',
            description='Premium features for power users',
            price=1000.00,
            billing_period='MONTHLY',
            created_by=self.user
        )
        
        self.subscription = UserSubscription.objects.create(
            user=self.user,
            plan=self.plan,
            start_date=timezone.now(),
            end_date=timezone.now() + timedelta(days=30),
            status='ACTIVE',
            amount_paid=1000.00,
            payment_status='COMPLETED',
            created_by=self.user
        )
    
    def test_subscription_creation(self):
        """Test subscription is created correctly"""
        self.assertEqual(self.subscription.user, self.user)
        self.assertEqual(self.subscription.plan, self.plan)
        self.assertTrue(self.subscription.subscription_code)  # Should auto-generate
        self.assertEqual(self.subscription.status, 'ACTIVE')
    
    def test_is_active_property(self):
        """Test is_active property"""
        self.assertTrue(self.subscription.is_active)
        
        # Test with expired subscription
        expired_subscription = UserSubscription.objects.create(
            user=self.user,
            plan=self.plan,
            start_date=timezone.now() - timedelta(days=60),
            end_date=timezone.now() - timedelta(days=30),
            status='ACTIVE',
            amount_paid=1000.00,
            payment_status='COMPLETED',
            created_by=self.user
        )
        self.assertFalse(expired_subscription.is_active)
        
        # Test with non-active status
        cancelled_subscription = UserSubscription.objects.create(
            user=self.user,
            plan=self.plan,
            start_date=timezone.now(),
            end_date=timezone.now() + timedelta(days=30),
            status='CANCELLED',
            amount_paid=1000.00,
            payment_status='COMPLETED',
            created_by=self.user
        )
        self.assertFalse(cancelled_subscription.is_active)
    
    def test_days_remaining_property(self):
        """Test days_remaining property"""
        # This will be approximate due to time differences
        self.assertAlmostEqual(self.subscription.days_remaining, 30, delta=1)
    
    def test_percentage_remaining_property(self):
        """Test percentage_remaining property"""
        # This will be approximate due to time differences
        self.assertAlmostEqual(self.subscription.percentage_remaining, 100, delta=1)
    
    def test_cancel_method(self):
        """Test cancel method"""
        self.assertTrue(self.subscription.cancel())
        self.assertEqual(self.subscription.status, 'CANCELLED')
        self.assertIsNotNone(self.subscription.cancelled_at)
        self.assertFalse(self.subscription.is_auto_renew)


class SubscriptionAPITest(APITestCase):
    """Test Subscription API endpoints"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            crn='ICAP-CA-2023-1234',
            password='testpass123',
            is_approved=True
        )
        
        self.plan = SubscriptionPlan.objects.create(
            name='Premium Plan',
            plan_type='PREMIUM',
            description='Premium features for power users',
            price=1000.00,
            billing_period='MONTHLY',
            created_by=self.user
        )
        
        self.client.force_authenticate(user=self.user)
    
    def test_list_plans(self):
        """Test listing subscription plans"""
        url = reverse('subscriptions:plan-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['name'], 'Premium Plan')
    
    def test_purchase_subscription(self):
        """Test purchasing a subscription"""
        url = reverse('subscriptions:purchase')
        data = {
            'plan_id': str(self.plan.id),
            'payment_method': 'CREDIT_CARD',
            'payment_reference': 'TEST-PAYMENT-123',
        }
        response = self.client.post(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        # Check that subscription was created
        subscription = UserSubscription.objects.get(user=self.user, plan=self.plan)
        self.assertEqual(subscription.status, 'ACTIVE')
        self.assertEqual(subscription.payment_status, 'COMPLETED')
        
        # Check that transaction was created
        transaction = SubscriptionTransaction.objects.get(subscription=subscription)
        self.assertEqual(transaction.transaction_type, 'PURCHASE')
        self.assertEqual(transaction.status, 'COMPLETED')
    
    def test_cancel_subscription(self):
        """Test cancelling a subscription"""
        # First create a subscription
        subscription = UserSubscription.objects.create(
            user=self.user,
            plan=self.plan,
            start_date=timezone.now(),
            end_date=timezone.now() + timedelta(days=30),
            status='ACTIVE',
            amount_paid=1000.00,
            payment_status='COMPLETED',
            created_by=self.user
        )
        
        url = reverse('subscriptions:cancel')
        data = {
            'subscription_id': str(subscription.id),
            'cancellation_reason': 'Testing cancellation',
        }
        response = self.client.post(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Check that subscription was cancelled
        subscription.refresh_from_db()
        self.assertEqual(subscription.status, 'CANCELLED')
        self.assertIsNotNone(subscription.cancelled_at)
        self.assertFalse(subscription.is_auto_renew)
    
    def test_get_current_subscription(self):
        """Test getting current subscription"""
        # Create an active subscription
        subscription = UserSubscription.objects.create(
            user=self.user,
            plan=self.plan,
            start_date=timezone.now(),
            end_date=timezone.now() + timedelta(days=30),
            status='ACTIVE',
            amount_paid=1000.00,
            payment_status='COMPLETED',
            created_by=self.user
        )
        
        url = reverse('subscriptions:current')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['id'], str(subscription.id))
        self.assertEqual(response.data['status'], 'ACTIVE')