"""
URL patterns for subscriptions app
"""
from django.urls import path
from . import views

app_name = 'subscriptions'

urlpatterns = [
    # Subscription Plans
    path('plans/', views.SubscriptionPlanListView.as_view(), name='plan-list'),
    path('plans/<uuid:id>/', views.SubscriptionPlanDetailView.as_view(), name='plan-detail'),
    
    # User Subscriptions
    path('my-subscriptions/', views.UserSubscriptionListView.as_view(), name='my-subscriptions'),
    path('my-subscriptions/<uuid:id>/', views.UserSubscriptionDetailView.as_view(), name='subscription-detail'),
    
    # Subscription Actions
    path('purchase/', views.purchase_subscription, name='purchase'),
    path('cancel/', views.cancel_subscription, name='cancel'),
    path('renew/', views.renew_subscription, name='renew'),
    
    # Transactions
    path('transactions/', views.SubscriptionTransactionListView.as_view(), name='transaction-list'),
    
    # Current Subscription
    path('current/', views.get_current_subscription, name='current'),
    
    # Benefits
    path('benefits/', views.SubscriptionBenefitListView.as_view(), name='benefit-list'),
]