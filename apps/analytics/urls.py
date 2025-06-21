"""
URL patterns for analytics app
"""
from django.urls import path
from . import views

app_name = 'analytics'

urlpatterns = [
    path('dashboard/', views.get_dashboard_analytics, name='dashboard'),
    path('users/', views.get_user_analytics, name='users'),
    path('books/', views.get_book_analytics, name='books'),
    path('seats/', views.get_seat_analytics, name='seats'),
    path('events/', views.get_event_analytics, name='events'),
    path('libraries/', views.get_library_analytics, name='libraries'),
    path('subscriptions/', views.get_subscription_analytics, name='subscriptions'),
]