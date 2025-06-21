"""
URL patterns for notifications app
"""
from django.urls import path
from . import views

app_name = 'notifications'

urlpatterns = [
    path('', views.NotificationListView.as_view(), name='notification-list'),
    path('<uuid:id>/', views.NotificationDetailView.as_view(), name='notification-detail'),
    path('<uuid:id>/read/', views.mark_notification_as_read, name='mark-as-read'),
    path('mark-all-read/', views.mark_all_notifications_as_read, name='mark-all-read'),
    path('unread-count/', views.unread_notification_count, name='unread-count'),
]