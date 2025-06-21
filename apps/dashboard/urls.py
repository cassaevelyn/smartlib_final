"""
URL patterns for dashboard app
"""
from django.urls import path
from . import views

app_name = 'dashboard'

urlpatterns = [
    path('stats/', views.DashboardStatsView.as_view(), name='stats'),
    path('activities/', views.RecentActivityListView.as_view(), name='activities'),
]