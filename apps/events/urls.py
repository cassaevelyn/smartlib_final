"""
URL patterns for events app
"""
from django.urls import path
from . import views

app_name = 'events'

urlpatterns = [
    # Categories and Speakers
    path('categories/', views.EventCategoryListView.as_view(), name='category-list'),
    path('speakers/', views.EventSpeakerListView.as_view(), name='speaker-list'),
    
    # Events
    path('', views.EventListView.as_view(), name='event-list'),
    path('search/', views.search_events, name='event-search'),
    path('<uuid:id>/', views.EventDetailView.as_view(), name='event-detail'),
    
    # Event Registrations
    path('registrations/', views.EventRegistrationListCreateView.as_view(), name='registration-list'),
    path('registrations/<uuid:id>/', views.EventRegistrationDetailView.as_view(), name='registration-detail'),
    path('registrations/<uuid:registration_id>/qr-code/', views.generate_qr_code, name='generate-qr-code'),
    
    # Check-in/Check-out
    path('check-in/', views.check_in_event, name='check-in'),
    path('check-out/', views.check_out_event, name='check-out'),
    
    # Feedback
    path('feedback/', views.EventFeedbackListCreateView.as_view(), name='feedback-list'),
    path('<uuid:event_id>/feedback/', views.EventFeedbackListCreateView.as_view(), name='event-feedback'),
    
    # Resources
    path('<uuid:event_id>/resources/', views.EventResourceListView.as_view(), name='event-resources'),
    
    # Waitlist
    path('waitlist/', views.EventWaitlistListCreateView.as_view(), name='waitlist'),
    
    # Event Series
    path('series/', views.EventSeriesListView.as_view(), name='series-list'),
    
    # User Summary
    path('summary/', views.get_user_event_summary, name='event-summary'),
    
    # Admin Views
    path('admin/manage/', views.EventManagementView.as_view(), name='admin-event-management'),
    path('admin/<uuid:event_id>/bulk-check-in/', views.bulk_check_in, name='bulk-check-in'),
    path('admin/<uuid:event_id>/analytics/', views.event_analytics, name='event-analytics'),
]