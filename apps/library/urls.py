"""
URL patterns for library app
"""
from django.urls import path
from . import views

app_name = 'library'

urlpatterns = [
    # Public Library Views
    path('', views.LibraryListView.as_view(), name='library-list'),
    path('search/', views.search_libraries, name='library-search'),
    path('<uuid:id>/', views.LibraryDetailView.as_view(), name='library-detail'),
    
    # Library Structure
    path('<uuid:library_id>/floors/', views.LibraryFloorListView.as_view(), name='library-floors'),
    path('floors/<uuid:floor_id>/sections/', views.LibrarySectionListView.as_view(), name='floor-sections'),
    
    # Reviews
    path('<uuid:library_id>/reviews/', views.LibraryReviewListCreateView.as_view(), name='library-reviews'),
    
    # Notifications
    path('<uuid:library_id>/notifications/', views.LibraryNotificationListView.as_view(), name='library-notifications'),
    path('notifications/<uuid:notification_id>/view/', views.mark_notification_viewed, name='mark-notification-viewed'),
    path('notifications/<uuid:notification_id>/acknowledge/', views.acknowledge_notification, name='acknowledge-notification'),
    
    # Admin Views
    path('admin/manage/', views.LibraryManagementView.as_view(), name='admin-library-management'),
    path('admin/<uuid:id>/', views.LibraryDetailManagementView.as_view(), name='admin-library-detail'),
    path('admin/<uuid:library_id>/statistics/', views.LibraryStatisticsView.as_view(), name='library-statistics'),
    path('admin/<uuid:library_id>/configuration/', views.LibraryConfigurationView.as_view(), name='library-configuration'),
    
    # Admin Floor Management
    path('admin/<uuid:library_id>/floors/', views.LibraryFloorManagementView.as_view(), name='admin-library-floors'),
    path('admin/floors/<uuid:id>/', views.LibraryFloorDetailManagementView.as_view(), name='admin-floor-detail'),
    
    # Admin Section Management
    path('admin/floors/<uuid:floor_id>/sections/', views.LibrarySectionManagementView.as_view(), name='admin-floor-sections'),
    path('admin/sections/<uuid:id>/', views.LibrarySectionDetailManagementView.as_view(), name='admin-section-detail'),
    
    # Admin Amenity Management
    path('admin/<uuid:library_id>/amenities/', views.LibraryAmenityManagementView.as_view(), name='admin-library-amenities'),
    path('admin/amenities/<uuid:id>/', views.LibraryAmenityDetailManagementView.as_view(), name='admin-amenity-detail'),
    
    # Admin Operating Hours Management
    path('admin/<uuid:library_id>/operating-hours/', views.LibraryOperatingHoursManagementView.as_view(), name='admin-library-operating-hours'),
    path('admin/operating-hours/<uuid:id>/', views.LibraryOperatingHoursDetailManagementView.as_view(), name='admin-operating-hours-detail'),
    
    # Admin Holiday Management
    path('admin/<uuid:library_id>/holidays/', views.LibraryHolidayManagementView.as_view(), name='admin-library-holidays'),
    path('admin/holidays/<uuid:id>/', views.LibraryHolidayDetailManagementView.as_view(), name='admin-holiday-detail'),
]
