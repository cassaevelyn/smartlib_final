"""
URL patterns for seats app
"""
from django.urls import path
from . import views

app_name = 'seats'

urlpatterns = [
    # Seat Views
    path('', views.SeatListView.as_view(), name='seat-list'),
    path('search/', views.search_seats, name='seat-search'),
    path('<uuid:id>/', views.SeatDetailView.as_view(), name='seat-detail'),
    path('library/<uuid:library_id>/', views.SeatListView.as_view(), name='library-seats'),
    path('floor/<uuid:floor_id>/', views.SeatListView.as_view(), name='floor-seats'),
    path('section/<uuid:section_id>/', views.SeatListView.as_view(), name='section-seats'),
    
    # Seat Availability
    path('availability/check/', views.check_seat_availability, name='check-availability'),
    
    # Seat Bookings
    path('bookings/', views.SeatBookingListCreateView.as_view(), name='booking-list'),
    path('bookings/<uuid:id>/', views.SeatBookingDetailView.as_view(), name='booking-detail'),
    path('bookings/summary/', views.get_user_booking_summary, name='booking-summary'),
    
    # QR Code and Check-in/Check-out
    path('bookings/<uuid:booking_id>/qr-code/', views.generate_qr_code, name='generate-qr-code'),
    path('check-in/', views.check_in_seat, name='check-in'),
    path('check-out/', views.check_out_seat, name='check-out'),
    
    # Waitlist
    path('waitlist/', views.SeatBookingWaitlistListCreateView.as_view(), name='waitlist'),
    
    # Reviews
    path('reviews/', views.SeatReviewListCreateView.as_view(), name='review-list'),
    path('<uuid:seat_id>/reviews/', views.SeatReviewListCreateView.as_view(), name='seat-reviews'),
    
    # Admin Views
    path('admin/manage/', views.SeatManagementView.as_view(), name='admin-seat-management'),
    path('admin/maintenance/', views.SeatMaintenanceLogListCreateView.as_view(), name='maintenance-logs'),
    path('admin/<uuid:seat_id>/maintenance/', views.SeatMaintenanceLogListCreateView.as_view(), name='seat-maintenance'),
    path('admin/statistics/', views.SeatUsageStatisticsView.as_view(), name='usage-statistics'),
    path('admin/<uuid:seat_id>/statistics/', views.SeatUsageStatisticsView.as_view(), name='seat-statistics'),
]