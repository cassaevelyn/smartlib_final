"""
URL patterns for recommendations app
"""
from django.urls import path
from . import views

app_name = 'recommendations'

urlpatterns = [
    path('books/', views.get_book_recommendations, name='book-recommendations'),
    path('events/', views.get_event_recommendations, name='event-recommendations'),
    path('seats/', views.get_seat_recommendations, name='seat-recommendations'),
    path('subscriptions/', views.get_subscription_recommendations, name='subscription-recommendations'),
]