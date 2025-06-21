"""
URL patterns for books app
"""
from django.urls import path
from . import views

app_name = 'books'

urlpatterns = [
    # Categories, Authors, Publishers
    path('categories/', views.BookCategoryListView.as_view(), name='category-list'),
    path('authors/', views.AuthorListView.as_view(), name='author-list'),
    path('publishers/', views.PublisherListView.as_view(), name='publisher-list'),
    
    # Books
    path('', views.BookListView.as_view(), name='book-list'),
    path('search/', views.search_books, name='book-search'),
    path('<uuid:id>/', views.BookDetailView.as_view(), name='book-detail'),
    
    # Book Reservations
    path('reservations/', views.BookReservationListCreateView.as_view(), name='reservation-list'),
    path('reservations/<uuid:id>/', views.BookReservationDetailView.as_view(), name='reservation-detail'),
    path('reservations/<uuid:reservation_id>/renew/', views.renew_reservation, name='renew-reservation'),
    path('reservations/<uuid:reservation_id>/digital-access/', views.grant_digital_access, name='grant-digital-access'),
    
    # Digital Book Access
    path('digital/access/', views.access_digital_book, name='access-digital-book'),
    path('digital/<uuid:session_id>/content/', views.serve_digital_book, name='serve-digital-book'),
    
    # Reviews
    path('reviews/', views.BookReviewListCreateView.as_view(), name='review-list'),
    path('<uuid:book_id>/reviews/', views.BookReviewListCreateView.as_view(), name='book-reviews'),
    
    # Wishlist
    path('wishlist/', views.BookWishlistListCreateView.as_view(), name='wishlist'),
    path('wishlist/<uuid:id>/', views.BookWishlistDetailView.as_view(), name='wishlist-detail'),
    
    # Reading Lists
    path('reading-lists/', views.BookReadingListListCreateView.as_view(), name='reading-list'),
    path('reading-lists/<uuid:id>/', views.BookReadingListDetailView.as_view(), name='reading-list-detail'),
    path('reading-lists/<uuid:list_id>/add-book/', views.add_book_to_reading_list, name='add-book-to-list'),
    
    # Recommendations
    path('recommendations/', views.BookRecommendationListView.as_view(), name='recommendations'),
    
    # User Summary
    path('summary/', views.get_user_book_summary, name='book-summary'),
    
    # Admin Views
    path('admin/manage/', views.BookManagementView.as_view(), name='admin-book-management'),
    path('admin/statistics/', views.BookStatisticsView.as_view(), name='book-statistics'),
    path('admin/<uuid:book_id>/statistics/', views.BookStatisticsView.as_view(), name='book-detail-statistics'),
]