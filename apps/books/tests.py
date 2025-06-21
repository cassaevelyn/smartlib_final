"""
Tests for books app
"""
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APITestCase
from rest_framework import status
from datetime import date, timedelta
from apps.library.models import Library
from .models import (
    BookCategory, Author, Publisher, Book, BookReservation,
    BookReview, BookWishlist
)

User = get_user_model()


class BookModelTest(TestCase):
    """Test Book model"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            crn='ICAP-CA-2023-1234',
            password='testpass123'
        )
        
        self.library = Library.objects.create(
            name='Test Library',
            address='123 Test Street',
            city='Test City',
            opening_time='08:00',
            closing_time='22:00',
            created_by=self.user
        )
        
        self.category = BookCategory.objects.create(
            name='Computer Science',
            created_by=self.user
        )
        
        self.author = Author.objects.create(
            first_name='John',
            last_name='Doe',
            created_by=self.user
        )
        
        self.publisher = Publisher.objects.create(
            name='Test Publisher',
            created_by=self.user
        )
        
        self.book = Book.objects.create(
            title='Test Book',
            isbn='1234567890',
            category=self.category,
            publisher=self.publisher,
            library=self.library,
            book_type='PHYSICAL',
            physical_copies=5,
            available_copies=5,
            created_by=self.user
        )
        self.book.authors.add(self.author)
    
    def test_book_creation(self):
        """Test book is created correctly"""
        self.assertEqual(self.book.title, 'Test Book')
        self.assertTrue(self.book.book_code)  # Should auto-generate
        self.assertEqual(self.book.status, 'AVAILABLE')  # Default status
        self.assertTrue(self.book.is_available)
    
    def test_book_str_representation(self):
        """Test book string representation"""
        expected = f"{self.book.title} ({self.book.book_code})"
        self.assertEqual(str(self.book), expected)
    
    def test_can_user_reserve_available_book(self):
        """Test reserving available book"""
        can_reserve, message = self.book.can_user_reserve(self.user, 'PHYSICAL')
        self.assertTrue(can_reserve)
        self.assertEqual(message, "Book can be reserved")
    
    def test_cannot_reserve_unavailable_book(self):
        """Test reserving unavailable book"""
        self.book.available_copies = 0
        self.book.save()
        
        can_reserve, message = self.book.can_user_reserve(self.user, 'PHYSICAL')
        self.assertFalse(can_reserve)
        self.assertEqual(message, "No physical copies available")
    
    def test_authors_list_property(self):
        """Test authors list property"""
        expected = "John Doe"
        self.assertEqual(self.book.authors_list, expected)


class BookReservationModelTest(TestCase):
    """Test BookReservation model"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            crn='ICAP-CA-2023-1234',
            password='testpass123'
        )
        
        self.library = Library.objects.create(
            name='Test Library',
            address='123 Test Street',
            city='Test City',
            opening_time='08:00',
            closing_time='22:00',
            created_by=self.user
        )
        
        self.category = BookCategory.objects.create(
            name='Computer Science',
            created_by=self.user
        )
        
        self.publisher = Publisher.objects.create(
            name='Test Publisher',
            created_by=self.user
        )
        
        self.book = Book.objects.create(
            title='Test Book',
            category=self.category,
            publisher=self.publisher,
            library=self.library,
            book_type='PHYSICAL',
            physical_copies=5,
            available_copies=5,
            created_by=self.user
        )
        
        self.reservation = BookReservation.objects.create(
            user=self.user,
            book=self.book,
            reservation_type='PHYSICAL',
            pickup_library=self.library,
            created_by=self.user
        )
    
    def test_reservation_creation(self):
        """Test reservation is created correctly"""
        self.assertEqual(self.reservation.user, self.user)
        self.assertEqual(self.reservation.book, self.book)
        self.assertTrue(self.reservation.reservation_code)  # Should auto-generate
        self.assertEqual(self.reservation.status, 'CONFIRMED')  # Default status
    
    def test_reservation_str_representation(self):
        """Test reservation string representation"""
        expected = f"{self.user.get_full_name()} - {self.book.title} ({self.reservation.status})"
        self.assertEqual(str(self.reservation), expected)
    
    def test_can_renew_reservation(self):
        """Test reservation renewal eligibility"""
        self.reservation.status = 'CHECKED_OUT'
        self.reservation.save()
        
        self.assertTrue(self.reservation.can_renew)
    
    def test_cannot_renew_overdue_reservation(self):
        """Test cannot renew overdue reservation"""
        self.reservation.status = 'CHECKED_OUT'
        self.reservation.due_date = timezone.now() - timedelta(days=1)
        self.reservation.save()
        
        self.assertFalse(self.reservation.can_renew)
    
    def test_grant_digital_access(self):
        """Test granting digital access"""
        digital_book = Book.objects.create(
            title='Digital Book',
            category=self.category,
            publisher=self.publisher,
            library=self.library,
            book_type='DIGITAL',
            created_by=self.user
        )
        
        digital_reservation = BookReservation.objects.create(
            user=self.user,
            book=digital_book,
            reservation_type='DIGITAL',
            created_by=self.user
        )
        
        success, message = digital_reservation.grant_digital_access()
        
        self.assertTrue(success)
        self.assertEqual(message, "Digital access granted")
        self.assertEqual(digital_reservation.status, 'CHECKED_OUT')
        self.assertIsNotNone(digital_reservation.digital_access_password)


class BookAPITest(APITestCase):
    """Test Book API endpoints"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            crn='ICAP-CA-2023-1234',
            password='testpass123',
            is_approved=True
        )
        
        self.library = Library.objects.create(
            name='Test Library',
            address='123 Test Street',
            city='Test City',
            opening_time='08:00',
            closing_time='22:00',
            created_by=self.user
        )
        
        self.category = BookCategory.objects.create(
            name='Computer Science',
            created_by=self.user
        )
        
        self.publisher = Publisher.objects.create(
            name='Test Publisher',
            created_by=self.user
        )
        
        self.book = Book.objects.create(
            title='Test Book',
            category=self.category,
            publisher=self.publisher,
            library=self.library,
            book_type='PHYSICAL',
            physical_copies=5,
            available_copies=5,
            created_by=self.user
        )
        
        # Give user access to library
        from apps.accounts.models import UserLibraryAccess
        UserLibraryAccess.objects.create(
            user=self.user,
            library=self.library,
            granted_by=self.user,
            created_by=self.user
        )
        
        self.client.force_authenticate(user=self.user)
    
    def test_book_list(self):
        """Test book list endpoint"""
        url = reverse('books:book-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['title'], 'Test Book')
    
    def test_book_detail(self):
        """Test book detail endpoint"""
        url = reverse('books:book-detail', kwargs={'id': self.book.id})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['title'], 'Test Book')
        self.assertIn('category', response.data)
        self.assertIn('authors', response.data)
    
    def test_book_search(self):
        """Test book search endpoint"""
        url = reverse('books:book-search')
        data = {
            'query': 'Test',
            'category_id': str(self.category.id)
        }
        response = self.client.post(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)
        self.assertEqual(response.data['results'][0]['title'], 'Test Book')
    
    def test_book_categories(self):
        """Test book categories endpoint"""
        url = reverse('books:category-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['name'], 'Computer Science')


class BookReservationAPITest(APITestCase):
    """Test Book Reservation API endpoints"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            crn='ICAP-CA-2023-1234',
            password='testpass123',
            is_approved=True
        )
        
        self.library = Library.objects.create(
            name='Test Library',
            address='123 Test Street',
            city='Test City',
            opening_time='08:00',
            closing_time='22:00',
            created_by=self.user
        )
        
        self.category = BookCategory.objects.create(
            name='Computer Science',
            created_by=self.user
        )
        
        self.publisher = Publisher.objects.create(
            name='Test Publisher',
            created_by=self.user
        )
        
        self.book = Book.objects.create(
            title='Test Book',
            category=self.category,
            publisher=self.publisher,
            library=self.library,
            book_type='PHYSICAL',
            physical_copies=5,
            available_copies=5,
            created_by=self.user
        )
        
        # Give user access to library
        from apps.accounts.models import UserLibraryAccess
        UserLibraryAccess.objects.create(
            user=self.user,
            library=self.library,
            granted_by=self.user,
            created_by=self.user
        )
        
        self.client.force_authenticate(user=self.user)
    
    def test_create_reservation(self):
        """Test creating a book reservation"""
        url = reverse('books:reservation-list')
        data = {
            'book': str(self.book.id),
            'reservation_type': 'PHYSICAL',
            'pickup_library': str(self.library.id),
            'purpose': 'Study'
        }
        response = self.client.post(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(BookReservation.objects.count(), 1)
        
        reservation = BookReservation.objects.first()
        self.assertEqual(reservation.user, self.user)
        self.assertEqual(reservation.book, self.book)
        self.assertEqual(reservation.status, 'CONFIRMED')
    
    def test_list_user_reservations(self):
        """Test listing user's reservations"""
        # Create a reservation
        BookReservation.objects.create(
            user=self.user,
            book=self.book,
            reservation_type='PHYSICAL',
            pickup_library=self.library,
            created_by=self.user
        )
        
        url = reverse('books:reservation-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)
    
    def test_renew_reservation(self):
        """Test renewing a reservation"""
        # Create a checked out reservation
        reservation = BookReservation.objects.create(
            user=self.user,
            book=self.book,
            reservation_type='PHYSICAL',
            pickup_library=self.library,
            status='CHECKED_OUT',
            created_by=self.user
        )
        
        url = reverse('books:renew-reservation', kwargs={'reservation_id': reservation.id})
        response = self.client.post(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('message', response.data)
        
        reservation.refresh_from_db()
        self.assertEqual(reservation.renewal_count, 1)
    
    def test_book_summary(self):
        """Test user book summary"""
        url = reverse('books:book-summary')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('current_reservations', response.data)
        self.assertIn('overdue_reservations', response.data)
        self.assertIn('statistics', response.data)


class BookWishlistTest(APITestCase):
    """Test Book Wishlist functionality"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            crn='ICAP-CA-2023-1234',
            password='testpass123',
            is_approved=True
        )
        
        self.library = Library.objects.create(
            name='Test Library',
            address='123 Test Street',
            city='Test City',
            opening_time='08:00',
            closing_time='22:00',
            created_by=self.user
        )
        
        self.category = BookCategory.objects.create(
            name='Computer Science',
            created_by=self.user
        )
        
        self.publisher = Publisher.objects.create(
            name='Test Publisher',
            created_by=self.user
        )
        
        self.book = Book.objects.create(
            title='Test Book',
            category=self.category,
            publisher=self.publisher,
            library=self.library,
            created_by=self.user
        )
        
        self.client.force_authenticate(user=self.user)
    
    def test_add_to_wishlist(self):
        """Test adding book to wishlist"""
        url = reverse('books:wishlist')
        data = {
            'book_id': str(self.book.id),
            'priority': 1,
            'notes': 'Want to read this book'
        }
        response = self.client.post(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(BookWishlist.objects.count(), 1)
        
        wishlist_item = BookWishlist.objects.first()
        self.assertEqual(wishlist_item.user, self.user)
        self.assertEqual(wishlist_item.book, self.book)
        self.assertEqual(wishlist_item.priority, 1)
    
    def test_list_wishlist(self):
        """Test listing user's wishlist"""
        # Add book to wishlist
        BookWishlist.objects.create(
            user=self.user,
            book=self.book,
            priority=1,
            created_by=self.user
        )
        
        url = reverse('books:wishlist')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['book']['title'], 'Test Book')