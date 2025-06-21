"""
Tests for library app
"""
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from .models import (
    Library, LibraryFloor, LibrarySection, LibraryReview,
    LibraryConfiguration, LibraryNotification
)

User = get_user_model()


class LibraryModelTest(TestCase):
    """Test Library model"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            crn='ICAP-CA-2023-1234',
            password='testpass123'
        )
        
        self.library = Library.objects.create(
            name='Test Library',
            library_type='MAIN',
            address='123 Test Street',
            city='Test City',
            opening_time='08:00',
            closing_time='22:00',
            total_seats=100,
            created_by=self.user
        )
    
    def test_library_creation(self):
        """Test library is created correctly"""
        self.assertEqual(self.library.name, 'Test Library')
        self.assertTrue(self.library.code)  # Should auto-generate
        self.assertEqual(self.library.status, 'ACTIVE')  # Default status
    
    def test_library_str_representation(self):
        """Test library string representation"""
        expected = f"{self.library.name} ({self.library.code})"
        self.assertEqual(str(self.library), expected)
    
    def test_library_is_open_property(self):
        """Test library is_open property"""
        # Library should be open during operating hours
        self.library.status = 'ACTIVE'
        self.library.is_24_hours = False
        # Note: This test would need to mock the current time
        # for proper testing of time-based logic
    
    def test_occupancy_rate_calculation(self):
        """Test occupancy rate calculation"""
        # This would require creating seats and bookings
        # For now, test with zero seats
        rate = self.library.get_occupancy_rate()
        self.assertEqual(rate, 0)


class LibraryFloorTest(TestCase):
    """Test LibraryFloor model"""
    
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
        
        self.floor = LibraryFloor.objects.create(
            library=self.library,
            floor_number=1,
            floor_name='Ground Floor',
            total_seats=50,
            created_by=self.user
        )
    
    def test_floor_creation(self):
        """Test floor is created correctly"""
        self.assertEqual(self.floor.floor_number, 1)
        self.assertEqual(self.floor.floor_name, 'Ground Floor')
        self.assertEqual(self.floor.library, self.library)
    
    def test_floor_str_representation(self):
        """Test floor string representation"""
        expected = f"{self.library.name} - {self.floor.floor_name}"
        self.assertEqual(str(self.floor), expected)


class LibraryAPITest(APITestCase):
    """Test Library API endpoints"""
    
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
            library_type='MAIN',
            address='123 Test Street',
            city='Test City',
            opening_time='08:00',
            closing_time='22:00',
            total_seats=100,
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
    
    def test_library_list(self):
        """Test library list endpoint"""
        url = reverse('library:library-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['name'], 'Test Library')
    
    def test_library_detail(self):
        """Test library detail endpoint"""
        url = reverse('library:library-detail', kwargs={'id': self.library.id})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['name'], 'Test Library')
        self.assertIn('floors', response.data)
        self.assertIn('amenities', response.data)
    
    def test_library_search(self):
        """Test library search endpoint"""
        url = reverse('library:library-search')
        data = {
            'query': 'Test',
            'city': 'Test City'
        }
        response = self.client.post(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)
        self.assertEqual(response.data['results'][0]['name'], 'Test Library')
    
    def test_unauthorized_library_access(self):
        """Test accessing library without permission"""
        # Create another library without giving user access
        other_library = Library.objects.create(
            name='Other Library',
            address='456 Other Street',
            city='Other City',
            opening_time='09:00',
            closing_time='21:00',
            created_by=self.user
        )
        
        url = reverse('library:library-detail', kwargs={'id': other_library.id})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class LibraryReviewTest(APITestCase):
    """Test Library Review functionality"""
    
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
        
        # Give user access to library
        from apps.accounts.models import UserLibraryAccess
        UserLibraryAccess.objects.create(
            user=self.user,
            library=self.library,
            granted_by=self.user,
            created_by=self.user
        )
        
        self.client.force_authenticate(user=self.user)
    
    def test_create_review(self):
        """Test creating a library review"""
        url = reverse('library:library-reviews', kwargs={'library_id': self.library.id})
        data = {
            'rating': 5,
            'title': 'Great library!',
            'review_text': 'Very clean and quiet environment.',
            'cleanliness_rating': 5,
            'facilities_rating': 4
        }
        response = self.client.post(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(LibraryReview.objects.count(), 1)
        
        review = LibraryReview.objects.first()
        self.assertEqual(review.rating, 5)
        self.assertEqual(review.user, self.user)
        self.assertEqual(review.library, self.library)
    
    def test_duplicate_review_prevention(self):
        """Test that users can't review the same library twice"""
        # Create first review
        LibraryReview.objects.create(
            library=self.library,
            user=self.user,
            rating=4,
            review_text='First review',
            created_by=self.user
        )
        
        # Try to create second review
        url = reverse('library:library-reviews', kwargs={'library_id': self.library.id})
        data = {
            'rating': 5,
            'review_text': 'Second review'
        }
        response = self.client.post(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(LibraryReview.objects.count(), 1)
    
    def test_list_approved_reviews(self):
        """Test listing only approved reviews"""
        # Create approved review
        approved_review = LibraryReview.objects.create(
            library=self.library,
            user=self.user,
            rating=5,
            review_text='Approved review',
            is_approved=True,
            created_by=self.user
        )
        
        # Create unapproved review
        other_user = User.objects.create_user(
            username='otheruser',
            email='other@example.com',
            crn='ICAP-CA-2023-5678',
            password='testpass123'
        )
        
        LibraryReview.objects.create(
            library=self.library,
            user=other_user,
            rating=3,
            review_text='Unapproved review',
            is_approved=False,
            created_by=other_user
        )
        
        url = reverse('library:library-reviews', kwargs={'library_id': self.library.id})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['id'], str(approved_review.id))