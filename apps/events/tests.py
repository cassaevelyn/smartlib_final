"""
Tests for events app
"""
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APITestCase
from rest_framework import status
from datetime import date, time, timedelta
from apps.library.models import Library
from .models import (
    EventCategory, EventSpeaker, Event, EventRegistration,
    EventFeedback
)

User = get_user_model()


class EventModelTest(TestCase):
    """Test Event model"""
    
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
        
        self.category = EventCategory.objects.create(
            name='Workshop',
            created_by=self.user
        )
        
        self.speaker = EventSpeaker.objects.create(
            first_name='John',
            last_name='Doe',
            title='Dr.',
            organization='Test University',
            created_by=self.user
        )
        
        tomorrow = timezone.now().date() + timedelta(days=1)
        self.event = Event.objects.create(
            title='Test Workshop',
            category=self.category,
            event_type='WORKSHOP',
            description='A test workshop',
            organizer=self.user,
            start_date=tomorrow,
            end_date=tomorrow,
            start_time=time(10, 0),
            end_time=time(12, 0),
            library=self.library,
            registration_deadline=timezone.now() + timedelta(hours=12),
            max_participants=20,
            created_by=self.user
        )
        self.event.speakers.add(self.speaker)
    
    def test_event_creation(self):
        """Test event is created correctly"""
        self.assertEqual(self.event.title, 'Test Workshop')
        self.assertTrue(self.event.event_code)  # Should auto-generate
        self.assertEqual(self.event.status, 'DRAFT')  # Default status
    
    def test_event_str_representation(self):
        """Test event string representation"""
        expected = f"{self.event.title} ({self.event.event_code})"
        self.assertEqual(str(self.event), expected)
    
    def test_event_duration_calculation(self):
        """Test event duration calculation"""
        expected_duration = 2.0  # 2 hours
        self.assertEqual(self.event.duration_hours, expected_duration)
    
    def test_can_user_register(self):
        """Test user registration eligibility"""
        self.event.status = 'REGISTRATION_OPEN'
        self.event.save()
        
        can_register, message = self.event.can_user_register(self.user)
        self.assertTrue(can_register)
        self.assertEqual(message, "You can register for this event")
    
    def test_cannot_register_when_full(self):
        """Test registration when event is full"""
        self.event.status = 'REGISTRATION_OPEN'
        self.event.max_participants = 1
        self.event.total_registrations = 1
        self.event.save()
        
        can_register, message = self.event.can_user_register(self.user)
        self.assertFalse(can_register)
        self.assertEqual(message, "Event is full")
    
    def test_speakers_list_property(self):
        """Test speakers list property"""
        expected = "Dr. John Doe"
        self.assertEqual(self.event.speakers_list, expected)


class EventRegistrationModelTest(TestCase):
    """Test EventRegistration model"""
    
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
        
        self.category = EventCategory.objects.create(
            name='Workshop',
            created_by=self.user
        )
        
        tomorrow = timezone.now().date() + timedelta(days=1)
        self.event = Event.objects.create(
            title='Test Workshop',
            category=self.category,
            organizer=self.user,
            start_date=tomorrow,
            end_date=tomorrow,
            start_time=time(10, 0),
            end_time=time(12, 0),
            library=self.library,
            registration_deadline=timezone.now() + timedelta(hours=12),
            created_by=self.user
        )
        
        self.registration = EventRegistration.objects.create(
            user=self.user,
            event=self.event,
            created_by=self.user
        )
    
    def test_registration_creation(self):
        """Test registration is created correctly"""
        self.assertEqual(self.registration.user, self.user)
        self.assertEqual(self.registration.event, self.event)
        self.assertTrue(self.registration.registration_code)  # Should auto-generate
        self.assertEqual(self.registration.status, 'CONFIRMED')  # Default status
    
    def test_registration_str_representation(self):
        """Test registration string representation"""
        expected = f"{self.user.get_full_name()} - {self.event.title} ({self.registration.status})"
        self.assertEqual(str(self.registration), expected)
    
    def test_can_check_in(self):
        """Test check-in eligibility"""
        # Set event to start soon
        now = timezone.now()
        self.event.start_date = now.date()
        self.event.start_time = (now + timedelta(minutes=15)).time()
        self.event.save()
        
        self.assertTrue(self.registration.can_check_in)
    
    def test_check_in_process(self):
        """Test check-in process"""
        # Set event to current time
        now = timezone.now()
        self.event.start_date = now.date()
        self.event.start_time = now.time()
        self.event.save()
        
        success, message = self.registration.check_in()
        
        self.assertTrue(success)
        self.assertEqual(message, "Checked in successfully")
        self.assertEqual(self.registration.status, 'ATTENDED')
        self.assertIsNotNone(self.registration.check_in_time)
    
    def test_check_out_process(self):
        """Test check-out process"""
        # First check in
        now = timezone.now()
        self.event.start_date = now.date()
        self.event.start_time = now.time()
        self.event.save()
        
        self.registration.check_in()
        
        # Then check out
        success, message = self.registration.check_out()
        
        self.assertTrue(success)
        self.assertEqual(message, "Checked out successfully")
        self.assertIsNotNone(self.registration.check_out_time)
        self.assertIsNotNone(self.registration.attendance_duration)
    
    def test_cancel_registration(self):
        """Test registration cancellation"""
        success, message = self.registration.cancel_registration()
        
        self.assertTrue(success)
        self.assertEqual(message, "Registration cancelled successfully")
        self.assertEqual(self.registration.status, 'CANCELLED')


class EventAPITest(APITestCase):
    """Test Event API endpoints"""
    
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
        
        self.category = EventCategory.objects.create(
            name='Workshop',
            created_by=self.user
        )
        
        tomorrow = timezone.now().date() + timedelta(days=1)
        self.event = Event.objects.create(
            title='Test Workshop',
            category=self.category,
            event_type='WORKSHOP',
            status='REGISTRATION_OPEN',
            description='A test workshop',
            organizer=self.user,
            start_date=tomorrow,
            end_date=tomorrow,
            start_time=time(10, 0),
            end_time=time(12, 0),
            library=self.library,
            registration_deadline=timezone.now() + timedelta(hours=12),
            max_participants=20,
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
    
    def test_event_list(self):
        """Test event list endpoint"""
        url = reverse('events:event-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['title'], 'Test Workshop')
    
    def test_event_detail(self):
        """Test event detail endpoint"""
        url = reverse('events:event-detail', kwargs={'id': self.event.id})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['title'], 'Test Workshop')
        self.assertIn('category', response.data)
        self.assertIn('speakers', response.data)
    
    def test_event_search(self):
        """Test event search endpoint"""
        url = reverse('events:event-search')
        data = {
            'query': 'Test',
            'category_id': str(self.category.id)
        }
        response = self.client.post(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)
        self.assertEqual(response.data['results'][0]['title'], 'Test Workshop')
    
    def test_event_categories(self):
        """Test event categories endpoint"""
        url = reverse('events:category-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['name'], 'Workshop')


class EventRegistrationAPITest(APITestCase):
    """Test Event Registration API endpoints"""
    
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
        
        self.category = EventCategory.objects.create(
            name='Workshop',
            created_by=self.user
        )
        
        tomorrow = timezone.now().date() + timedelta(days=1)
        self.event = Event.objects.create(
            title='Test Workshop',
            category=self.category,
            status='REGISTRATION_OPEN',
            organizer=self.user,
            start_date=tomorrow,
            end_date=tomorrow,
            start_time=time(10, 0),
            end_time=time(12, 0),
            library=self.library,
            registration_deadline=timezone.now() + timedelta(hours=12),
            max_participants=20,
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
    
    def test_create_registration(self):
        """Test creating an event registration"""
        url = reverse('events:registration-list')
        data = {
            'event': str(self.event.id),
            'dietary_requirements': 'Vegetarian',
            'expectations': 'Learn new skills'
        }
        response = self.client.post(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(EventRegistration.objects.count(), 1)
        
        registration = EventRegistration.objects.first()
        self.assertEqual(registration.user, self.user)
        self.assertEqual(registration.event, self.event)
        self.assertEqual(registration.status, 'CONFIRMED')
    
    def test_list_user_registrations(self):
        """Test listing user's registrations"""
        # Create a registration
        EventRegistration.objects.create(
            user=self.user,
            event=self.event,
            created_by=self.user
        )
        
        url = reverse('events:registration-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)
    
    def test_generate_qr_code(self):
        """Test QR code generation"""
        # Create a registration
        registration = EventRegistration.objects.create(
            user=self.user,
            event=self.event,
            created_by=self.user
        )
        
        url = reverse('events:generate-qr-code', kwargs={'registration_id': registration.id})
        response = self.client.post(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('qr_data', response.data)
        self.assertIn('expires_at', response.data)
        
        # Check that registration was updated
        registration.refresh_from_db()
        self.assertIsNotNone(registration.qr_code_data)
        self.assertIsNotNone(registration.qr_code_expires_at)
    
    def test_event_summary(self):
        """Test user event summary"""
        url = reverse('events:event-summary')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('upcoming_registrations', response.data)
        self.assertIn('past_events', response.data)
        self.assertIn('statistics', response.data)


class EventFeedbackTest(APITestCase):
    """Test Event Feedback functionality"""
    
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
        
        self.category = EventCategory.objects.create(
            name='Workshop',
            created_by=self.user
        )
        
        yesterday = timezone.now().date() - timedelta(days=1)
        self.event = Event.objects.create(
            title='Test Workshop',
            category=self.category,
            status='COMPLETED',
            organizer=self.user,
            start_date=yesterday,
            end_date=yesterday,
            start_time=time(10, 0),
            end_time=time(12, 0),
            library=self.library,
            registration_deadline=timezone.now() - timedelta(hours=12),
            created_by=self.user
        )
        
        self.registration = EventRegistration.objects.create(
            user=self.user,
            event=self.event,
            status='ATTENDED',
            created_by=self.user
        )
        
        self.client.force_authenticate(user=self.user)
    
    def test_create_feedback(self):
        """Test creating event feedback"""
        url = reverse('events:event-feedback', kwargs={'event_id': self.event.id})
        data = {
            'registration': str(self.registration.id),
            'overall_rating': 5,
            'content_rating': 4,
            'speaker_rating': 5,
            'what_you_liked': 'Great content and presentation',
            'would_recommend': True
        }
        response = self.client.post(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(EventFeedback.objects.count(), 1)
        
        feedback = EventFeedback.objects.first()
        self.assertEqual(feedback.user, self.user)
        self.assertEqual(feedback.event, self.event)
        self.assertEqual(feedback.overall_rating, 5)
    
    def test_cannot_feedback_without_attendance(self):
        """Test that users can't provide feedback without attending"""
        # Create another user who didn't attend
        other_user = User.objects.create_user(
            username='otheruser',
            email='other@example.com',
            crn='ICAP-CA-2023-5678',
            password='testpass123',
            is_approved=True
        )
        
        self.client.force_authenticate(user=other_user)
        
        url = reverse('events:event-feedback', kwargs={'event_id': self.event.id})
        data = {
            'overall_rating': 5,
            'what_you_liked': 'Great event'
        }
        response = self.client.post(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(EventFeedback.objects.count(), 0)