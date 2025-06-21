"""
Tests for seats app
"""
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APITestCase
from rest_framework import status
from datetime import date, time, timedelta
from apps.library.models import Library, LibraryFloor, LibrarySection
from .models import Seat, SeatBooking, SeatReview

User = get_user_model()


class SeatModelTest(TestCase):
    """Test Seat model"""
    
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
            created_by=self.user
        )
        
        self.section = LibrarySection.objects.create(
            floor=self.floor,
            name='Silent Study',
            section_type='SILENT',
            created_by=self.user
        )
        
        self.seat = Seat.objects.create(
            library=self.library,
            floor=self.floor,
            section=self.section,
            seat_number='S001',
            seat_type='INDIVIDUAL',
            created_by=self.user
        )
    
    def test_seat_creation(self):
        """Test seat is created correctly"""
        self.assertEqual(self.seat.seat_number, 'S001')
        self.assertTrue(self.seat.seat_code)  # Should auto-generate
        self.assertEqual(self.seat.status, 'AVAILABLE')  # Default status
        self.assertTrue(self.seat.is_available)
    
    def test_seat_str_representation(self):
        """Test seat string representation"""
        expected = f"{self.library.name} - {self.seat.seat_number} ({self.seat.seat_code})"
        self.assertEqual(str(self.seat), expected)
    
    def test_can_user_book_available_seat(self):
        """Test booking available seat"""
        tomorrow = timezone.now().date() + timedelta(days=1)
        start_time = time(10, 0)
        end_time = time(12, 0)
        
        can_book, message = self.seat.can_user_book(
            self.user, start_time, end_time, tomorrow
        )
        
        self.assertTrue(can_book)
        self.assertEqual(message, "Seat can be booked")
    
    def test_cannot_book_unavailable_seat(self):
        """Test booking unavailable seat"""
        self.seat.status = 'MAINTENANCE'
        self.seat.save()
        
        tomorrow = timezone.now().date() + timedelta(days=1)
        start_time = time(10, 0)
        end_time = time(12, 0)
        
        can_book, message = self.seat.can_user_book(
            self.user, start_time, end_time, tomorrow
        )
        
        self.assertFalse(can_book)
        self.assertEqual(message, "Seat is not available")


class SeatBookingModelTest(TestCase):
    """Test SeatBooking model"""
    
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
            created_by=self.user
        )
        
        self.section = LibrarySection.objects.create(
            floor=self.floor,
            name='Silent Study',
            section_type='SILENT',
            created_by=self.user
        )
        
        self.seat = Seat.objects.create(
            library=self.library,
            floor=self.floor,
            section=self.section,
            seat_number='S001',
            created_by=self.user
        )
        
        self.booking = SeatBooking.objects.create(
            user=self.user,
            seat=self.seat,
            booking_date=timezone.now().date() + timedelta(days=1),
            start_time=time(10, 0),
            end_time=time(12, 0),
            created_by=self.user
        )
    
    def test_booking_creation(self):
        """Test booking is created correctly"""
        self.assertEqual(self.booking.user, self.user)
        self.assertEqual(self.booking.seat, self.seat)
        self.assertTrue(self.booking.booking_code)  # Should auto-generate
        self.assertEqual(self.booking.status, 'CONFIRMED')  # Default status
    
    def test_booking_duration_calculation(self):
        """Test booking duration calculation"""
        expected_duration = 2.0  # 2 hours
        self.assertEqual(self.booking.duration_hours, expected_duration)
    
    def test_check_in_process(self):
        """Test check-in process"""
        # Initially should be able to check in
        self.assertTrue(self.booking.can_check_in)
        
        # Perform check-in
        success, message = self.booking.check_in()
        
        self.assertTrue(success)
        self.assertEqual(message, "Checked in successfully")
        self.assertEqual(self.booking.status, 'CHECKED_IN')
        self.assertIsNotNone(self.booking.checked_in_at)
        
        # Seat should be occupied
        self.seat.refresh_from_db()
        self.assertEqual(self.seat.status, 'OCCUPIED')
    
    def test_check_out_process(self):
        """Test check-out process"""
        # First check in
        self.booking.check_in()
        
        # Should be able to check out
        self.assertTrue(self.booking.can_check_out)
        
        # Perform check-out
        success, message = self.booking.check_out()
        
        self.assertTrue(success)
        self.assertEqual(message, "Checked out successfully")
        self.assertEqual(self.booking.status, 'COMPLETED')
        self.assertIsNotNone(self.booking.checked_out_at)
        
        # Seat should be available
        self.seat.refresh_from_db()
        self.assertEqual(self.seat.status, 'AVAILABLE')
    
    def test_cancel_booking(self):
        """Test booking cancellation"""
        success, message = self.booking.cancel_booking()
        
        self.assertTrue(success)
        self.assertEqual(message, "Booking cancelled successfully")
        self.assertEqual(self.booking.status, 'CANCELLED')


class SeatAPITest(APITestCase):
    """Test Seat API endpoints"""
    
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
        
        self.floor = LibraryFloor.objects.create(
            library=self.library,
            floor_number=1,
            floor_name='Ground Floor',
            created_by=self.user
        )
        
        self.section = LibrarySection.objects.create(
            floor=self.floor,
            name='Silent Study',
            section_type='SILENT',
            created_by=self.user
        )
        
        self.seat = Seat.objects.create(
            library=self.library,
            floor=self.floor,
            section=self.section,
            seat_number='S001',
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
    
    def test_seat_list(self):
        """Test seat list endpoint"""
        url = reverse('seats:seat-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['seat_number'], 'S001')
    
    def test_seat_detail(self):
        """Test seat detail endpoint"""
        url = reverse('seats:seat-detail', kwargs={'id': self.seat.id})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['seat_number'], 'S001')
    
    def test_seat_search(self):
        """Test seat search endpoint"""
        url = reverse('seats:seat-search')
        data = {
            'library_id': str(self.library.id),
            'seat_type': 'INDIVIDUAL'
        }
        response = self.client.post(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)
        self.assertEqual(response.data['results'][0]['seat_number'], 'S001')
    
    def test_check_availability(self):
        """Test seat availability check"""
        url = reverse('seats:check-availability')
        tomorrow = timezone.now().date() + timedelta(days=1)
        data = {
            'seat_id': str(self.seat.id),
            'date': tomorrow.isoformat(),
            'start_time': '10:00',
            'end_time': '12:00'
        }
        response = self.client.post(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['available'])


class SeatBookingAPITest(APITestCase):
    """Test Seat Booking API endpoints"""
    
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
        
        self.floor = LibraryFloor.objects.create(
            library=self.library,
            floor_number=1,
            floor_name='Ground Floor',
            created_by=self.user
        )
        
        self.section = LibrarySection.objects.create(
            floor=self.floor,
            name='Silent Study',
            section_type='SILENT',
            created_by=self.user
        )
        
        self.seat = Seat.objects.create(
            library=self.library,
            floor=self.floor,
            section=self.section,
            seat_number='S001',
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
    
    def test_create_booking(self):
        """Test creating a seat booking"""
        url = reverse('seats:booking-list')
        tomorrow = timezone.now().date() + timedelta(days=1)
        data = {
            'seat': str(self.seat.id),
            'booking_date': tomorrow.isoformat(),
            'start_time': '10:00',
            'end_time': '12:00',
            'purpose': 'Study session'
        }
        response = self.client.post(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(SeatBooking.objects.count(), 1)
        
        booking = SeatBooking.objects.first()
        self.assertEqual(booking.user, self.user)
        self.assertEqual(booking.seat, self.seat)
        self.assertEqual(booking.status, 'CONFIRMED')
    
    def test_list_user_bookings(self):
        """Test listing user's bookings"""
        # Create a booking
        tomorrow = timezone.now().date() + timedelta(days=1)
        SeatBooking.objects.create(
            user=self.user,
            seat=self.seat,
            booking_date=tomorrow,
            start_time=time(10, 0),
            end_time=time(12, 0),
            created_by=self.user
        )
        
        url = reverse('seats:booking-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)
    
    def test_generate_qr_code(self):
        """Test QR code generation"""
        # Create a booking
        tomorrow = timezone.now().date() + timedelta(days=1)
        booking = SeatBooking.objects.create(
            user=self.user,
            seat=self.seat,
            booking_date=tomorrow,
            start_time=time(10, 0),
            end_time=time(12, 0),
            created_by=self.user
        )
        
        url = reverse('seats:generate-qr-code', kwargs={'booking_id': booking.id})
        response = self.client.post(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('qr_data', response.data)
        self.assertIn('expires_at', response.data)
        
        # Check that booking was updated
        booking.refresh_from_db()
        self.assertIsNotNone(booking.qr_code_data)
        self.assertIsNotNone(booking.qr_code_expires_at)
    
    def test_booking_summary(self):
        """Test user booking summary"""
        url = reverse('seats:booking-summary')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('current_bookings', response.data)
        self.assertIn('upcoming_bookings', response.data)
        self.assertIn('recent_bookings', response.data)
        self.assertIn('statistics', response.data)