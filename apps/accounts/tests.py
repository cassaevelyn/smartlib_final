"""
Tests for accounts app
"""
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from .models import UserProfile, LoyaltyTransaction, UserSession, UserVerification

User = get_user_model()


class UserModelTest(TestCase):
    """Test User model"""
    
    def setUp(self):
        self.user_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'crn': 'ICAP-CA-2023-1234',
            'first_name': 'Test',
            'last_name': 'User',
            'password': 'testpass123'
        }
    
    def test_create_user(self):
        """Test creating a user"""
        user = User.objects.create_user(**self.user_data)
        self.assertEqual(user.email, self.user_data['email'])
        self.assertEqual(user.crn, self.user_data['crn'])
        self.assertTrue(user.check_password(self.user_data['password']))
        self.assertFalse(user.is_approved)
        self.assertTrue(user.student_id)
    
    def test_create_superuser(self):
        """Test creating a superuser"""
        user = User.objects.create_superuser(**self.user_data)
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_superuser)
        self.assertTrue(user.is_approved)
        self.assertEqual(user.role, 'SUPER_ADMIN')
    
    def test_user_str_representation(self):
        """Test user string representation"""
        user = User.objects.create_user(**self.user_data)
        expected = f"{user.get_full_name()} ({user.crn})"
        self.assertEqual(str(user), expected)
    
    def test_user_properties(self):
        """Test user properties"""
        user = User.objects.create_user(**self.user_data)
        self.assertTrue(user.is_student)
        self.assertFalse(user.is_admin)
        self.assertFalse(user.is_super_admin)
        
        user.role = 'ADMIN'
        self.assertFalse(user.is_student)
        self.assertTrue(user.is_admin)
        self.assertFalse(user.is_super_admin)


class UserProfileTest(TestCase):
    """Test UserProfile model"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            crn='ICAP-CA-2023-1234',
            password='testpass123'
        )
    
    def test_profile_creation(self):
        """Test profile is created with user"""
        self.assertTrue(hasattr(self.user, 'profile'))
        self.assertIsInstance(self.user.profile, UserProfile)
    
    def test_add_loyalty_points(self):
        """Test adding loyalty points"""
        initial_points = self.user.profile.loyalty_points
        self.user.profile.add_loyalty_points(50, 'TEST_ACTIVITY')
        
        self.user.profile.refresh_from_db()
        self.assertEqual(self.user.profile.loyalty_points, initial_points + 50)
        
        # Check transaction was created
        transaction = LoyaltyTransaction.objects.filter(user=self.user).first()
        self.assertIsNotNone(transaction)
        self.assertEqual(transaction.points, 50)
        self.assertEqual(transaction.transaction_type, 'EARNED')
    
    def test_deduct_loyalty_points(self):
        """Test deducting loyalty points"""
        self.user.profile.loyalty_points = 100
        self.user.profile.save()
        
        result = self.user.profile.deduct_loyalty_points(30, 'Test deduction')
        self.assertTrue(result)
        
        self.user.profile.refresh_from_db()
        self.assertEqual(self.user.profile.loyalty_points, 70)
    
    def test_deduct_insufficient_points(self):
        """Test deducting more points than available"""
        self.user.profile.loyalty_points = 10
        self.user.profile.save()
        
        result = self.user.profile.deduct_loyalty_points(50, 'Test deduction')
        self.assertFalse(result)
        
        self.user.profile.refresh_from_db()
        self.assertEqual(self.user.profile.loyalty_points, 10)


class UserRegistrationAPITest(APITestCase):
    """Test user registration API"""
    
    def setUp(self):
        self.registration_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'crn': 'ICAP-CA-2023-1234',
            'first_name': 'Test',
            'last_name': 'User',
            'password': 'testpass123',
            'password_confirm': 'testpass123'
        }
        self.url = reverse('accounts:register')
    
    def test_successful_registration(self):
        """Test successful user registration"""
        response = self.client.post(self.url, self.registration_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        # Check user was created
        user = User.objects.get(email=self.registration_data['email'])
        self.assertEqual(user.crn, self.registration_data['crn'])
        self.assertFalse(user.is_approved)
        
        # Check profile was created
        self.assertTrue(hasattr(user, 'profile'))
    
    def test_invalid_crn_format(self):
        """Test registration with invalid CRN format"""
        self.registration_data['crn'] = 'INVALID-CRN'
        response = self.client.post(self.url, self.registration_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_password_mismatch(self):
        """Test registration with password mismatch"""
        self.registration_data['password_confirm'] = 'differentpass'
        response = self.client.post(self.url, self.registration_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_duplicate_email(self):
        """Test registration with duplicate email"""
        User.objects.create_user(
            username='existing',
            email=self.registration_data['email'],
            crn='ICAP-CA-2023-5678',
            password='pass123'
        )
        
        response = self.client.post(self.url, self.registration_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class UserLoginAPITest(APITestCase):
    """Test user login API"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            crn='ICAP-CA-2023-1234',
            password='testpass123',
            is_approved=True
        )
        self.login_data = {
            'email': 'test@example.com',
            'password': 'testpass123'
        }
        self.url = reverse('accounts:login')
    
    def test_successful_login(self):
        """Test successful login"""
        response = self.client.post(self.url, self.login_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Check response contains tokens and user data
        self.assertIn('access_token', response.data)
        self.assertIn('refresh_token', response.data)
        self.assertIn('user', response.data)
        self.assertIn('session_id', response.data)
        
        # Check user login count was updated
        self.user.refresh_from_db()
        self.assertEqual(self.user.login_count, 1)
    
    def test_invalid_credentials(self):
        """Test login with invalid credentials"""
        self.login_data['password'] = 'wrongpass'
        response = self.client.post(self.url, self.login_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_unapproved_user_login(self):
        """Test login with unapproved user"""
        self.user.is_approved = False
        self.user.save()
        
        response = self.client.post(self.url, self.login_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_inactive_user_login(self):
        """Test login with inactive user"""
        self.user.is_active = False
        self.user.save()
        
        response = self.client.post(self.url, self.login_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class UserProfileAPITest(APITestCase):
    """Test user profile API"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            crn='ICAP-CA-2023-1234',
            password='testpass123',
            is_approved=True
        )
        self.client.force_authenticate(user=self.user)
        self.url = reverse('accounts:profile')
    
    def test_get_profile(self):
        """Test getting user profile"""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], self.user.email)
    
    def test_update_profile(self):
        """Test updating user profile"""
        update_data = {
            'first_name': 'Updated',
            'last_name': 'Name',
            'bio': 'Updated bio'
        }
        response = self.client.patch(self.url, update_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, 'Updated')
        self.assertEqual(self.user.bio, 'Updated bio')
    
    def test_unauthorized_access(self):
        """Test unauthorized access to profile"""
        self.client.force_authenticate(user=None)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)