"""
Views for accounts app
"""
from rest_framework import generics, status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import login, logout
from django.utils import timezone
from django.db import transaction, models
from django.shortcuts import redirect
from django.conf import settings
from apps.core.permissions import IsOwnerOrReadOnly, IsAdminUser, IsSuperAdminUser
from apps.core.utils import get_user_ip, send_notification_email, generate_secure_token, generate_numeric_otp
from apps.core.models import ActivityLog
from apps.library.models import Library
from .models import (
    User, UserProfile, LoyaltyTransaction, UserSession,
    UserVerification, UserPreference, UserLibraryAccess, AdminProfile
)
from .serializers import (
    UserRegistrationSerializer, UserLoginSerializer, UserSerializer,
    UserProfileSerializer, LoyaltyTransactionSerializer, UserSessionSerializer,
    UserVerificationSerializer, UserPreferenceSerializer, UserLibraryAccessSerializer,
    AdminProfileSerializer, PasswordChangeSerializer, PasswordResetSerializer,
    PasswordResetConfirmSerializer, LibraryApplicationSerializer, 
    SendOtpSerializer, VerifyOtpSerializer, UserAdminUpdateSerializer,
    UserLibraryAccessAdminSerializer
)
from datetime import timedelta
from .tasks import send_welcome_email, send_account_activation_email


class UserRegistrationView(generics.CreateAPIView):
    """User registration endpoint"""
    queryset = User.objects.all()
    serializer_class = UserRegistrationSerializer
    permission_classes = [permissions.AllowAny]
    
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        with transaction.atomic():
            user = serializer.save()
            
            # Create verification token and code
            token = generate_secure_token()
            code = generate_numeric_otp(6)
            
            # Create verification record
            verification = UserVerification.objects.create(
                user=user,
                verification_type='ACCOUNT_ACTIVATION',
                token=token,
                code=code,
                expires_at=timezone.now() + timedelta(hours=24),
                attempts=0
            )
            
            # Send activation email
            send_account_activation_email.delay(
                str(user.id), 
                token, 
                code
            )
            
            # Log activity
            ActivityLog.objects.create(
                user=user,
                activity_type='PROFILE_UPDATE',
                description='User registered and verification email sent',
                metadata={
                    'verification_type': 'ACCOUNT_ACTIVATION',
                }
            )
        
        return Response({
            'message': 'Registration successful. Please check your email to verify your account.',
            'user_id': user.id
        }, status=status.HTTP_201_CREATED)


@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def login_view(request):
    """User login endpoint"""
    serializer = UserLoginSerializer(data=request.data, context={'request': request})
    
    try:
        serializer.is_valid(raise_exception=True)
    except serializers.ValidationError as e:
        # Check if this is the special 'account_not_active' error
        if e.get_codes() == {'non_field_errors': ['account_not_active']}:
            # Get the user by email
            try:
                user = User.objects.get(email=request.data.get('email'))
                
                # Generate a new verification token and code
                token = generate_secure_token()
                code = generate_numeric_otp(6)
                
                # Create or update verification record
                verification, created = UserVerification.objects.get_or_create(
                    user=user,
                    verification_type='ACCOUNT_ACTIVATION',
                    is_verified=False,
                    defaults={
                        'token': token,
                        'code': code,
                        'expires_at': timezone.now() + timedelta(hours=24),
                        'attempts': 0
                    }
                )
                
                if not created:
                    # Update existing verification
                    verification.token = token
                    verification.code = code
                    verification.expires_at = timezone.now() + timedelta(hours=24)
                    verification.attempts = 0
                    verification.save()
                
                # Send activation email
                send_account_activation_email.delay(
                    str(user.id), 
                    token, 
                    code
                )
                
                # Log activity
                ActivityLog.objects.create(
                    user=user,
                    activity_type='PROFILE_UPDATE',
                    description='Account activation email resent during login attempt',
                    metadata={
                        'verification_type': 'ACCOUNT_ACTIVATION',
                    }
                )
                
                return Response({
                    'message': 'Your account is not active. A verification email has been sent to your email address.',
                    'code': 'account_not_active'
                }, status=status.HTTP_400_BAD_REQUEST)
                
            except User.DoesNotExist:
                pass
        
        # For other validation errors, just raise them
        raise e
    
    user = serializer.validated_data['user']
    
    # Update login tracking
    user.login_count += 1
    user.last_login_ip = get_user_ip(request)
    user.save()
    
    # Create user session
    session = UserSession.objects.create(
        user=user,
        session_key=request.session.session_key or generate_secure_token()[:40],
        ip_address=get_user_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', ''),
        device_info={
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
            'accept_language': request.META.get('HTTP_ACCEPT_LANGUAGE', ''),
        }
    )
    
    # Generate JWT tokens
    refresh = RefreshToken.for_user(user)
    access_token = refresh.access_token
    
    # Add custom claims
    access_token['role'] = user.role
    access_token['student_id'] = user.student_id
    
    return Response({
        'access_token': str(access_token),
        'refresh_token': str(refresh),
        'user': UserSerializer(user).data,
        'session_id': session.id
    })


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def logout_view(request):
    """User logout endpoint"""
    try:
        # End user session
        session_key = request.data.get('session_id')
        if session_key:
            try:
                session = UserSession.objects.get(id=session_key, user=request.user)
                session.end_session()
            except UserSession.DoesNotExist:
                pass
        
        # Blacklist refresh token if provided
        refresh_token = request.data.get('refresh_token')
        if refresh_token:
            try:
                token = RefreshToken(refresh_token)
                token.blacklist()
            except Exception:
                pass
        
        return Response({'message': 'Logout successful'})
    except Exception as e:
        return Response(
            {'error': 'Logout failed'},
            status=status.HTTP_400_BAD_REQUEST
        )


@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def send_otp_view(request):
    """Send OTP for account activation"""
    serializer = SendOtpSerializer(data=request.data, context={'request': request})
    serializer.is_valid(raise_exception=True)
    
    user = serializer.context.get('user')
    verification = serializer.context.get('verification')
    
    # Check if user is already active
    if user.is_active:
        return Response({
            'message': 'Your account is already active. You can now log in.',
            'user_id': str(user.id)
        })
    
    # If verification doesn't exist, create a new one
    if not verification:
        # Generate a token and 6-digit OTP
        token = generate_secure_token()
        otp_code = generate_numeric_otp(6)
        
        verification = UserVerification.objects.create(
            user=user,
            verification_type='ACCOUNT_ACTIVATION',
            token=token,
            code=otp_code,
            expires_at=timezone.now() + timedelta(hours=24),  # Expires in 24 hours
            attempts=0
        )
    else:
        # Generate a new token and OTP code
        token = generate_secure_token()
        otp_code = generate_numeric_otp(6)
        verification.token = token
        verification.code = otp_code
        verification.expires_at = timezone.now() + timedelta(hours=24)
        verification.save()
    
    # Update verification attempts and last resend time
    verification.attempts += 1
    verification.last_resend_attempt = timezone.now()
    verification.save()
    
    # Send activation email
    send_account_activation_email.delay(str(user.id), token, otp_code)
    
    # Calculate cooldown for next attempt
    cooldown = 1  # Default 1 minute
    if verification.attempts > 1:
        cooldown = min(verification.attempts * 2, 60)  # Increase cooldown with each attempt, max 60 minutes
    
    return Response({
        'message': 'Verification email sent. Please check your inbox and spam folders.',
        'attempts_remaining': max(0, 5 - verification.attempts),
        'cooldown_minutes': cooldown,
        'user_id': str(user.id)  # Return the user ID to the frontend
    })


@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def verify_otp_view(request):
    """Verify OTP for account activation"""
    serializer = VerifyOtpSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    
    email = serializer.validated_data.get('email')
    otp = serializer.validated_data.get('otp')
    
    # First check if user is already active
    try:
        user = User.objects.get(email=email)
        if user.is_active:
            return Response({
                'message': 'Your account is already active. You can now log in.',
                'user_id': str(user.id)
            })
    except User.DoesNotExist:
        return Response(
            {'error': 'No account found with this email'},
            status=status.HTTP_404_NOT_FOUND
        )
    
    # If not active, proceed with verification
    try:
        verification = UserVerification.objects.get(
            user=user,
            verification_type='ACCOUNT_ACTIVATION',
            code=otp,
            is_verified=False
        )
        
        if verification.is_expired():
            return Response(
                {'error': 'Verification code has expired. Please request a new one.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if not verification.can_attempt():
            return Response(
                {'error': 'Maximum verification attempts exceeded. Please request a new code.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Mark verification as verified
        verification.verify()
        
        # Update user status
        user.is_active = True  # Activate the user
        user.save()
        
        # Log activity
        ActivityLog.objects.create(
            user=user,
            activity_type='PROFILE_UPDATE',
            description='Email verified and account activated',
            metadata={
                'verification_type': 'ACCOUNT_ACTIVATION',
            }
        )
        
        return Response({
            'message': 'Email verified successfully. You can now log in.',
            'user_id': str(user.id)
        })
        
    except UserVerification.DoesNotExist:
        # Increment attempts for any existing verification
        try:
            existing_verification = UserVerification.objects.get(
                user=user,
                verification_type='ACCOUNT_ACTIVATION',
                is_verified=False
            )
            existing_verification.attempts += 1
            existing_verification.save()
            
            if not existing_verification.can_attempt():
                return Response(
                    {'error': 'Maximum verification attempts exceeded. Please request a new code.'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        except UserVerification.DoesNotExist:
            pass
        
        return Response(
            {'error': 'Invalid verification code. Please try again.'},
            status=status.HTTP_400_BAD_REQUEST
        )


class EmailVerificationConfirmView(APIView):
    """View to handle email verification from link"""
    permission_classes = [permissions.AllowAny]
    
    def get(self, request, token):
        try:
            # First check if token exists
            verification = UserVerification.objects.get(
                token=token,
                verification_type='ACCOUNT_ACTIVATION'
            )
            
            # Get the user
            user = verification.user
            
            # Check if user is already active
            if user.is_active:
                # Return success response with already_verified reason
                return Response({
                    'message': 'Your account is already active. You can now log in.',
                    'status': 'success',
                    'reason': 'already_verified'
                })
            
            # Check if token is expired
            if verification.is_expired():
                # Return error response with expired reason
                return Response({
                    'error': 'Your verification link has expired. Please request a new one.',
                    'reason': 'expired',
                    'status': 'failed'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Check if verification is already used
            if verification.is_verified:
                # Return error response with token_already_used reason
                return Response({
                    'error': 'This verification link has already been used. Please request a new one.',
                    'reason': 'token_already_used',
                    'status': 'failed'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Mark verification as verified
            verification.verify()
            
            # Update user status
            user.is_active = True  # Activate the user
            user.save()
            
            # Log activity
            ActivityLog.objects.create(
                user=user,
                activity_type='PROFILE_UPDATE',
                description='Email verified and account activated via link',
                metadata={
                    'verification_type': 'ACCOUNT_ACTIVATION',
                }
            )
            
            # Return success response with verified_successfully reason
            return Response({
                'message': 'Your email has been verified successfully. You can now log in.',
                'status': 'success',
                'reason': 'verified_successfully'
            })
            
        except UserVerification.DoesNotExist:
            # Return error response with invalid reason
            return Response({
                'error': 'Invalid verification link. Please request a new one.',
                'reason': 'invalid',
                'status': 'failed'
            }, status=status.HTTP_400_BAD_REQUEST)


class UserProfileView(generics.RetrieveUpdateAPIView):
    """User profile view"""
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_object(self):
        return self.request.user


class UserProfileDetailView(generics.RetrieveUpdateAPIView):
    """User profile detail view"""
    serializer_class = UserProfileSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_object(self):
        profile, created = UserProfile.objects.get_or_create(user=self.request.user)
        return profile


class UserActivityListView(generics.ListAPIView):
    """List user activities"""
    serializer_class = ActivityLog
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return ActivityLog.objects.filter(
            user=self.request.user
        ).order_by('-created_at')
    
    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        page = self.paginate_queryset(queryset)
        
        # Transform the data to match the frontend expected format
        transformed_data = []
        
        activity_type_mapping = {
            'LOGIN': 'ACCOUNT',
            'LOGOUT': 'ACCOUNT',
            'SEAT_BOOK': 'SEAT_BOOKING',
            'SEAT_CHECKIN': 'SEAT_BOOKING',
            'SEAT_CHECKOUT': 'SEAT_BOOKING',
            'BOOK_RESERVE': 'BOOK_RESERVATION',
            'BOOK_PICKUP': 'BOOK_RESERVATION',
            'BOOK_RETURN': 'BOOK_RESERVATION',
            'EVENT_REGISTER': 'EVENT_REGISTRATION',
            'EVENT_ATTEND': 'EVENT_REGISTRATION',
            'PROFILE_UPDATE': 'ACCOUNT',
            'PASSWORD_CHANGE': 'ACCOUNT',
        }
        
        for activity in page:
            activity_type = activity.activity_type
            mapped_type = activity_type_mapping.get(activity_type, 'ACCOUNT')
            
            # Create a title based on activity type
            title_mapping = {
                'LOGIN': 'Account Login',
                'LOGOUT': 'Account Logout',
                'SEAT_BOOK': 'Seat Booking',
                'SEAT_CHECKIN': 'Seat Check-in',
                'SEAT_CHECKOUT': 'Seat Check-out',
                'BOOK_RESERVE': 'Book Reservation',
                'BOOK_PICKUP': 'Book Pickup',
                'BOOK_RETURN': 'Book Return',
                'EVENT_REGISTER': 'Event Registration',
                'EVENT_ATTEND': 'Event Attendance',
                'PROFILE_UPDATE': 'Profile Update',
                'PASSWORD_CHANGE': 'Password Change',
            }
            
            title = title_mapping.get(activity_type, activity_type.replace('_', ' ').title())
            
            # Extract status from metadata if available
            status = 'COMPLETED'
            if activity.metadata and 'status' in activity.metadata:
                status = activity.metadata['status']
            
            transformed_data.append({
                'id': str(activity.id),
                'type': mapped_type,
                'title': title,
                'description': activity.description,
                'timestamp': activity.created_at.isoformat(),
                'status': status,
            })
        
        return self.get_paginated_response(transformed_data)


class LoyaltyTransactionListView(generics.ListAPIView):
    """List user loyalty transactions"""
    serializer_class = LoyaltyTransactionSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return LoyaltyTransaction.objects.filter(
            user=self.request.user
        ).select_related('user')


class UserSessionListView(generics.ListAPIView):
    """List user sessions"""
    serializer_class = UserSessionSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return UserSession.objects.filter(
            user=self.request.user
        ).select_related('user')


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def end_session_view(request, session_id):
    """End a specific user session"""
    try:
        session = UserSession.objects.get(id=session_id, user=request.user)
        session.end_session()
        return Response({'message': 'Session ended successfully'})
    except UserSession.DoesNotExist:
        return Response(
            {'error': 'Session not found'},
            status=status.HTTP_404_NOT_FOUND
        )


class UserPreferenceListCreateView(generics.ListCreateAPIView):
    """List and create user preferences"""
    serializer_class = UserPreferenceSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return UserPreference.objects.filter(user=self.request.user)
    
    def perform_create(self, serializer):
        serializer.save(user=self.request.user, created_by=self.request.user)


class UserPreferenceDetailView(generics.RetrieveUpdateDestroyAPIView):
    """User preference detail view"""
    serializer_class = UserPreferenceSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrReadOnly]
    
    def get_queryset(self):
        return UserPreference.objects.filter(user=self.request.user)


class LibraryApplicationView(generics.CreateAPIView):
    """Apply for library access"""
    serializer_class = LibraryApplicationSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def perform_create(self, serializer):
        serializer.save()
        
        # Log activity
        ActivityLog.objects.create(
            user=self.request.user,
            activity_type='PROFILE_UPDATE',
            description=f'Applied for library access: {serializer.validated_data["library"].name}',
            metadata={
                'library_id': str(serializer.validated_data["library"].id),
                'library_name': serializer.validated_data["library"].name,
            }
        )


class UserLibraryAccessListView(generics.ListAPIView):
    """List user's library access applications"""
    serializer_class = UserLibraryAccessSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return UserLibraryAccess.objects.filter(
            user=self.request.user
        ).select_related('library', 'granted_by')


def get_user_library_access_queryset(user):
    """
    Helper function to get the appropriate queryset for UserLibraryAccess
    based on the user's role and permissions
    """
    if user.is_super_admin:
        # Super admins can see all library access records
        return UserLibraryAccess.objects.all().select_related(
            'user', 'library', 'granted_by'
        )
    elif user.role == 'ADMIN':
        # Regular admins can only see access records for their managed library
        try:
            admin_profile = user.admin_profile
            if admin_profile and admin_profile.managed_library:
                return UserLibraryAccess.objects.filter(
                    library=admin_profile.managed_library
                ).select_related('user', 'library', 'granted_by')
        except AdminProfile.DoesNotExist:
            pass
    
    # Default: return empty queryset
    return UserLibraryAccess.objects.none()


class UserLibraryAccessListCreateView(generics.ListCreateAPIView):
    """Manage user library access"""
    serializer_class = UserLibraryAccessSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def get_queryset(self):
        return get_user_library_access_queryset(self.request.user)
    
    def perform_create(self, serializer):
        serializer.save(
            granted_by=self.request.user,
            created_by=self.request.user
        )


class UserLibraryAccessApprovalView(generics.GenericAPIView):
    """Approve a library access application"""
    serializer_class = UserLibraryAccessAdminSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def get_queryset(self):
        return get_user_library_access_queryset(self.request.user)
    
    def post(self, request, access_id):
        try:
            # Get the library access application
            application = self.get_queryset().get(id=access_id)
            
            # Update application status
            application.is_active = True
            application.granted_by = request.user
            application.granted_at = timezone.now()
            application.save()
            
            # Create notification for the user
            try:
                from apps.notifications.models import Notification
                Notification.objects.create(
                    user=application.user,
                    title='Library Access Approved',
                    message=f'Your application for access to {application.library.name} has been approved.',
                    notification_type='APPROVAL',
                    metadata={
                        'library_id': str(application.library.id),
                        'library_name': application.library.name,
                        'approved_by': request.user.full_name,
                        'approved_at': timezone.now().isoformat()
                    }
                )
            except Exception as e:
                import logging
                logger = logging.getLogger(__name__)
                logger.error(f"Error creating notification for library access approval: {e}")
            
            # Log activity
            ActivityLog.objects.create(
                user=request.user,
                activity_type='PROFILE_UPDATE',
                description=f'Approved library access for {application.user.full_name} to {application.library.name}',
                metadata={
                    'user_id': str(application.user.id),
                    'user_name': application.user.full_name,
                    'library_id': str(application.library.id),
                    'library_name': application.library.name,
                    'application_id': str(application.id)
                }
            )
            
            return Response({
                'message': f'Library access for {application.user.full_name} to {application.library.name} has been approved.',
                'application': UserLibraryAccessSerializer(application).data
            })
            
        except UserLibraryAccess.DoesNotExist:
            return Response(
                {'error': 'Library access application not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )


class UserLibraryAccessRejectionView(generics.GenericAPIView):
    """Reject or revoke a library access application"""
    serializer_class = UserLibraryAccessAdminSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def get_queryset(self):
        return get_user_library_access_queryset(self.request.user)
    
    def post(self, request, access_id):
        try:
            # Get the library access application
            application = self.get_queryset().get(id=access_id)
            
            # Get reason from request data
            reason = request.data.get('reason', '')
            
            # Update application status
            application.is_active = False
            
            # Add rejection note
            rejection_note = f"\n[REJECTED by {request.user.full_name} on {timezone.now().strftime('%Y-%m-%d %H:%M')}]"
            if reason:
                rejection_note += f"\nReason: {reason}"
                
            if application.notes:
                application.notes += rejection_note
            else:
                application.notes = rejection_note
            
            application.save()
            
            # Create notification for the user
            try:
                from apps.notifications.models import Notification
                Notification.objects.create(
                    user=application.user,
                    title='Library Access Rejected',
                    message=f'Your application for access to {application.library.name} has been rejected.',
                    notification_type='REJECTION',
                    metadata={
                        'library_id': str(application.library.id),
                        'library_name': application.library.name,
                        'rejected_by': request.user.full_name,
                        'rejected_at': timezone.now().isoformat(),
                        'reason': reason
                    }
                )
            except Exception as e:
                import logging
                logger = logging.getLogger(__name__)
                logger.error(f"Error creating notification for library access rejection: {e}")
            
            # Log activity
            ActivityLog.objects.create(
                user=request.user,
                activity_type='PROFILE_UPDATE',
                description=f'Rejected library access for {application.user.full_name} to {application.library.name}',
                metadata={
                    'user_id': str(application.user.id),
                    'user_name': application.user.full_name,
                    'library_id': str(application.library.id),
                    'library_name': application.library.name,
                    'application_id': str(application.id),
                    'reason': reason
                }
            )
            
            return Response({
                'message': f'Library access for {application.user.full_name} to {application.library.name} has been rejected.',
                'application': UserLibraryAccessSerializer(application).data
            })
            
        except UserLibraryAccess.DoesNotExist:
            return Response(
                {'error': 'Library access application not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )


class PasswordChangeView(generics.GenericAPIView):
    """Change user password"""
    serializer_class = PasswordChangeSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        
        return Response({'message': 'Password changed successfully'})


class PasswordResetView(generics.GenericAPIView):
    """Request password reset"""
    serializer_class = PasswordResetSerializer
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = serializer.user
        
        # Create password reset verification
        verification = UserVerification.objects.create(
            user=user,
            verification_type='PASSWORD_RESET',
            token=generate_secure_token(),
            expires_at=timezone.now() + timedelta(hours=2)
        )
        
        # Send reset email
        send_notification_email(
            to_email=user.email,
            subject='Smart Lib - Password Reset',
            message=f'Use this token to reset your password: {verification.token}',
            html_message=f'''
            <h2>Password Reset Request</h2>
            <p>You requested a password reset for your Smart Lib account.</p>
            <p>Use the following token to reset your password:</p>
            <p><strong>{verification.token}</strong></p>
            <p>This token will expire in 2 hours.</p>
            <p>If you didn't request this, please ignore this email.</p>
            '''
        )
        
        return Response({'message': 'Password reset email sent'})


class PasswordResetConfirmView(generics.GenericAPIView):
    """Confirm password reset"""
    serializer_class = PasswordResetConfirmSerializer
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        
        return Response({'message': 'Password reset successful'})


# Admin Views
class UserListView(generics.ListCreateAPIView):
    """List and create users (Admin only)"""
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    filterset_fields = ['role', 'is_active']
    search_fields = ['email', 'first_name', 'last_name', 'crn', 'student_id']
    ordering_fields = ['created_at', 'last_login', 'login_count']
    ordering = ['-created_at']
    
    def get_queryset(self):
        if self.request.user.is_super_admin:
            return User.objects.all()
        elif self.request.user.role == 'ADMIN':
            # Library admin can only see users with access to their library
            admin_profile = getattr(self.request.user, 'admin_profile', None)
            if admin_profile and admin_profile.managed_library:
                return User.objects.filter(
                    library_access__library=admin_profile.managed_library
                ).distinct()
        return User.objects.none()
    
    def get_serializer_class(self):
        if self.request.method == 'POST':
            return UserAdminUpdateSerializer
        return UserSerializer
    
    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)


class UserDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Retrieve, update or delete a user (Admin only)"""
    serializer_class = UserAdminUpdateSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    lookup_url_kwarg = 'user_id'
    
    def get_queryset(self):
        if self.request.user.is_super_admin:
            return User.objects.all()
        elif self.request.user.role == 'ADMIN':
            # Library admin can only see users with access to their library
            admin_profile = getattr(self.request.user, 'admin_profile', None)
            if admin_profile and admin_profile.managed_library:
                return User.objects.filter(
                    library_access__library=admin_profile.managed_library
                ).distinct()
        return User.objects.none()
    
    def perform_update(self, serializer):
        serializer.save(updated_by=self.request.user)
        
        # Log activity
        ActivityLog.objects.create(
            user=self.request.user,
            activity_type='PROFILE_UPDATE',
            description=f'Admin updated user: {serializer.instance.get_full_name()}',
            metadata={
                'user_id': str(serializer.instance.id),
                'user_email': serializer.instance.email,
            }
        )


# Admin Profile Management Views
class AdminProfileListCreateView(generics.ListCreateAPIView):
    """List and create admin profiles (Super Admin only)"""
    serializer_class = AdminProfileSerializer
    permission_classes = [permissions.IsAuthenticated, IsSuperAdminUser]
    
    def get_queryset(self):
        return AdminProfile.objects.all().select_related('user', 'managed_library')
    
    def perform_create(self, serializer):
        # Save the admin profile
        admin_profile = serializer.save(created_by=self.request.user)
        
        # Update the user's role to ADMIN if it's not already SUPER_ADMIN
        user = admin_profile.user
        if user.role != 'SUPER_ADMIN':
            user.role = 'ADMIN'
            user.save()
        
        # Log activity
        ActivityLog.objects.create(
            user=self.request.user,
            activity_type='PROFILE_UPDATE',
            description=f'Created admin profile for {user.get_full_name()}',
            metadata={
                'user_id': str(user.id),
                'library_id': str(admin_profile.managed_library.id) if admin_profile.managed_library else None,
                'permissions': admin_profile.permissions,
            }
        )


class AdminProfileDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Retrieve, update or delete an admin profile (Super Admin only)"""
    serializer_class = AdminProfileSerializer
    permission_classes = [permissions.IsAuthenticated, IsSuperAdminUser]
    lookup_field = 'id'
    
    def get_queryset(self):
        return AdminProfile.objects.all().select_related('user', 'managed_library')
    
    def perform_update(self, serializer):
        serializer.save(updated_by=self.request.user)
        
        # Log activity
        ActivityLog.objects.create(
            user=self.request.user,
            activity_type='PROFILE_UPDATE',
            description=f'Updated admin profile for {serializer.instance.user.get_full_name()}',
            metadata={
                'user_id': str(serializer.instance.user.id),
                'library_id': str(serializer.instance.managed_library.id) if serializer.instance.managed_library else None,
                'permissions': serializer.instance.permissions,
            }
        )
    
    def perform_destroy(self, instance):
        user = instance.user
        
        # Log activity before deleting
        ActivityLog.objects.create(
            user=self.request.user,
            activity_type='PROFILE_UPDATE',
            description=f'Deleted admin profile for {user.get_full_name()}',
            metadata={
                'user_id': str(user.id),
                'library_id': str(instance.managed_library.id) if instance.managed_library else None,
            }
        )
        
        # If the user is not a SUPER_ADMIN, change their role back to STUDENT
        if user.role != 'SUPER_ADMIN':
            user.role = 'STUDENT'
            user.save()
        
        # Delete the admin profile
        instance.delete()


class AdminProfileListView(generics.ListAPIView):
    """List admin profiles (Super Admin only)"""
    serializer_class = AdminProfileSerializer
    permission_classes = [permissions.IsAuthenticated, IsSuperAdminUser]
    
    def get_queryset(self):
        return AdminProfile.objects.all().select_related('user', 'managed_library')


# API endpoint to get users eligible for admin assignment
class EligibleAdminUsersView(generics.ListAPIView):
    """List users eligible to be assigned as admins (Super Admin only)"""
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated, IsSuperAdminUser]
    
    def get_queryset(self):
        # Get users with role ADMIN who don't already have an admin profile
        return User.objects.filter(
            role='ADMIN',
            is_active=True
        ).exclude(
            id__in=AdminProfile.objects.values_list('user_id', flat=True)
        )