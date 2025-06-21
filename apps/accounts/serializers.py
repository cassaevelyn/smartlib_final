"""
Serializers for accounts app
"""
from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.utils import timezone
from apps.core.serializers import BaseModelSerializer
from apps.core.utils import validate_crn, generate_secure_token, generate_numeric_otp
from .models import (
    User, UserProfile, LoyaltyTransaction, UserSession,
    UserVerification, UserPreference, UserLibraryAccess, AdminProfile
)


class UserRegistrationSerializer(serializers.ModelSerializer):
    """Serializer for user registration"""
    password = serializers.CharField(write_only=True, validators=[validate_password])
    password_confirm = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = [
            'username', 'email', 'password', 'password_confirm',
            'first_name', 'last_name', 'crn', 'phone_number',
            'date_of_birth', 'gender', 'address', 'city'
        ]
    
    def validate_crn(self, value):
        """Validate CRN format"""
        if not validate_crn(value):
            raise serializers.ValidationError(
                "Invalid CRN format. Use: ICAP-CA-YYYY-####"
            )
        return value
    
    def validate(self, attrs):
        """Validate password confirmation"""
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Passwords don't match")
        return attrs
    
    def create(self, validated_data):
        """Create new user"""
        validated_data.pop('password_confirm')
        password = validated_data.pop('password')
        
        # Create new user with is_active=False (will be activated after email verification)
        user = User.objects.create_user(
            password=password,
            **validated_data
        )
        
        # UserProfile is created by the post_save signal in signals.py
        
        return user


class UserLoginSerializer(serializers.Serializer):
    """Serializer for user login"""
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    
    def validate(self, attrs):
        """Validate login credentials"""
        email = attrs.get('email')
        password = attrs.get('password')
        
        if email and password:
            user = authenticate(
                request=self.context.get('request'),
                username=email,
                password=password
            )
            
            if not user:
                raise serializers.ValidationError('Invalid credentials')
            
            if not user.is_active:
                # Check if the user exists but is not active (email not verified)
                try:
                    inactive_user = User.objects.get(email=email, is_active=False)
                    if inactive_user:
                        # This is a special error that will be caught by the view
                        # to trigger the email verification resend process
                        raise serializers.ValidationError(
                            'Account not active. Please verify your email.',
                            code='account_not_active'
                        )
                except User.DoesNotExist:
                    pass
                
                raise serializers.ValidationError('Account is deactivated')
            
            attrs['user'] = user
            return attrs
        
        raise serializers.ValidationError('Email and password are required')


class SendOtpSerializer(serializers.Serializer):
    """Serializer for sending account activation email"""
    email = serializers.EmailField()
    
    def validate_email(self, value):
        """Validate email exists"""
        try:
            # Try to find an existing user
            user = User.objects.get(email=value)
            
            # If user is already verified and active, raise an error
            if user.is_verified and user.is_active:
                raise serializers.ValidationError('Your account is already verified. Please login instead.')
            
            # If user exists but is not verified, we'll use this user for activation
            self.context['user'] = user
            
        except User.DoesNotExist:
            raise serializers.ValidationError('No account found with this email address.')
        
        # Check for existing verification
        try:
            verification = UserVerification.objects.get(
                user=user,
                verification_type='ACCOUNT_ACTIVATION',
                is_verified=False
            )
            
            # Check rate limiting
            if not verification.can_resend():
                # Check if last attempt was within the last hour
                one_hour_ago = timezone.now() - timezone.timedelta(hours=1)
                if verification.last_resend_attempt and verification.last_resend_attempt > one_hour_ago and verification.attempts >= 5:
                    raise serializers.ValidationError('Too many verification attempts. Please try again after 1 hour.')
            
            self.context['verification'] = verification
        except UserVerification.DoesNotExist:
            # Will create a new verification in the view
            pass
        
        return value


class VerifyOtpSerializer(serializers.Serializer):
    """Serializer for verifying OTP"""
    email = serializers.EmailField()
    otp = serializers.CharField(min_length=6, max_length=6)
    
    def validate(self, attrs):
        """Validate OTP"""
        email = attrs.get('email')
        otp = attrs.get('otp')
        
        try:
            user = User.objects.get(email=email)
            
            try:
                verification = UserVerification.objects.get(
                    user=user,
                    verification_type='ACCOUNT_ACTIVATION',
                    code=otp,
                    is_verified=False
                )
                
                if verification.is_expired():
                    raise serializers.ValidationError('Verification code has expired. Please request a new one.')
                
                if not verification.can_attempt():
                    raise serializers.ValidationError('Maximum verification attempts exceeded. Please request a new code.')
                
                self.context['user'] = user
                self.context['verification'] = verification
                return attrs
                
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
                        raise serializers.ValidationError('Maximum verification attempts exceeded. Please request a new code.')
                except UserVerification.DoesNotExist:
                    pass
                
                raise serializers.ValidationError('Invalid verification code. Please try again.')
                
        except User.DoesNotExist:
            raise serializers.ValidationError('No account found with this email')


class UserSerializer(serializers.ModelSerializer):
    """Serializer for user details"""
    full_name = serializers.ReadOnlyField()
    is_student = serializers.ReadOnlyField()
    is_admin = serializers.ReadOnlyField()
    is_super_admin = serializers.ReadOnlyField()
    managed_library_id = serializers.SerializerMethodField()
    has_admin_profile = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name', 'full_name',
            'crn', 'student_id', 'phone_number', 'date_of_birth', 'gender',
            'address', 'city', 'role', 'is_verified', 'avatar', 'bio',
            'preferred_language', 'is_student', 'is_admin', 'is_super_admin',
            'last_login', 'created_at', 'is_active', 'login_count', 'managed_library_id',
            'has_admin_profile'
        ]
        read_only_fields = [
            'id', 'student_id', 'is_verified', 'last_login', 'created_at', 'login_count'
        ]
    
    def get_managed_library_id(self, obj):
        """Get the ID of the library managed by this admin user"""
        if obj.role in ['ADMIN', 'SUPER_ADMIN']:
            try:
                admin_profile = obj.admin_profile
                if admin_profile and admin_profile.managed_library:
                    return str(admin_profile.managed_library.id)
            except AdminProfile.DoesNotExist:
                pass
        return None
    
    def get_has_admin_profile(self, obj):
        """Check if user has an admin profile"""
        if obj.role in ['ADMIN', 'SUPER_ADMIN']:
            return hasattr(obj, 'admin_profile')
        return False


class UserAdminUpdateSerializer(serializers.ModelSerializer):
    """Serializer for admin-initiated user updates"""
    
    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name',
            'crn', 'student_id', 'phone_number', 'date_of_birth', 'gender',
            'address', 'city', 'role', 'is_verified', 'is_active',
            'bio', 'preferred_language'
        ]
        read_only_fields = ['id', 'student_id', 'created_at']
    
    def validate_role(self, value):
        """Validate role changes"""
        # Only super admins can create other admins
        request = self.context.get('request')
        if request and request.user:
            if value in ['ADMIN', 'SUPER_ADMIN'] and request.user.role != 'SUPER_ADMIN':
                raise serializers.ValidationError("Only super admins can assign admin roles")
        return value


class UserProfileSerializer(BaseModelSerializer):
    """Serializer for user profile"""
    user_display = serializers.CharField(source='user.full_name', read_only=True)
    
    class Meta:
        model = UserProfile
        fields = [
            'id', 'user', 'user_display', 'education_level', 'enrollment_year',
            'expected_completion_year', 'emergency_contact_name',
            'emergency_contact_phone', 'emergency_contact_relation',
            'preferred_study_time', 'preferred_seat_type', 'study_subjects',
            'total_study_hours', 'books_read', 'events_attended',
            'loyalty_points', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'total_study_hours', 'books_read', 'events_attended',
            'loyalty_points', 'created_at', 'updated_at'
        ]


class LoyaltyTransactionSerializer(BaseModelSerializer):
    """Serializer for loyalty transactions"""
    user_display = serializers.CharField(source='user.get_full_name', read_only=True)
    transaction_type_display = serializers.CharField(
        source='get_transaction_type_display', read_only=True
    )
    
    class Meta:
        model = LoyaltyTransaction
        fields = [
            'id', 'user', 'user_display', 'points', 'transaction_type',
            'transaction_type_display', 'description', 'reference_id',
            'created_at'
        ]
        read_only_fields = ['id', 'created_at']


class UserSessionSerializer(serializers.ModelSerializer):
    """Serializer for user sessions"""
    user_display = serializers.CharField(source='user.get_full_name', read_only=True)
    
    class Meta:
        model = UserSession
        fields = [
            'id', 'user', 'user_display', 'session_key', 'ip_address',
            'user_agent', 'device_info', 'is_active', 'created_at',
            'last_activity', 'logout_time'
        ]
        read_only_fields = ['id', 'created_at', 'last_activity']


class UserVerificationSerializer(serializers.ModelSerializer):
    """Serializer for user verification"""
    user_display = serializers.CharField(source='user.get_full_name', read_only=True)
    verification_type_display = serializers.CharField(
        source='get_verification_type_display', read_only=True
    )
    
    class Meta:
        model = UserVerification
        fields = [
            'id', 'user', 'user_display', 'verification_type',
            'verification_type_display', 'is_verified', 'expires_at',
            'verified_at', 'attempts', 'max_attempts', 'created_at',
            'last_resend_attempt'
        ]
        read_only_fields = [
            'id', 'token', 'code', 'is_verified', 'verified_at', 'attempts', 'created_at',
            'last_resend_attempt'
        ]


class UserPreferenceSerializer(BaseModelSerializer):
    """Serializer for user preferences"""
    user_display = serializers.CharField(source='user.get_full_name', read_only=True)
    category_display = serializers.CharField(
        source='get_category_display', read_only=True
    )
    
    class Meta:
        model = UserPreference
        fields = [
            'id', 'user', 'user_display', 'category', 'category_display',
            'key', 'value', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class UserLibraryAccessSerializer(BaseModelSerializer):
    """Serializer for user library access"""
    user_display = serializers.CharField(source='user.get_full_name', read_only=True)
    library_display = serializers.CharField(source='library.name', read_only=True)
    granted_by_display = serializers.CharField(source='granted_by.full_name', read_only=True)
    access_type_display = serializers.CharField(
        source='get_access_type_display', read_only=True
    )
    
    class Meta:
        model = UserLibraryAccess
        fields = [
            'id', 'user', 'user_display', 'library', 'library_display',
            'access_type', 'access_type_display', 'granted_by',
            'granted_by_display', 'granted_at', 'expires_at', 'is_active',
            'notes', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'granted_by', 'granted_at', 'created_at', 'updated_at'
        ]


class UserLibraryAccessAdminSerializer(BaseModelSerializer):
    """Serializer for admin management of user library access"""
    user_display = serializers.CharField(source='user.get_full_name', read_only=True)
    library_display = serializers.CharField(source='library.name', read_only=True)
    granted_by_display = serializers.CharField(source='granted_by.full_name', read_only=True)
    access_type_display = serializers.CharField(
        source='get_access_type_display', read_only=True
    )
    
    class Meta:
        model = UserLibraryAccess
        fields = [
            'id', 'user', 'user_display', 'library', 'library_display',
            'access_type', 'access_type_display', 'granted_by',
            'granted_by_display', 'granted_at', 'expires_at', 'is_active',
            'notes', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'user', 'library', 'created_at', 'updated_at'
        ]


class LibraryApplicationSerializer(serializers.ModelSerializer):
    """Serializer for library access application"""
    notes = serializers.CharField(required=False, allow_blank=True)
    
    class Meta:
        model = UserLibraryAccess
        fields = ['library', 'notes']
    
    def create(self, validated_data):
        user = self.context['request'].user
        validated_data['user'] = user
        validated_data['created_by'] = user
        validated_data['is_active'] = False  # Pending approval
        validated_data['access_type'] = 'STANDARD'
        return super().create(validated_data)


class AdminProfileSerializer(BaseModelSerializer):
    """Serializer for admin profile"""
    user_display = serializers.CharField(source='user.get_full_name', read_only=True)
    managed_library_display = serializers.CharField(
        source='managed_library.name', read_only=True
    )
    
    class Meta:
        model = AdminProfile
        fields = [
            'id', 'user', 'user_display', 'managed_library',
            'managed_library_display', 'permissions', 'can_manage_events',
            'can_manage_books', 'can_view_analytics',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def validate_user(self, value):
        """Validate that the user can be assigned as an admin"""
        # Check if user already has an admin profile
        if hasattr(value, 'admin_profile'):
            # If we're updating an existing profile, check if it's the same user
            if self.instance and self.instance.user == value:
                return value
            raise serializers.ValidationError("This user already has an admin profile")
        
        # Check if user has the correct role
        if value.role not in ['ADMIN', 'SUPER_ADMIN']:
            raise serializers.ValidationError("Only users with ADMIN or SUPER_ADMIN role can have admin profiles")
        
        return value
    
    def create(self, validated_data):
        """Create admin profile and ensure user has correct role"""
        user = validated_data.get('user')
        
        # Ensure user has ADMIN role if not already SUPER_ADMIN
        if user.role != 'SUPER_ADMIN':
            user.role = 'ADMIN'
            user.save()
        
        return super().create(validated_data)
    
    def update(self, instance, validated_data):
        """Update admin profile"""
        # If user is being changed, ensure the new user has correct role
        if 'user' in validated_data:
            user = validated_data.get('user')
            if user.role != 'SUPER_ADMIN':
                user.role = 'ADMIN'
                user.save()
        
        return super().update(instance, validated_data)


class PasswordChangeSerializer(serializers.Serializer):
    """Serializer for password change"""
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True, validators=[validate_password])
    new_password_confirm = serializers.CharField(write_only=True)
    
    def validate_old_password(self, value):
        """Validate old password"""
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError('Old password is incorrect')
        return value
    
    def validate(self, attrs):
        """Validate new password confirmation"""
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError("New passwords don't match")
        return attrs
    
    def save(self):
        """Change user password"""
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.save()
        return user


class PasswordResetSerializer(serializers.Serializer):
    """Serializer for password reset request"""
    email = serializers.EmailField()
    
    def validate_email(self, value):
        """Validate email exists"""
        try:
            user = User.objects.get(email=value, is_active=True)
            self.user = user
            return value
        except User.DoesNotExist:
            raise serializers.ValidationError('No active account found with this email')


class PasswordResetConfirmSerializer(serializers.Serializer):
    """Serializer for password reset confirmation"""
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True, validators=[validate_password])
    new_password_confirm = serializers.CharField(write_only=True)
    
    def validate(self, attrs):
        """Validate token and password confirmation"""
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError("Passwords don't match")
        
        # Validate token
        try:
            verification = UserVerification.objects.get(
                token=attrs['token'],
                verification_type='PASSWORD_RESET',
                is_verified=False
            )
            if verification.is_expired() or not verification.can_attempt():
                raise serializers.ValidationError('Token is expired or invalid')
            
            attrs['verification'] = verification
            return attrs
        except UserVerification.DoesNotExist:
            raise serializers.ValidationError('Invalid token')
    
    def save(self):
        """Reset user password"""
        verification = self.validated_data['verification']
        user = verification.user
        user.set_password(self.validated_data['new_password'])
        user.save()
        
        # Mark verification as used
        verification.verify()
        
        return user