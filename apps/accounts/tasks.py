"""
Celery tasks for accounts app
"""
from celery import shared_task
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from datetime import timedelta
from .models import User, UserSession, UserVerification, LoyaltyTransaction
import logging

logger = logging.getLogger(__name__)


@shared_task
def cleanup_expired_sessions():
    """Clean up expired user sessions"""
    try:
        # Sessions inactive for more than 30 days
        cutoff_date = timezone.now() - timedelta(days=30)
        expired_sessions = UserSession.objects.filter(
            last_activity__lt=cutoff_date,
            is_active=True
        )
        
        count = expired_sessions.count()
        expired_sessions.update(is_active=False, logout_time=timezone.now())
        
        logger.info(f"Cleaned up {count} expired user sessions")
        return f"Cleaned up {count} expired sessions"
        
    except Exception as e:
        logger.error(f"Error cleaning up expired sessions: {e}")
        return f"Error: {e}"


@shared_task
def cleanup_expired_verifications():
    """Clean up expired verification tokens"""
    try:
        cutoff_date = timezone.now()
        expired_verifications = UserVerification.objects.filter(
            expires_at__lt=cutoff_date,
            is_verified=False
        )
        
        count = expired_verifications.count()
        expired_verifications.delete()
        
        logger.info(f"Cleaned up {count} expired verification tokens")
        return f"Cleaned up {count} expired verification tokens"
        
    except Exception as e:
        logger.error(f"Error cleaning up expired verifications: {e}")
        return f"Error: {e}"


@shared_task
def send_account_activation_email(user_id, token, code):
    """Send account activation email to user"""
    try:
        user = User.objects.get(id=user_id)
        
        verification_url = f"{settings.FRONTEND_URL}/auth/verify-email/{token}"
        
        subject = 'Smart Lib - Verify Your Email Address'
        message = f'''
        Dear {user.get_full_name()},
        
        Thank you for registering with Smart Lib! Please verify your email address to activate your account.
        
        Verification Link: {verification_url}
        
        If you prefer to enter the code manually, use this verification code: {code}
        
        This verification link and code will expire in 24 hours.
        
        Your Student ID: {user.student_id}
        Your CRN: {user.crn}
        
        Best regards,
        Smart Lib Team
        '''
        
        html_message = f'''
        <h2>Welcome to Smart Lib!</h2>
        <p>Dear {user.get_full_name()},</p>
        <p>Thank you for registering with Smart Lib! Please verify your email address to activate your account.</p>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="{verification_url}" style="background-color: #4CAF50; color: white; padding: 15px 25px; text-decoration: none; border-radius: 5px; font-weight: bold;">Verify Email Address</a>
        </div>
        
        <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
        <p><a href="{verification_url}">{verification_url}</a></p>
        
        <p>Or if you prefer to enter the code manually, use this verification code:</p>
        <div style="background-color: #f5f5f5; padding: 15px; font-size: 24px; font-weight: bold; text-align: center; letter-spacing: 5px; margin: 20px 0;">
            {code}
        </div>
        
        <p>This verification link and code will expire in 24 hours.</p>
        
        <p><strong>Your Account Information:</strong></p>
        <ul>
            <li>Student ID: {user.student_id}</li>
            <li>CRN: {user.crn}</li>
        </ul>
        
        <p>Best regards,<br>Smart Lib Team</p>
        '''
        
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )
        
        logger.info(f"Account activation email sent to {user.email}")
        return f"Account activation email sent to {user.email}"
        
    except User.DoesNotExist:
        logger.error(f"User with ID {user_id} not found")
        return f"User with ID {user_id} not found"
    except Exception as e:
        logger.error(f"Error sending account activation email: {e}")
        return f"Error: {e}"


@shared_task
def send_welcome_email(user_id):
    """Send welcome email to new user"""
    try:
        user = User.objects.get(id=user_id)
        
        subject = 'Welcome to Smart Lib!'
        message = f'''
        Dear {user.get_full_name()},
        
        Welcome to Smart Lib! Your account has been created successfully.
        
        Your Student ID: {user.student_id}
        Your CRN: {user.crn}
        
        Please verify your email address to activate your account.
        
        Best regards,
        Smart Lib Team
        '''
        
        html_message = f'''
        <h2>Welcome to Smart Lib!</h2>
        <p>Dear {user.get_full_name()},</p>
        <p>Welcome to Smart Lib! Your account has been created successfully.</p>
        <ul>
            <li><strong>Student ID:</strong> {user.student_id}</li>
            <li><strong>CRN:</strong> {user.crn}</li>
        </ul>
        <p>Please verify your email address to activate your account.</p>
        <p>Best regards,<br>Smart Lib Team</p>
        '''
        
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )
        
        logger.info(f"Welcome email sent to {user.email}")
        return f"Welcome email sent to {user.email}"
        
    except User.DoesNotExist:
        logger.error(f"User with ID {user_id} not found")
        return f"User with ID {user_id} not found"
    except Exception as e:
        logger.error(f"Error sending welcome email: {e}")
        return f"Error: {e}"


@shared_task
def process_loyalty_points_expiry():
    """Process expired loyalty points"""
    try:
        # Points expire after 1 year
        cutoff_date = timezone.now() - timedelta(days=365)
        
        # Find transactions older than 1 year that haven't been processed for expiry
        old_transactions = LoyaltyTransaction.objects.filter(
            created_at__lt=cutoff_date,
            transaction_type='EARNED'
        ).values('user').distinct()
        
        expired_count = 0
        for transaction_data in old_transactions:
            user_id = transaction_data['user']
            try:
                user = User.objects.get(id=user_id)
                profile = user.profile
                
                # Calculate expired points
                expired_points = LoyaltyTransaction.objects.filter(
                    user=user,
                    created_at__lt=cutoff_date,
                    transaction_type='EARNED'
                ).aggregate(total=models.Sum('points'))['total'] or 0
                
                if expired_points > 0:
                    # Deduct expired points
                    profile.loyalty_points = max(0, profile.loyalty_points - expired_points)
                    profile.save()
                    
                    # Create expiry transaction
                    LoyaltyTransaction.objects.create(
                        user=user,
                        points=expired_points,
                        transaction_type='EXPIRED',
                        description=f'Points expired after 1 year',
                        created_by=user
                    )
                    
                    expired_count += 1
                    
            except User.DoesNotExist:
                continue
        
        logger.info(f"Processed loyalty points expiry for {expired_count} users")
        return f"Processed loyalty points expiry for {expired_count} users"
        
    except Exception as e:
        logger.error(f"Error processing loyalty points expiry: {e}")
        return f"Error: {e}"


@shared_task
def generate_user_statistics():
    """Generate daily user statistics"""
    try:
        from django.db.models import Count, Q
        
        today = timezone.now().date()
        
        stats = {
            'total_users': User.objects.count(),
            'active_users': User.objects.filter(is_active=True).count(),
            'verified_users': User.objects.filter(is_verified=True).count(),
            'pending_verification': User.objects.filter(is_verified=False, is_active=False).count(),
            'students': User.objects.filter(role='STUDENT').count(),
            'admins': User.objects.filter(role__in=['ADMIN', 'SUPER_ADMIN']).count(),
            'new_registrations_today': User.objects.filter(created_at__date=today).count(),
            'active_sessions': UserSession.objects.filter(is_active=True).count(),
        }
        
        logger.info(f"User statistics generated: {stats}")
        return stats
        
    except Exception as e:
        logger.error(f"Error generating user statistics: {e}")
        return f"Error: {e}"