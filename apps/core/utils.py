"""
Utility functions for Smart Lib
"""
import qrcode
import uuid
from io import BytesIO
from django.core.files import File
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
import hashlib
import secrets
import random
from PIL import Image
import logging

logger = logging.getLogger(__name__)


def generate_qr_code(data, format='PNG'):
    """
    Generate QR code for given data
    
    Args:
        data (str): Data to encode in QR code
        format (str): Image format (PNG, JPEG, etc.)
    
    Returns:
        BytesIO: QR code image buffer
    """
    try:
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format=format)
        buffer.seek(0)
        
        return buffer
    except Exception as e:
        logger.error(f"Error generating QR code: {e}")
        return None


def generate_unique_code(prefix='', length=8):
    """
    Generate a unique code with optional prefix
    
    Args:
        prefix (str): Prefix for the code
        length (int): Length of random part
    
    Returns:
        str: Unique code
    """
    random_part = secrets.token_urlsafe(length)[:length].upper()
    return f"{prefix}{random_part}" if prefix else random_part


def generate_numeric_otp(length=6):
    """
    Generate a numeric OTP of specified length
    
    Args:
        length (int): Length of the OTP
    
    Returns:
        str: Numeric OTP
    """
    digits = "0123456789"
    return ''.join(random.choice(digits) for _ in range(length))


def send_notification_email(to_email, subject, message, html_message=None):
    """
    Send notification email
    
    Args:
        to_email (str): Recipient email
        subject (str): Email subject
        message (str): Plain text message
        html_message (str, optional): HTML message
    
    Returns:
        bool: Success status
    """
    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[to_email],
            html_message=html_message,
            fail_silently=False,
        )
        return True
    except Exception as e:
        logger.error(f"Error sending email to {to_email}: {e}")
        return False


def calculate_loyalty_points(activity_type, base_points=10):
    """
    Calculate loyalty points based on activity type
    
    Args:
        activity_type (str): Type of activity
        base_points (int): Base points to award
    
    Returns:
        int: Points to award
    """
    multipliers = {
        'SEAT_BOOKING': 1.0,
        'BOOK_RESERVATION': 1.2,
        'EVENT_ATTENDANCE': 2.5,
        'SUBSCRIPTION_PURCHASE': 5.0,
        'REVIEW_SUBMISSION': 1.5,
    }
    
    multiplier = multipliers.get(activity_type, 1.0)
    return int(base_points * multiplier)


def hash_sensitive_data(data):
    """
    Hash sensitive data using SHA-256
    
    Args:
        data (str): Data to hash
    
    Returns:
        str: Hashed data
    """
    return hashlib.sha256(data.encode()).hexdigest()


def validate_crn(crn):
    """
    Validate ICAP CA student CRN format
    
    Args:
        crn (str): CRN to validate
    
    Returns:
        bool: Validation result
    """
    # CRN format: ICAP-CA-YYYY-#### (e.g., ICAP-CA-2023-1234)
    import re
    pattern = r'^ICAP-CA-\d{4}-\d{4}$'
    return bool(re.match(pattern, crn))


def get_user_ip(request):
    """
    Get user's IP address from request
    
    Args:
        request: Django request object
    
    Returns:
        str: IP address
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def resize_image(image_file, max_width=800, max_height=600, quality=85):
    """
    Resize image while maintaining aspect ratio
    
    Args:
        image_file: Image file object
        max_width (int): Maximum width
        max_height (int): Maximum height
        quality (int): JPEG quality (1-100)
    
    Returns:
        File: Resized image file
    """
    try:
        with Image.open(image_file) as img:
            # Convert to RGB if necessary
            if img.mode in ('RGBA', 'LA', 'P'):
                img = img.convert('RGB')
            
            # Calculate new dimensions
            img.thumbnail((max_width, max_height), Image.Resampling.LANCZOS)
            
            # Save to BytesIO
            output = BytesIO()
            img.save(output, format='JPEG', quality=quality, optimize=True)
            output.seek(0)
            
            return File(output, name=image_file.name)
    except Exception as e:
        logger.error(f"Error resizing image: {e}")
        return image_file


def calculate_time_until_expiry(expiry_time):
    """
    Calculate time remaining until expiry
    
    Args:
        expiry_time (datetime): Expiry datetime
    
    Returns:
        dict: Time remaining breakdown
    """
    now = timezone.now()
    if expiry_time <= now:
        return {'expired': True, 'time_remaining': timedelta(0)}
    
    time_remaining = expiry_time - now
    days = time_remaining.days
    hours, remainder = divmod(time_remaining.seconds, 3600)
    minutes, _ = divmod(remainder, 60)
    
    return {
        'expired': False,
        'time_remaining': time_remaining,
        'days': days,
        'hours': hours,
        'minutes': minutes
    }


def generate_secure_token():
    """
    Generate a secure token for various uses
    
    Returns:
        str: Secure token
    """
    return secrets.token_urlsafe(32)


def validate_file_upload(file, allowed_types=None, max_size_mb=10):
    """
    Validate uploaded file
    
    Args:
        file: Uploaded file object
        allowed_types (list): List of allowed MIME types
        max_size_mb (int): Maximum file size in MB
    
    Returns:
        dict: Validation result
    """
    errors = []
    
    if allowed_types and file.content_type not in allowed_types:
        errors.append(f"File type {file.content_type} is not allowed")
    
    max_size_bytes = max_size_mb * 1024 * 1024
    if file.size > max_size_bytes:
        errors.append(f"File size exceeds {max_size_mb}MB limit")
    
    return {
        'valid': len(errors) == 0,
        'errors': errors
    }


class SmartLibCache:
    """
    Utility class for caching operations
    """
    @staticmethod
    def get_cache_key(prefix, *args):
        """Generate cache key"""
        key_parts = [prefix] + [str(arg) for arg in args]
        return ':'.join(key_parts)
    
    @staticmethod
    def get_user_cache_key(user_id, key_type):
        """Generate user-specific cache key"""
        return f"user:{user_id}:{key_type}"
    
    @staticmethod
    def get_library_cache_key(library_id, key_type):
        """Generate library-specific cache key"""
        return f"library:{library_id}:{key_type}"