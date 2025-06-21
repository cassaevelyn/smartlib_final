"""
Custom middleware for Smart Lib
"""
from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth import get_user_model
from django.utils import timezone
from .models import ActivityLog
from .utils import get_user_ip
import logging

logger = logging.getLogger(__name__)
User = get_user_model()


class RequestLoggingMiddleware(MiddlewareMixin):
    """
    Middleware to log API requests for analytics and monitoring
    """
    def process_request(self, request):
        # Skip logging for certain endpoints
        skip_paths = ['/admin/', '/health/', '/static/', '/media/']
        if any(request.path.startswith(path) for path in skip_paths):
            return None
        
        # Log request details
        request.start_time = timezone.now()
        request.user_ip = get_user_ip(request)
        
        return None
    
    def process_response(self, request, response):
        # Skip for non-API requests
        if not request.path.startswith('/api/'):
            return response
        
        try:
            # Calculate request duration
            if hasattr(request, 'start_time'):
                from django.utils import timezone
                duration = (timezone.now() - request.start_time).total_seconds()
            else:
                duration = 0
            
            # Log API request
            logger.info(
                f"API Request: {request.method} {request.path} "
                f"Status: {response.status_code} "
                f"Duration: {duration:.3f}s "
                f"User: {getattr(request.user, 'username', 'Anonymous')} "
                f"IP: {getattr(request, 'user_ip', 'Unknown')}"
            )
        except Exception as e:
            logger.error(f"Error in request logging: {e}")
        
        return response


class UserActivityMiddleware(MiddlewareMixin):
    """
    Middleware to track user activities
    """
    def process_response(self, request, response):
        # Only track for authenticated users on successful API requests
        if (
            request.user.is_authenticated and 
            request.path.startswith('/api/') and 
            200 <= response.status_code < 300
        ):
            try:
                self.log_user_activity(request, response)
            except Exception as e:
                logger.error(f"Error logging user activity: {e}")
        
        return response
    
    def log_user_activity(self, request, response):
        """Log specific user activities"""
        path = request.path
        method = request.method
        
        # Map endpoints to activity types
        activity_mapping = {
            ('/api/v1/auth/login/', 'POST'): 'LOGIN',
            ('/api/v1/auth/logout/', 'POST'): 'LOGOUT',
            ('/api/v1/seats/book/', 'POST'): 'SEAT_BOOK',
            ('/api/v1/seats/checkin/', 'POST'): 'SEAT_CHECKIN',
            ('/api/v1/seats/checkout/', 'POST'): 'SEAT_CHECKOUT',
            ('/api/v1/books/reserve/', 'POST'): 'BOOK_RESERVE',
            ('/api/v1/events/register/', 'POST'): 'EVENT_REGISTER',
        }
        
        activity_key = (path, method)
        activity_type = activity_mapping.get(activity_key)
        
        if activity_type:
            ActivityLog.objects.create(
                user=request.user,
                activity_type=activity_type,
                description=f"{method} {path}",
                ip_address=getattr(request, 'user_ip', None),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                metadata={
                    'status_code': response.status_code,
                    'path': path,
                    'method': method,
                }
            )


class SecurityHeadersMiddleware(MiddlewareMixin):
    """
    Middleware to add security headers
    """
    def process_response(self, request, response):
        # Add security headers
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Add CORS headers for API requests
        if request.path.startswith('/api/'):
            response['Access-Control-Allow-Methods'] = 'GET, POST, PUT, PATCH, DELETE, OPTIONS'
            response['Access-Control-Allow-Headers'] = 'Accept, Authorization, Content-Type, X-Requested-With'
            response['Access-Control-Max-Age'] = '3600'
        
        return response