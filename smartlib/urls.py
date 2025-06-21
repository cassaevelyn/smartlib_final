"""
SmartLib URL Configuration
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.http import JsonResponse

def health_check(request):
    """Health check endpoint"""
    return JsonResponse({'status': 'healthy', 'service': 'Smart Lib API'})

api_v1_patterns = [
    path('auth/', include('apps.accounts.urls')),
    path('libraries/', include('apps.library.urls')),
    path('seats/', include('apps.seats.urls')),
    path('books/', include('apps.books.urls')),
    path('events/', include('apps.events.urls')),
    path('dashboard/', include('apps.dashboard.urls')),
    path('notifications/', include('apps.notifications.urls')),
    path('subscriptions/', include('apps.subscriptions.urls')),
    path('analytics/', include('apps.analytics.urls')),
    path('recommendations/', include('apps.recommendations.urls')),
]

urlpatterns = [
    path('admin/', admin.site.urls),
    path('health/', health_check, name='health_check'),
    path('api/v1/', include(api_v1_patterns)),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

# Admin site customization
admin.site.site_header = "Smart Lib Administration"
admin.site.site_title = "Smart Lib Admin"
admin.site.index_title = "Welcome to Smart Lib Administration"