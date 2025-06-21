from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.html import format_html
from django.utils import timezone
from . import models


@admin.register(models.User)
class UserAdmin(BaseUserAdmin):
    list_display = [
        'email', 'full_name', 'crn', 'role', 'is_verified',
        'is_active', 'login_count', 'created_at'
    ]
    list_filter = [
        'role', 'is_verified', 'is_active', 'is_staff', 
        'created_at', 'last_login'
    ]
    search_fields = ['email', 'username', 'first_name', 'last_name', 'crn', 'student_id']
    readonly_fields = ['student_id', 'created_at', 'updated_at', 'login_count']
    ordering = ['-created_at']
    
    fieldsets = (
        (None, {
            'fields': ('username', 'email', 'password')
        }),
        ('Personal Info', {
            'fields': (
                'first_name', 'last_name', 'phone_number', 'date_of_birth',
                'gender', 'address', 'city', 'avatar', 'bio'
            )
        }),
        ('ICAP CA Info', {
            'fields': ('crn', 'student_id')
        }),
        ('Role & Status', {
            'fields': (
                'role', 'is_verified', 'is_active', 'is_staff', 'is_superuser'
            )
        }),
        ('Preferences', {
            'fields': ('preferred_language', 'notification_preferences'),
            'classes': ('collapse',)
        }),
        ('Tracking', {
            'fields': ('last_login', 'last_login_ip', 'login_count', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
        ('Permissions', {
            'fields': ('groups', 'user_permissions'),
            'classes': ('collapse',)
        }),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': (
                'username', 'email', 'password1', 'password2',
                'first_name', 'last_name', 'crn', 'role'
            ),
        }),
    )
    
    def full_name(self, obj):
        return obj.get_full_name()
    full_name.short_description = 'Full Name'
    
    actions = ['deactivate_users', 'activate_users', 'verify_users']
    
    def deactivate_users(self, request, queryset):
        updated = queryset.update(is_active=False)
        self.message_user(request, f'{updated} users deactivated successfully.')
    deactivate_users.short_description = 'Deactivate selected users'
    
    def activate_users(self, request, queryset):
        updated = queryset.update(is_active=True)
        self.message_user(request, f'{updated} users activated successfully.')
    activate_users.short_description = 'Activate selected users'
    
    def verify_users(self, request, queryset):
        updated = queryset.update(is_verified=True)
        self.message_user(request, f'{updated} users verified successfully.')
    verify_users.short_description = 'Verify selected users'


@admin.register(models.UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = [
        'user', 'education_level', 'enrollment_year', 'loyalty_points',
        'total_study_hours', 'books_read', 'events_attended'
    ]
    list_filter = ['education_level', 'enrollment_year', 'preferred_study_time']
    search_fields = ['user__email', 'user__first_name', 'user__last_name']
    readonly_fields = ['created_at', 'updated_at']
    
    fieldsets = (
        ('User', {
            'fields': ('user',)
        }),
        ('Academic Info', {
            'fields': (
                'education_level', 'enrollment_year', 'expected_completion_year',
                'study_subjects'
            )
        }),
        ('Emergency Contact', {
            'fields': (
                'emergency_contact_name', 'emergency_contact_phone',
                'emergency_contact_relation'
            )
        }),
        ('Preferences', {
            'fields': ('preferred_study_time', 'preferred_seat_type')
        }),
        ('Statistics', {
            'fields': (
                'loyalty_points', 'total_study_hours', 'books_read', 'events_attended'
            )
        }),
    )


@admin.register(models.LoyaltyTransaction)
class LoyaltyTransactionAdmin(admin.ModelAdmin):
    list_display = [
        'user', 'points', 'transaction_type', 'description', 'created_at'
    ]
    list_filter = ['transaction_type', 'created_at']
    search_fields = ['user__email', 'user__first_name', 'user__last_name', 'description']
    readonly_fields = ['created_at', 'updated_at']
    date_hierarchy = 'created_at'
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False


@admin.register(models.UserSession)
class UserSessionAdmin(admin.ModelAdmin):
    list_display = [
        'user', 'ip_address', 'is_active', 'created_at', 'last_activity', 'logout_time'
    ]
    list_filter = ['is_active', 'created_at', 'last_activity']
    search_fields = ['user__email', 'ip_address']
    readonly_fields = ['created_at', 'updated_at']
    date_hierarchy = 'created_at'
    
    def has_add_permission(self, request):
        return False


@admin.register(models.UserVerification)
class UserVerificationAdmin(admin.ModelAdmin):
    list_display = [
        'user', 'verification_type', 'is_verified', 'attempts',
        'expires_at', 'created_at', 'last_resend_attempt'
    ]
    list_filter = ['verification_type', 'is_verified', 'created_at']
    search_fields = ['user__email', 'token']
    readonly_fields = ['token', 'created_at', 'updated_at']
    
    def has_add_permission(self, request):
        return False


@admin.register(models.UserPreference)
class UserPreferenceAdmin(admin.ModelAdmin):
    list_display = ['user', 'category', 'key', 'created_at']
    list_filter = ['category', 'created_at']
    search_fields = ['user__email', 'key']
    readonly_fields = ['created_at', 'updated_at']


@admin.register(models.UserLibraryAccess)
class UserLibraryAccessAdmin(admin.ModelAdmin):
    list_display = [
        'user', 'library', 'access_type', 'is_active',
        'granted_by', 'granted_at', 'expires_at'
    ]
    list_filter = ['access_type', 'is_active', 'granted_at']
    search_fields = ['user__email', 'library__name', 'notes']
    readonly_fields = ['granted_at', 'created_at', 'updated_at']
    
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        # If user is a super admin, show all applications
        if request.user.is_superuser or request.user.role == 'SUPER_ADMIN':
            return qs
        # If user is a library admin, show only applications for their library
        elif request.user.role == 'ADMIN':
            try:
                admin_profile = request.user.admin_profile
                if admin_profile and admin_profile.managed_library:
                    return qs.filter(library=admin_profile.managed_library)
            except models.AdminProfile.DoesNotExist:
                pass
        # Default: return empty queryset
        return qs.none()
    
    actions = ['approve_selected_access', 'reject_selected_access']
    
    def approve_selected_access(self, request, queryset):
        """Approve selected library access applications"""
        from django.utils import timezone
        from apps.core.models import ActivityLog
        
        updated_count = 0
        for application in queryset:
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
            
            updated_count += 1
        
        self.message_user(request, f'{updated_count} library access applications approved successfully.')
    approve_selected_access.short_description = 'Approve selected library access applications'
    
    def reject_selected_access(self, request, queryset):
        """Reject selected library access applications"""
        from django.utils import timezone
        from apps.core.models import ActivityLog
        
        updated_count = 0
        for application in queryset:
            # Update application status
            application.is_active = False
            
            # Add rejection note
            rejection_note = f"\n[REJECTED by {request.user.full_name} on {timezone.now().strftime('%Y-%m-%d %H:%M')}]"
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
                        'rejected_at': timezone.now().isoformat()
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
                    'application_id': str(application.id)
                }
            )
            
            updated_count += 1
        
        self.message_user(request, f'{updated_count} library access applications rejected successfully.')
    reject_selected_access.short_description = 'Reject selected library access applications'


@admin.register(models.AdminProfile)
class AdminProfileAdmin(admin.ModelAdmin):
    list_display = [
        'user', 'managed_library', 'can_manage_events', 
        'can_manage_books', 'can_view_analytics'
    ]
    list_filter = [
        'can_manage_events', 'can_manage_books', 'can_view_analytics'
    ]
    search_fields = ['user__email', 'managed_library__name']
    readonly_fields = ['created_at', 'updated_at']
    
    fieldsets = (
        ('Admin User', {
            'fields': ('user', 'managed_library')
        }),
        ('Permissions', {
            'fields': (
                'can_manage_events', 'can_manage_books', 
                'can_view_analytics', 'permissions'
            )
        }),
    )
    
    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        # Filter the user dropdown to only show users with role ADMIN or SUPER_ADMIN
        if db_field.name == "user":
            kwargs["queryset"] = models.User.objects.filter(role__in=['ADMIN', 'SUPER_ADMIN'])
        return super().formfield_for_foreignkey(db_field, request, **kwargs)