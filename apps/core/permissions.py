"""
Custom permissions for Smart Lib
"""
from rest_framework import permissions


class IsOwnerOrReadOnly(permissions.BasePermission):
    """
    Custom permission to only allow owners of an object to edit it.
    """
    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed for any request,
        # so we'll always allow GET, HEAD or OPTIONS requests.
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Write permissions are only allowed to the owner of the object.
        return obj.created_by == request.user


class IsStudentUser(permissions.BasePermission):
    """
    Permission to allow only student users
    """
    def has_permission(self, request, view):
        return (
            request.user and 
            request.user.is_authenticated and 
            hasattr(request.user, 'role') and
            request.user.role == 'STUDENT'
        )


class IsAdminUser(permissions.BasePermission):
    """
    Permission to allow only admin users
    """
    def has_permission(self, request, view):
        return (
            request.user and 
            request.user.is_authenticated and 
            hasattr(request.user, 'role') and
            request.user.role in ['ADMIN', 'SUPER_ADMIN']
        )


class IsSuperAdminUser(permissions.BasePermission):
    """
    Permission to allow only super admin users
    """
    def has_permission(self, request, view):
        return (
            request.user and 
            request.user.is_authenticated and 
            hasattr(request.user, 'role') and
            request.user.role == 'SUPER_ADMIN'
        )


class IsVerifiedUser(permissions.BasePermission):
    """
    Permission to allow only verified users
    """
    def has_permission(self, request, view):
        return (
            request.user and 
            request.user.is_authenticated and 
            hasattr(request.user, 'is_verified') and
            request.user.is_verified
        )


class CanAccessLibrary(permissions.BasePermission):
    """
    Permission to check if user can access a specific library
    """
    def has_object_permission(self, request, view, obj):
        # Super admins can access all libraries
        if request.user.role == 'SUPER_ADMIN':
            return True
        
        # Library admins can access their own library
        if request.user.role == 'ADMIN' and hasattr(request.user, 'managed_library'):
            return request.user.managed_library == obj
        
        # Students can access their assigned libraries
        if request.user.role == 'STUDENT':
            return obj in request.user.accessible_libraries.all()
        
        return False


class CanManageBookings(permissions.BasePermission):
    """
    Permission to manage seat bookings
    """
    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        
        # Only verified users can make bookings
        if not getattr(request.user, 'is_verified', False):
            return False
        
        # Check if user has active subscription for premium features
        if request.method in ['POST', 'PUT', 'PATCH']:
            return hasattr(request.user, 'current_subscription') and request.user.current_subscription
        
        return True
    
    def has_object_permission(self, request, view, obj):
        # Users can only manage their own bookings
        if request.method in permissions.SAFE_METHODS:
            return obj.user == request.user or request.user.role in ['ADMIN', 'SUPER_ADMIN']
        
        return obj.user == request.user