"""
Custom managers for accounts app
"""
from django.contrib.auth.models import BaseUserManager
from django.db import models


class UserManager(BaseUserManager):
    """Custom user manager"""
    
    def create_user(self, email, username, crn, password=None, **extra_fields):
        """Create and return a regular user"""
        if not email:
            raise ValueError('Email is required')
        if not username:
            raise ValueError('Username is required')
        if not crn:
            raise ValueError('CRN is required')
        
        email = self.normalize_email(email)
        user = self.model(
            email=email,
            username=username,
            crn=crn,
            **extra_fields
        )
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, email, username, crn, password=None, **extra_fields):
        """Create and return a superuser"""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('is_verified', True)
        extra_fields.setdefault('role', 'SUPER_ADMIN')
        
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True')
        
        return self.create_user(email, username, crn, password, **extra_fields)


class ActiveUserManager(models.Manager):
    """Manager for active users only"""
    
    def get_queryset(self):
        return super().get_queryset().filter(is_active=True, is_deleted=False)


class VerifiedUserManager(models.Manager):
    """Manager for verified users only"""
    
    def get_queryset(self):
        return super().get_queryset().filter(
            is_active=True, 
            is_verified=True, 
            is_deleted=False
        )


class StudentManager(models.Manager):
    """Manager for student users only"""
    
    def get_queryset(self):
        return super().get_queryset().filter(
            role='STUDENT',
            is_active=True,
            is_verified=True,
            is_deleted=False
        )


class AdminManager(models.Manager):
    """Manager for admin users only"""
    
    def get_queryset(self):
        return super().get_queryset().filter(
            role__in=['ADMIN', 'SUPER_ADMIN'],
            is_active=True,
            is_deleted=False
        )