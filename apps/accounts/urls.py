# apps/accounts/urls.py
"""
URL patterns for accounts app
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

app_name = 'accounts'

urlpatterns = [
    # Authentication
    path('register/', views.UserRegistrationView.as_view(), name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('send-otp/', views.send_otp_view, name='send-otp'),
    path('verify-otp/', views.verify_otp_view, name='verify-otp'),
    path('verify-email/<str:token>/', views.EmailVerificationConfirmView.as_view(), name='verify-email'),
    
    # Password Management
    path('password/change/', views.PasswordChangeView.as_view(), name='password-change'),
    path('password/reset/', views.PasswordResetView.as_view(), name='password-reset'),
    path('password/reset/confirm/', views.PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    
    # User Profile
    path('profile/', views.UserProfileView.as_view(), name='profile'),
    path('profile/detail/', views.UserProfileDetailView.as_view(), name='profile-detail'),
    path('activities/', views.UserActivityListView.as_view(), name='user-activities'),
    
    # User Data
    path('loyalty-transactions/', views.LoyaltyTransactionListView.as_view(), name='loyalty-transactions'),
    path('sessions/', views.UserSessionListView.as_view(), name='sessions'),
    path('sessions/<uuid:session_id>/end/', views.end_session_view, name='end-session'),
    
    # User Preferences
    path('preferences/', views.UserPreferenceListCreateView.as_view(), name='preferences'),
    path('preferences/<uuid:pk>/', views.UserPreferenceDetailView.as_view(), name='preference-detail'),
    
    # Library Access
    path('apply-library-access/', views.LibraryApplicationView.as_view(), name='apply-library-access'),
    path('my-library-access/', views.UserLibraryAccessListView.as_view(), name='my-library-access'),
    
    # Admin Views
    path('users/', views.UserListView.as_view(), name='user-list'),
    path('users/<uuid:user_id>/', views.UserDetailView.as_view(), name='user-detail'),
    path('library-access/', views.UserLibraryAccessListCreateView.as_view(), name='library-access'),
    path('library-access/<uuid:access_id>/approve/', views.UserLibraryAccessApprovalView.as_view(), name='library-access-approval'),
    path('library-access/<uuid:access_id>/reject/', views.UserLibraryAccessRejectionView.as_view(), name='library-access-rejection'),
    
    # Admin Profile Management
    path('admin-profiles/', views.AdminProfileListView.as_view(), name='admin-profiles'),
    path('admin-profiles/create/', views.AdminProfileListCreateView.as_view(), name='admin-profile-create'),
    path('admin-profiles/<uuid:id>/', views.AdminProfileDetailView.as_view(), name='admin-profile-detail'),
    path('eligible-admin-users/', views.EligibleAdminUsersView.as_view(), name='eligible-admin-users'),
]