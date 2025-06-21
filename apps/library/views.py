"""
Views for library app
"""
from rest_framework import generics, status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from django.db.models import Q, Count, Avg
from django.utils import timezone
from apps.core.permissions import IsAdminUser, IsSuperAdminUser
from .models import (
    Library, LibraryFloor, LibrarySection, LibraryAmenity,
    LibraryOperatingHours, LibraryHoliday, LibraryReview,
    LibraryStatistics, LibraryNotification, LibraryConfiguration
)
from .serializers import (
    LibraryListSerializer, LibraryDetailSerializer, LibraryFloorSerializer,
    LibrarySectionSerializer, LibraryAmenitySerializer, LibraryOperatingHoursSerializer,
    LibraryHolidaySerializer, LibraryReviewSerializer, LibraryStatisticsSerializer,
    LibraryNotificationSerializer, LibraryConfigurationSerializer, LibrarySearchSerializer,
    LibraryAdminSerializer, LibraryFloorAdminSerializer, LibrarySectionAdminSerializer,
    LibraryAmenityAdminSerializer, LibraryOperatingHoursAdminSerializer, LibraryHolidayAdminSerializer
)


class LibraryListView(generics.ListAPIView):
    """List all libraries with search and filtering"""
    serializer_class = LibraryListSerializer
    permission_classes = [permissions.IsAuthenticated]
    filterset_fields = ['library_type', 'status', 'city', 'has_wifi', 'has_parking']
    search_fields = ['name', 'city', 'address']
    ordering_fields = ['name', 'city', 'average_rating', 'total_seats']
    ordering = ['name']
    
    def get_queryset(self):
        queryset = Library.objects.filter(is_deleted=False)

        user = self.request.user

        # If the user is a super admin, they can see all libraries
        if user.is_super_admin:
            pass  # No additional filtering needed for super admins
        # If the user is an admin, they can only see their managed library
        elif user.role == 'ADMIN':
            admin_profile = getattr(user, 'admin_profile', None)
            if admin_profile and admin_profile.managed_library:
                queryset = queryset.filter(id=admin_profile.managed_library.id)
            else:
                queryset = queryset.none()
        # For students and other roles
        else:
            if not user.is_verified:
                # For unverified users, show all ACTIVE libraries they can apply for
                queryset = queryset.filter(status='ACTIVE')
            else:
                # For verified students, show only libraries they have active access to
                accessible_libraries = user.library_access.filter(
                    is_active=True
                ).values_list('library_id', flat=True)
                queryset = queryset.filter(id__in=accessible_libraries)

        return queryset


class LibraryDetailView(generics.RetrieveAPIView):
    """Get library details"""
    serializer_class = LibraryDetailSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'id'
    
    def get_queryset(self):
        return Library.objects.filter(is_deleted=False).prefetch_related(
            'floors__sections',
            'amenities',
            'operating_hours',
            'holidays',
            'reviews__user'
        )
    
    def get_object(self):
        obj = super().get_object()
        
        # Check if user can access this library
        if not obj.can_user_access(self.request.user):
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied("You don't have access to this library")
        
        return obj


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def search_libraries(request):
    """Advanced library search"""
    serializer = LibrarySearchSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    
    data = serializer.validated_data
    queryset = Library.objects.filter(is_deleted=False, status='ACTIVE')
    
    # Apply filters
    if data.get('query'):
        queryset = queryset.filter(
            Q(name__icontains=data['query']) |
            Q(description__icontains=data['query']) |
            Q(city__icontains=data['query'])
        )
    
    if data.get('city'):
        queryset = queryset.filter(city__icontains=data['city'])
    
    if data.get('library_type'):
        queryset = queryset.filter(library_type=data['library_type'])
    
    if data.get('has_wifi') is not None:
        queryset = queryset.filter(has_wifi=data['has_wifi'])
    
    if data.get('has_parking') is not None:
        queryset = queryset.filter(has_parking=data['has_parking'])
    
    if data.get('has_cafeteria') is not None:
        queryset = queryset.filter(has_cafeteria=data['has_cafeteria'])
    
    if data.get('is_24_hours') is not None:
        queryset = queryset.filter(is_24_hours=data['is_24_hours'])
    
    if data.get('min_available_seats'):
        # This would require a more complex query with seat availability
        pass
    
    # Apply user access restrictions
    user = request.user
    if not user.is_super_admin:
        if user.role == 'ADMIN':
            admin_profile = getattr(user, 'admin_profile', None)
            if admin_profile and admin_profile.managed_library:
                queryset = queryset.filter(id=admin_profile.managed_library.id)
            else:
                queryset = queryset.none()
        else:
            accessible_libraries = user.library_access.filter(
                is_active=True
            ).values_list('library_id', flat=True)
            queryset = queryset.filter(id__in=accessible_libraries)
    
    # Apply sorting
    sort_by = data.get('sort_by', 'name')
    if sort_by == 'rating':
        queryset = queryset.order_by('-average_rating')
    elif sort_by == 'available_seats':
        # This would require a more complex query
        queryset = queryset.order_by('-total_seats')
    else:
        queryset = queryset.order_by('name')
    
    # Serialize results
    serializer = LibraryListSerializer(queryset, many=True, context={'request': request})
    
    return Response({
        'count': queryset.count(),
        'results': serializer.data
    })


class LibraryFloorListView(generics.ListAPIView):
    """List floors for a specific library"""
    serializer_class = LibraryFloorSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        library_id = self.kwargs['library_id']
        return LibraryFloor.objects.filter(
            library_id=library_id,
            is_deleted=False
        ).prefetch_related('sections')
    
    def get_serializer_context(self):
        context = super().get_serializer_context()
        library_id = self.kwargs['library_id']
        
        # Check library access
        try:
            library = Library.objects.get(id=library_id, is_deleted=False)
            if not library.can_user_access(self.request.user):
                from rest_framework.exceptions import PermissionDenied
                raise PermissionDenied("You don't have access to this library")
        except Library.DoesNotExist:
            from rest_framework.exceptions import NotFound
            raise NotFound("Library not found")
        
        return context


class LibrarySectionListView(generics.ListAPIView):
    """List sections for a specific floor"""
    serializer_class = LibrarySectionSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        floor_id = self.kwargs['floor_id']
        return LibrarySection.objects.filter(
            floor_id=floor_id,
            is_deleted=False
        )


class LibraryReviewListCreateView(generics.ListCreateAPIView):
    """List and create library reviews"""
    serializer_class = LibraryReviewSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        library_id = self.kwargs['library_id']
        return LibraryReview.objects.filter(
            library_id=library_id,
            is_approved=True,
            is_deleted=False
        ).select_related('user').order_by('-created_at')
    
    def perform_create(self, serializer):
        library_id = self.kwargs['library_id']
        
        # Check if library exists and user has access
        try:
            library = Library.objects.get(id=library_id, is_deleted=False)
            if not library.can_user_access(self.request.user):
                from rest_framework.exceptions import PermissionDenied
                raise PermissionDenied("You don't have access to this library")
        except Library.DoesNotExist:
            from rest_framework.exceptions import NotFound
            raise NotFound("Library not found")
        
        # Check if user already reviewed this library
        if LibraryReview.objects.filter(
            library=library,
            user=self.request.user,
            is_deleted=False
        ).exists():
            from rest_framework.exceptions import ValidationError
            raise ValidationError("You have already reviewed this library")
        
        serializer.save(
            library=library,
            created_by=self.request.user
        )


class LibraryNotificationListView(generics.ListAPIView):
    """List active notifications for a library"""
    serializer_class = LibraryNotificationSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        library_id = self.kwargs['library_id']
        now = timezone.now()
        
        queryset = LibraryNotification.objects.filter(
            library_id=library_id,
            is_active=True,
            start_date__lte=now,
            is_deleted=False
        ).filter(
            Q(end_date__isnull=True) | Q(end_date__gte=now)
        )
        
        # Filter by user role if targeting is specified
        user = self.request.user
        queryset = queryset.filter(
            Q(target_all_users=True) |
            Q(target_user_roles__contains=[user.role])
        )
        
        return queryset.order_by('-priority', '-created_at')


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def mark_notification_viewed(request, notification_id):
    """Mark notification as viewed"""
    try:
        notification = LibraryNotification.objects.get(
            id=notification_id,
            is_deleted=False
        )
        
        # Increment view count
        notification.views_count += 1
        notification.save()
        
        return Response({'message': 'Notification marked as viewed'})
        
    except LibraryNotification.DoesNotExist:
        return Response(
            {'error': 'Notification not found'},
            status=status.HTTP_404_NOT_FOUND
        )


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def acknowledge_notification(request, notification_id):
    """Acknowledge notification (if required)"""
    try:
        notification = LibraryNotification.objects.get(
            id=notification_id,
            requires_acknowledgment=True,
            is_deleted=False
        )
        
        # Increment acknowledgment count
        notification.acknowledgments_count += 1
        notification.save()
        
        # You might want to track individual user acknowledgments
        # in a separate model for more detailed tracking
        
        return Response({'message': 'Notification acknowledged'})
        
    except LibraryNotification.DoesNotExist:
        return Response(
            {'error': 'Notification not found or does not require acknowledgment'},
            status=status.HTTP_404_NOT_FOUND
        )


# Admin Views
class LibraryManagementView(generics.ListCreateAPIView):
    """Admin view for managing libraries"""
    serializer_class = LibraryAdminSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def get_queryset(self):
        if self.request.user.is_super_admin:
            return Library.objects.filter(is_deleted=False)
        elif self.request.user.role == 'ADMIN':
            admin_profile = getattr(self.request.user, 'admin_profile', None)
            if admin_profile and admin_profile.managed_library:
                return Library.objects.filter(
                    id=admin_profile.managed_library.id,
                    is_deleted=False
                )
        return Library.objects.none()
    
    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)


class LibraryDetailManagementView(generics.RetrieveUpdateDestroyAPIView):
    """Admin view for retrieving, updating, or deleting a specific library"""
    serializer_class = LibraryAdminSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    lookup_field = 'id'

    def get_queryset(self):
        if self.request.user.is_super_admin:
            return Library.objects.filter(is_deleted=False)
        elif self.request.user.role == 'ADMIN':
            admin_profile = getattr(self.request.user, 'admin_profile', None)
            if admin_profile and admin_profile.managed_library:
                return Library.objects.filter(
                    id=admin_profile.managed_library.id,
                    is_deleted=False
                )
        return Library.objects.none()

    def perform_update(self, serializer):
        serializer.save(updated_by=self.request.user)

    def perform_destroy(self, instance):
        instance.soft_delete()


class LibraryStatisticsView(generics.ListAPIView):
    """View library statistics"""
    serializer_class = LibraryStatisticsSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def get_queryset(self):
        library_id = self.kwargs.get('library_id')
        queryset = LibraryStatistics.objects.all()
        
        if library_id:
            queryset = queryset.filter(library_id=library_id)
        
        # Filter based on user permissions
        if not self.request.user.is_super_admin:
            admin_profile = getattr(self.request.user, 'admin_profile', None)
            if admin_profile and admin_profile.managed_library:
                queryset = queryset.filter(library=admin_profile.managed_library)
            else:
                queryset = queryset.none()
        
        return queryset.order_by('-date')


class LibraryConfigurationView(generics.RetrieveUpdateAPIView):
    """View and update library configuration"""
    serializer_class = LibraryConfigurationSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    lookup_field = 'library_id'
    lookup_url_kwarg = 'library_id'
    
    def get_queryset(self):
        if self.request.user.is_super_admin:
            return LibraryConfiguration.objects.all()
        elif self.request.user.role == 'ADMIN':
            admin_profile = getattr(self.request.user, 'admin_profile', None)
            if admin_profile and admin_profile.managed_library:
                return LibraryConfiguration.objects.filter(
                    library=admin_profile.managed_library
                )
        return LibraryConfiguration.objects.none()
    
    def get_object(self):
        library_id = self.kwargs['library_id']
        try:
            return LibraryConfiguration.objects.get(library_id=library_id)
        except LibraryConfiguration.DoesNotExist:
            # Create default configuration if it doesn't exist
            library = Library.objects.get(id=library_id)
            return LibraryConfiguration.objects.create(
                library=library,
                created_by=self.request.user
            )


class LibraryFloorManagementView(generics.ListCreateAPIView):
    """Admin view for managing library floors"""
    serializer_class = LibraryFloorAdminSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]

    def get_queryset(self):
        library_id = self.kwargs.get('library_id')
        queryset = LibraryFloor.objects.filter(is_deleted=False)
        if library_id:
            queryset = queryset.filter(library_id=library_id)
        
        if self.request.user.is_super_admin:
            return queryset
        elif self.request.user.role == 'ADMIN':
            admin_profile = getattr(self.request.user, 'admin_profile', None)
            if admin_profile and admin_profile.managed_library:
                return queryset.filter(library=admin_profile.managed_library)
        return queryset.none()

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)


class LibraryFloorDetailManagementView(generics.RetrieveUpdateDestroyAPIView):
    """Admin view for retrieving, updating, or deleting a specific library floor"""
    serializer_class = LibraryFloorAdminSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    lookup_field = 'id'

    def get_queryset(self):
        queryset = LibraryFloor.objects.filter(is_deleted=False)
        if self.request.user.is_super_admin:
            return queryset
        elif self.request.user.role == 'ADMIN':
            admin_profile = getattr(self.request.user, 'admin_profile', None)
            if admin_profile and admin_profile.managed_library:
                return queryset.filter(library=admin_profile.managed_library)
        return queryset.none()

    def perform_update(self, serializer):
        serializer.save(updated_by=self.request.user)

    def perform_destroy(self, instance):
        instance.soft_delete()


class LibrarySectionManagementView(generics.ListCreateAPIView):
    """Admin view for managing library sections"""
    serializer_class = LibrarySectionAdminSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]

    def get_queryset(self):
        floor_id = self.kwargs.get('floor_id')
        queryset = LibrarySection.objects.filter(is_deleted=False)
        if floor_id:
            queryset = queryset.filter(floor_id=floor_id)
        
        if self.request.user.is_super_admin:
            return queryset
        elif self.request.user.role == 'ADMIN':
            admin_profile = getattr(self.request.user, 'admin_profile', None)
            if admin_profile and admin_profile.managed_library:
                return queryset.filter(floor__library=admin_profile.managed_library)
        return queryset.none()

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)


class LibrarySectionDetailManagementView(generics.RetrieveUpdateDestroyAPIView):
    """Admin view for retrieving, updating, or deleting a specific library section"""
    serializer_class = LibrarySectionAdminSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    lookup_field = 'id'

    def get_queryset(self):
        queryset = LibrarySection.objects.filter(is_deleted=False)
        if self.request.user.is_super_admin:
            return queryset
        elif self.request.user.role == 'ADMIN':
            admin_profile = getattr(self.request.user, 'admin_profile', None)
            if admin_profile and admin_profile.managed_library:
                return queryset.filter(floor__library=admin_profile.managed_library)
        return queryset.none()

    def perform_update(self, serializer):
        serializer.save(updated_by=self.request.user)

    def perform_destroy(self, instance):
        instance.soft_delete()


class LibraryAmenityManagementView(generics.ListCreateAPIView):
    """Admin view for managing library amenities"""
    serializer_class = LibraryAmenityAdminSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]

    def get_queryset(self):
        library_id = self.kwargs.get('library_id')
        queryset = LibraryAmenity.objects.filter(is_deleted=False)
        if library_id:
            queryset = queryset.filter(library_id=library_id)
        
        if self.request.user.is_super_admin:
            return queryset
        elif self.request.user.role == 'ADMIN':
            admin_profile = getattr(self.request.user, 'admin_profile', None)
            if admin_profile and admin_profile.managed_library:
                return queryset.filter(library=admin_profile.managed_library)
        return queryset.none()

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)


class LibraryAmenityDetailManagementView(generics.RetrieveUpdateDestroyAPIView):
    """Admin view for retrieving, updating, or deleting a specific library amenity"""
    serializer_class = LibraryAmenityAdminSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    lookup_field = 'id'

    def get_queryset(self):
        queryset = LibraryAmenity.objects.filter(is_deleted=False)
        if self.request.user.is_super_admin:
            return queryset
        elif self.request.user.role == 'ADMIN':
            admin_profile = getattr(self.request.user, 'admin_profile', None)
            if admin_profile and admin_profile.managed_library:
                return queryset.filter(library=admin_profile.managed_library)
        return queryset.none()

    def perform_update(self, serializer):
        serializer.save(updated_by=self.request.user)

    def perform_destroy(self, instance):
        instance.soft_delete()


class LibraryOperatingHoursManagementView(generics.ListCreateAPIView):
    """Admin view for managing library operating hours"""
    serializer_class = LibraryOperatingHoursAdminSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]

    def get_queryset(self):
        library_id = self.kwargs.get('library_id')
        queryset = LibraryOperatingHours.objects.filter(is_deleted=False)
        if library_id:
            queryset = queryset.filter(library_id=library_id)
        
        if self.request.user.is_super_admin:
            return queryset
        elif self.request.user.role == 'ADMIN':
            admin_profile = getattr(self.request.user, 'admin_profile', None)
            if admin_profile and admin_profile.managed_library:
                return queryset.filter(library=admin_profile.managed_library)
        return queryset.none()

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)


class LibraryOperatingHoursDetailManagementView(generics.RetrieveUpdateDestroyAPIView):
    """Admin view for retrieving, updating, or deleting specific library operating hours"""
    serializer_class = LibraryOperatingHoursAdminSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    lookup_field = 'id'

    def get_queryset(self):
        queryset = LibraryOperatingHours.objects.filter(is_deleted=False)
        if self.request.user.is_super_admin:
            return queryset
        elif self.request.user.role == 'ADMIN':
            admin_profile = getattr(self.request.user, 'admin_profile', None)
            if admin_profile and admin_profile.managed_library:
                return queryset.filter(library=admin_profile.managed_library)
        return queryset.none()

    def perform_update(self, serializer):
        serializer.save(updated_by=self.request.user)

    def perform_destroy(self, instance):
        instance.soft_delete()


class LibraryHolidayManagementView(generics.ListCreateAPIView):
    """Admin view for managing library holidays"""
    serializer_class = LibraryHolidayAdminSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]

    def get_queryset(self):
        library_id = self.kwargs.get('library_id')
        queryset = LibraryHoliday.objects.filter(is_deleted=False)
        if library_id:
            queryset = queryset.filter(library_id=library_id)
        
        if self.request.user.is_super_admin:
            return queryset
        elif self.request.user.role == 'ADMIN':
            admin_profile = getattr(self.request.user, 'admin_profile', None)
            if admin_profile and admin_profile.managed_library:
                return queryset.filter(library=admin_profile.managed_library)
        return queryset.none()

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)


class LibraryHolidayDetailManagementView(generics.RetrieveUpdateDestroyAPIView):
    """Admin view for retrieving, updating, or deleting a specific library holiday"""
    serializer_class = LibraryHolidayAdminSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    lookup_field = 'id'

    def get_queryset(self):
        queryset = LibraryHoliday.objects.filter(is_deleted=False)
        if self.request.user.is_super_admin:
            return queryset
        elif self.request.user.role == 'ADMIN':
            admin_profile = getattr(self.request.user, 'admin_profile', None)
            if admin_profile and admin_profile.managed_library:
                return queryset.filter(library=admin_profile.managed_library)
        return queryset.none()

    def perform_update(self, serializer):
        serializer.save(updated_by=self.request.user)

    def perform_destroy(self, instance):
        instance.soft_delete()