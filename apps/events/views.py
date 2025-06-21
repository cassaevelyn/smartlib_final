"""
Views for events app
"""
from rest_framework import generics, status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from django.db.models import Q, Count, Avg
from django.utils import timezone
from django.shortcuts import get_object_or_404
from apps.core.permissions import IsAdminUser
from .models import (
    EventCategory, EventSpeaker, Event, EventRegistration,
    EventFeedback, EventWaitlist, EventResource, EventStatistics,
    EventSeries, EventNotification
)
from .serializers import (
    EventCategorySerializer, EventSpeakerSerializer, EventListSerializer,
    EventDetailSerializer, EventRegistrationSerializer, EventRegistrationCreateSerializer,
    EventFeedbackSerializer, EventResourceSerializer, EventWaitlistSerializer,
    EventSeriesSerializer, EventNotificationSerializer, EventSearchSerializer,
    CheckInSerializer, CheckOutSerializer, QRCodeDataSerializer
)
import json


class EventCategoryListView(generics.ListAPIView):
    """List event categories"""
    serializer_class = EventCategorySerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return EventCategory.objects.filter(
            is_active=True,
            is_deleted=False
        ).order_by('sort_order', 'name')


class EventSpeakerListView(generics.ListAPIView):
    """List event speakers"""
    serializer_class = EventSpeakerSerializer
    permission_classes = [permissions.IsAuthenticated]
    search_fields = ['first_name', 'last_name', 'organization']
    ordering_fields = ['last_name', 'first_name', 'total_events', 'average_rating']
    ordering = ['last_name', 'first_name']
    
    def get_queryset(self):
        return EventSpeaker.objects.filter(is_deleted=False)


class EventListView(generics.ListAPIView):
    """List events with filtering and search"""
    serializer_class = EventListSerializer
    permission_classes = [permissions.IsAuthenticated]
    filterset_fields = [
        'category', 'event_type', 'status', 'library', 'registration_type',
        'is_online', 'has_certificate', 'organizer'
    ]
    search_fields = ['title', 'description', 'speakers__first_name', 'speakers__last_name']
    ordering_fields = [
        'start_date', 'start_time', 'title', 'registration_deadline',
        'total_registrations', 'average_rating'
    ]
    ordering = ['start_date', 'start_time']
    
    def get_queryset(self):
        queryset = Event.objects.filter(
            is_deleted=False,
            status__in=['PUBLISHED', 'REGISTRATION_OPEN', 'REGISTRATION_CLOSED', 'IN_PROGRESS']
        )
        
        # Filter based on user access
        user = self.request.user
        if not user.is_super_admin:
            if user.role == 'ADMIN':
                admin_profile = getattr(user, 'admin_profile', None)
                if admin_profile and admin_profile.managed_library:
                    queryset = queryset.filter(library=admin_profile.managed_library)
                else:
                    queryset = queryset.none()
            else:
                # Students can see events in libraries they have access to
                accessible_libraries = user.library_access.filter(
                    is_active=True
                ).values_list('library_id', flat=True)
                queryset = queryset.filter(library_id__in=accessible_libraries)
        
        return queryset.select_related('category', 'library', 'organizer').prefetch_related('speakers')


class EventDetailView(generics.RetrieveAPIView):
    """Get event details"""
    serializer_class = EventDetailSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'id'
    
    def get_queryset(self):
        return Event.objects.filter(is_deleted=False).select_related(
            'category', 'library', 'organizer'
        ).prefetch_related('speakers', 'co_organizers')


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def search_events(request):
    """Advanced event search"""
    serializer = EventSearchSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    
    data = serializer.validated_data
    queryset = Event.objects.filter(
        is_deleted=False,
        status__in=['PUBLISHED', 'REGISTRATION_OPEN', 'REGISTRATION_CLOSED', 'IN_PROGRESS']
    )
    
    # Apply filters
    if data.get('query'):
        queryset = queryset.filter(
            Q(title__icontains=data['query']) |
            Q(description__icontains=data['query']) |
            Q(speakers__first_name__icontains=data['query']) |
            Q(speakers__last_name__icontains=data['query']) |
            Q(organizer__first_name__icontains=data['query']) |
            Q(organizer__last_name__icontains=data['query'])
        ).distinct()
    
    if data.get('category_id'):
        queryset = queryset.filter(category_id=data['category_id'])
    
    if data.get('event_type'):
        queryset = queryset.filter(event_type=data['event_type'])
    
    if data.get('library_id'):
        queryset = queryset.filter(library_id=data['library_id'])
    
    if data.get('start_date_from'):
        queryset = queryset.filter(start_date__gte=data['start_date_from'])
    
    if data.get('start_date_to'):
        queryset = queryset.filter(start_date__lte=data['start_date_to'])
    
    if data.get('is_online') is not None:
        queryset = queryset.filter(is_online=data['is_online'])
    
    if data.get('is_free') is not None:
        if data['is_free']:
            queryset = queryset.filter(registration_fee=0)
        else:
            queryset = queryset.filter(registration_fee__gt=0)
    
    if data.get('has_certificate') is not None:
        queryset = queryset.filter(has_certificate=data['has_certificate'])
    
    if data.get('registration_open') is not None:
        if data['registration_open']:
            queryset = queryset.filter(
                status='REGISTRATION_OPEN',
                registration_deadline__gte=timezone.now()
            )
    
    # Apply user access restrictions
    user = request.user
    if not user.is_super_admin:
        if user.role == 'ADMIN':
            admin_profile = getattr(user, 'admin_profile', None)
            if admin_profile and admin_profile.managed_library:
                queryset = queryset.filter(library=admin_profile.managed_library)
            else:
                queryset = queryset.none()
        else:
            accessible_libraries = user.library_access.filter(
                is_active=True
            ).values_list('library_id', flat=True)
            queryset = queryset.filter(library_id__in=accessible_libraries)
    
    # Apply sorting
    sort_by = data.get('sort_by', 'start_date')
    if sort_by == 'title':
        queryset = queryset.order_by('title')
    elif sort_by == 'registration_deadline':
        queryset = queryset.order_by('registration_deadline')
    elif sort_by == 'popularity':
        queryset = queryset.order_by('-total_registrations', '-total_attendees')
    elif sort_by == 'rating':
        queryset = queryset.order_by('-average_rating')
    else:
        queryset = queryset.order_by('start_date', 'start_time')
    
    # Serialize results
    serializer = EventListSerializer(queryset, many=True, context={'request': request})
    
    return Response({
        'count': queryset.count(),
        'results': serializer.data
    })


class EventRegistrationListCreateView(generics.ListCreateAPIView):
    """List and create event registrations"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get_serializer_class(self):
        if self.request.method == 'POST':
            return EventRegistrationCreateSerializer
        return EventRegistrationSerializer
    
    def get_queryset(self):
        user = self.request.user
        queryset = EventRegistration.objects.filter(is_deleted=False)
        
        # Filter by user unless admin
        if not user.is_admin:
            queryset = queryset.filter(user=user)
        
        return queryset.select_related('user', 'event').order_by('-registration_date')


class EventRegistrationDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Event registration detail view"""
    serializer_class = EventRegistrationSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'id'
    
    def get_queryset(self):
        user = self.request.user
        queryset = EventRegistration.objects.filter(is_deleted=False)
        
        # Users can only access their own registrations unless admin
        if not user.is_admin:
            queryset = queryset.filter(user=user)
        
        return queryset.select_related('user', 'event')
    
    def destroy(self, request, *args, **kwargs):
        """Cancel registration instead of deleting"""
        registration = self.get_object()
        success, message = registration.cancel_registration('Cancelled by user')
        
        if success:
            return Response({'message': message})
        else:
            return Response(
                {'error': message},
                status=status.HTTP_400_BAD_REQUEST
            )


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def generate_qr_code(request, registration_id):
    """Generate QR code for event registration"""
    try:
        registration = EventRegistration.objects.get(
            id=registration_id,
            user=request.user,
            is_deleted=False
        )
        
        if registration.status not in ['CONFIRMED', 'ATTENDED']:
            return Response(
                {'error': 'QR code can only be generated for confirmed registrations'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        qr_data = registration.generate_qr_code()
        
        return Response({
            'qr_data': qr_data,
            'expires_at': registration.qr_code_expires_at
        })
        
    except EventRegistration.DoesNotExist:
        return Response(
            {'error': 'Registration not found'},
            status=status.HTTP_404_NOT_FOUND
        )


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def check_in_event(request):
    """Check in to an event"""
    serializer = CheckInSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    
    data = serializer.validated_data
    
    # Get registration
    if data.get('registration_id'):
        try:
            registration = EventRegistration.objects.get(
                id=data['registration_id'],
                user=request.user,
                is_deleted=False
            )
        except EventRegistration.DoesNotExist:
            return Response(
                {'error': 'Registration not found'},
                status=status.HTTP_404_NOT_FOUND
            )
    elif data.get('qr_code_data'):
        try:
            qr_data = json.loads(data['qr_code_data'])
            registration = EventRegistration.objects.get(
                id=qr_data['registration_id'],
                registration_code=qr_data['registration_code'],
                user=request.user,
                is_deleted=False
            )
            
            # Verify access token if provided
            if data.get('access_token') and qr_data.get('access_token') != data['access_token']:
                return Response(
                    {'error': 'Invalid access token'},
                    status=status.HTTP_400_BAD_REQUEST
                )
                
        except (json.JSONDecodeError, KeyError, EventRegistration.DoesNotExist):
            return Response(
                {'error': 'Invalid QR code'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    # Perform check-in
    success, message = registration.check_in(data.get('check_in_method', 'QR'))
    
    if success:
        return Response({
            'message': message,
            'registration': EventRegistrationSerializer(registration).data
        })
    else:
        return Response(
            {'error': message},
            status=status.HTTP_400_BAD_REQUEST
        )


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def check_out_event(request):
    """Check out from an event"""
    serializer = CheckOutSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    
    data = serializer.validated_data
    
    # Get registration
    if data.get('registration_id'):
        try:
            registration = EventRegistration.objects.get(
                id=data['registration_id'],
                user=request.user,
                is_deleted=False
            )
        except EventRegistration.DoesNotExist:
            return Response(
                {'error': 'Registration not found'},
                status=status.HTTP_404_NOT_FOUND
            )
    elif data.get('qr_code_data'):
        try:
            qr_data = json.loads(data['qr_code_data'])
            registration = EventRegistration.objects.get(
                id=qr_data['registration_id'],
                registration_code=qr_data['registration_code'],
                user=request.user,
                is_deleted=False
            )
        except (json.JSONDecodeError, KeyError, EventRegistration.DoesNotExist):
            return Response(
                {'error': 'Invalid QR code'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    # Perform check-out
    success, message = registration.check_out(data.get('check_out_method', 'QR'))
    
    if success:
        return Response({
            'message': message,
            'registration': EventRegistrationSerializer(registration).data
        })
    else:
        return Response(
            {'error': message},
            status=status.HTTP_400_BAD_REQUEST
        )


class EventFeedbackListCreateView(generics.ListCreateAPIView):
    """List and create event feedback"""
    serializer_class = EventFeedbackSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        event_id = self.kwargs.get('event_id')
        queryset = EventFeedback.objects.filter(is_deleted=False)
        
        if event_id:
            queryset = queryset.filter(event_id=event_id)
        
        # Users can only see their own feedback unless admin
        if not self.request.user.is_admin:
            queryset = queryset.filter(user=self.request.user)
        
        return queryset.select_related('user', 'event').order_by('-created_at')
    
    def perform_create(self, serializer):
        event_id = self.kwargs.get('event_id')
        if event_id:
            event = get_object_or_404(Event, id=event_id, is_deleted=False)
            
            # Check if user attended the event
            registration = EventRegistration.objects.filter(
                user=self.request.user,
                event=event,
                status='ATTENDED',
                is_deleted=False
            ).first()
            
            if not registration:
                from rest_framework.exceptions import ValidationError
                raise ValidationError("You can only provide feedback for events you attended")
            
            serializer.save(event=event, registration=registration, created_by=self.request.user)
        else:
            serializer.save(created_by=self.request.user)


class EventResourceListView(generics.ListAPIView):
    """List event resources"""
    serializer_class = EventResourceSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        event_id = self.kwargs['event_id']
        event = get_object_or_404(Event, id=event_id, is_deleted=False)
        
        # Check if user has access to the event
        user = self.request.user
        has_access = False
        
        if user.is_admin:
            has_access = True
        else:
            # Check if user is registered for the event
            registration = EventRegistration.objects.filter(
                user=user,
                event=event,
                status__in=['CONFIRMED', 'ATTENDED'],
                is_deleted=False
            ).exists()
            has_access = registration
        
        queryset = EventResource.objects.filter(
            event=event,
            is_deleted=False
        )
        
        # Filter based on access and timing
        if not has_access:
            queryset = queryset.filter(is_public=True)
        
        # Check timing restrictions
        now = timezone.now()
        event_start = timezone.datetime.combine(event.start_date, event.start_time)
        event_end = timezone.datetime.combine(event.end_date, event.end_time)
        
        if now < event_start:
            queryset = queryset.filter(available_before_event=True)
        elif now > event_end:
            queryset = queryset.filter(available_after_event=True)
        
        return queryset.order_by('resource_type', 'title')


class EventWaitlistListCreateView(generics.ListCreateAPIView):
    """List and create event waitlist entries"""
    serializer_class = EventWaitlistSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return EventWaitlist.objects.filter(
            user=self.request.user,
            is_deleted=False
        ).select_related('event').order_by('position')


class EventSeriesListView(generics.ListAPIView):
    """List event series"""
    serializer_class = EventSeriesSerializer
    permission_classes = [permissions.IsAuthenticated]
    search_fields = ['name', 'description']
    ordering = ['name']
    
    def get_queryset(self):
        return EventSeries.objects.filter(
            is_active=True,
            is_deleted=False
        ).prefetch_related('events')


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_user_event_summary(request):
    """Get user's event activity summary"""
    user = request.user
    
    # Upcoming registrations
    upcoming_registrations = EventRegistration.objects.filter(
        user=user,
        event__start_date__gte=timezone.now().date(),
        status__in=['CONFIRMED', 'ATTENDED'],
        is_deleted=False
    ).select_related('event').order_by('event__start_date', 'event__start_time')[:5]
    
    # Past events attended
    past_events = EventRegistration.objects.filter(
        user=user,
        status='ATTENDED',
        event__end_date__lt=timezone.now().date(),
        is_deleted=False
    ).select_related('event').order_by('-event__end_date')[:5]
    
    # Pending feedback
    pending_feedback = EventRegistration.objects.filter(
        user=user,
        status='ATTENDED',
        feedback_submitted=False,
        event__has_feedback_form=True,
        is_deleted=False
    ).select_related('event')
    
    # Statistics
    total_registrations = EventRegistration.objects.filter(
        user=user,
        is_deleted=False
    ).count()
    
    total_attended = EventRegistration.objects.filter(
        user=user,
        status='ATTENDED',
        is_deleted=False
    ).count()
    
    certificates_earned = EventRegistration.objects.filter(
        user=user,
        certificate_issued=True,
        is_deleted=False
    ).count()
    
    return Response({
        'upcoming_registrations': EventRegistrationSerializer(upcoming_registrations, many=True).data,
        'past_events': EventRegistrationSerializer(past_events, many=True).data,
        'pending_feedback': EventRegistrationSerializer(pending_feedback, many=True).data,
        'statistics': {
            'total_registrations': total_registrations,
            'total_attended': total_attended,
            'certificates_earned': certificates_earned,
            'attendance_rate': (total_attended / total_registrations * 100) if total_registrations > 0 else 0
        }
    })


# Admin Views
class EventManagementView(generics.ListCreateAPIView):
    """Admin view for managing events"""
    serializer_class = EventDetailSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def get_queryset(self):
        if self.request.user.is_super_admin:
            return Event.objects.filter(is_deleted=False)
        elif self.request.user.role == 'ADMIN':
            admin_profile = getattr(self.request.user, 'admin_profile', None)
            if admin_profile and admin_profile.managed_library:
                return Event.objects.filter(
                    library=admin_profile.managed_library,
                    is_deleted=False
                )
        return Event.objects.none()
    
    def perform_create(self, serializer):
        serializer.save(
            organizer=self.request.user,
            created_by=self.request.user
        )


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated, IsAdminUser])
def bulk_check_in(request, event_id):
    """Bulk check-in for event (Admin only)"""
    try:
        event = Event.objects.get(id=event_id, is_deleted=False)
        
        # Check admin permissions
        if not request.user.is_super_admin:
            admin_profile = getattr(request.user, 'admin_profile', None)
            if not (admin_profile and admin_profile.managed_library == event.library):
                return Response(
                    {'error': 'Permission denied'},
                    status=status.HTTP_403_FORBIDDEN
                )
        
        registration_ids = request.data.get('registration_ids', [])
        
        if not registration_ids:
            return Response(
                {'error': 'No registration IDs provided'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        registrations = EventRegistration.objects.filter(
            id__in=registration_ids,
            event=event,
            status='CONFIRMED',
            is_deleted=False
        )
        
        checked_in_count = 0
        for registration in registrations:
            success, _ = registration.check_in('MANUAL')
            if success:
                checked_in_count += 1
        
        return Response({
            'message': f'{checked_in_count} registrations checked in successfully',
            'checked_in_count': checked_in_count
        })
        
    except Event.DoesNotExist:
        return Response(
            {'error': 'Event not found'},
            status=status.HTTP_404_NOT_FOUND
        )


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated, IsAdminUser])
def event_analytics(request, event_id):
    """Get event analytics (Admin only)"""
    try:
        event = Event.objects.get(id=event_id, is_deleted=False)
        
        # Check admin permissions
        if not request.user.is_super_admin:
            admin_profile = getattr(request.user, 'admin_profile', None)
            if not (admin_profile and admin_profile.managed_library == event.library):
                return Response(
                    {'error': 'Permission denied'},
                    status=status.HTTP_403_FORBIDDEN
                )
        
        # Registration statistics
        total_registrations = event.registrations.filter(is_deleted=False).count()
        confirmed_registrations = event.registrations.filter(
            status__in=['CONFIRMED', 'ATTENDED'],
            is_deleted=False
        ).count()
        attended = event.registrations.filter(status='ATTENDED', is_deleted=False).count()
        no_shows = event.registrations.filter(status='NO_SHOW', is_deleted=False).count()
        cancelled = event.registrations.filter(status='CANCELLED', is_deleted=False).count()
        
        # Feedback statistics
        feedback_count = event.feedback.filter(is_deleted=False).count()
        avg_rating = event.feedback.filter(is_deleted=False).aggregate(
            avg=Avg('overall_rating')
        )['avg'] or 0
        
        # Registration timeline
        registration_timeline = event.registrations.filter(
            is_deleted=False
        ).extra(
            select={'date': 'DATE(registration_date)'}
        ).values('date').annotate(
            count=Count('id')
        ).order_by('date')
        
        return Response({
            'event': EventDetailSerializer(event).data,
            'statistics': {
                'total_registrations': total_registrations,
                'confirmed_registrations': confirmed_registrations,
                'attended': attended,
                'no_shows': no_shows,
                'cancelled': cancelled,
                'attendance_rate': (attended / confirmed_registrations * 100) if confirmed_registrations > 0 else 0,
                'feedback_count': feedback_count,
                'average_rating': round(avg_rating, 2),
                'capacity_utilization': (confirmed_registrations / event.max_participants * 100) if event.max_participants > 0 else 0
            },
            'registration_timeline': list(registration_timeline)
        })
        
    except Event.DoesNotExist:
        return Response(
            {'error': 'Event not found'},
            status=status.HTTP_404_NOT_FOUND
        )