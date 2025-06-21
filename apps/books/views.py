"""
Views for books app
"""
from rest_framework import generics, status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from django.db.models import Q, Count, Avg, F
from django.utils import timezone
from django.shortcuts import get_object_or_404
from django.http import HttpResponse, Http404
from apps.core.permissions import IsAdminUser
from .models import (
    BookCategory, Author, Publisher, Book, BookReservation,
    BookDigitalAccess, BookReview, BookWishlist, BookReadingList,
    BookReadingListItem, BookStatistics, BookRecommendation
)
from .serializers import (
    BookCategorySerializer, AuthorSerializer, PublisherSerializer,
    BookListSerializer, BookDetailSerializer, BookReservationSerializer,
    BookReservationCreateSerializer, BookDigitalAccessSerializer,
    BookReviewSerializer, BookWishlistSerializer, BookReadingListSerializer,
    BookStatisticsSerializer, BookRecommendationSerializer,
    BookSearchSerializer, DigitalBookAccessSerializer
)
import mimetypes
import os


class BookCategoryListView(generics.ListAPIView):
    """List book categories"""
    serializer_class = BookCategorySerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return BookCategory.objects.filter(
            is_active=True,
            is_deleted=False
        ).order_by('sort_order', 'name')


class AuthorListView(generics.ListAPIView):
    """List authors"""
    serializer_class = AuthorSerializer
    permission_classes = [permissions.IsAuthenticated]
    search_fields = ['first_name', 'last_name', 'middle_name']
    ordering_fields = ['last_name', 'first_name', 'books_count']
    ordering = ['last_name', 'first_name']
    
    def get_queryset(self):
        return Author.objects.filter(is_deleted=False)


class PublisherListView(generics.ListAPIView):
    """List publishers"""
    serializer_class = PublisherSerializer
    permission_classes = [permissions.IsAuthenticated]
    search_fields = ['name', 'description']
    ordering_fields = ['name', 'books_count']
    ordering = ['name']
    
    def get_queryset(self):
        return Publisher.objects.filter(is_deleted=False)


class BookListView(generics.ListAPIView):
    """List books with filtering and search"""
    serializer_class = BookListSerializer
    permission_classes = [permissions.IsAuthenticated]
    filterset_fields = [
        'category', 'book_type', 'status', 'library', 'language',
        'is_featured', 'is_new_arrival', 'is_popular', 'is_premium'
    ]
    search_fields = ['title', 'subtitle', 'isbn', 'isbn13', 'description']
    ordering_fields = [
        'title', 'publication_date', 'average_rating', 'total_reviews',
        'view_count', 'created_at'
    ]
    ordering = ['title']
    
    def get_queryset(self):
        queryset = Book.objects.filter(is_deleted=False)
        
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
                # Students can see books in libraries they have access to
                accessible_libraries = user.library_access.filter(
                    is_active=True
                ).values_list('library_id', flat=True)
                queryset = queryset.filter(library_id__in=accessible_libraries)
        
        return queryset.select_related('category', 'publisher', 'library').prefetch_related('authors')


class BookDetailView(generics.RetrieveAPIView):
    """Get book details"""
    serializer_class = BookDetailSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'id'
    
    def get_queryset(self):
        return Book.objects.filter(is_deleted=False).select_related(
            'category', 'publisher', 'library'
        ).prefetch_related('authors', 'reviews__user')
    
    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        
        # Increment view count
        Book.objects.filter(id=instance.id).update(view_count=F('view_count') + 1)
        
        serializer = self.get_serializer(instance)
        return Response(serializer.data)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def search_books(request):
    """Advanced book search"""
    serializer = BookSearchSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    
    data = serializer.validated_data
    queryset = Book.objects.filter(is_deleted=False)
    
    # Apply filters
    if data.get('query'):
        queryset = queryset.filter(
            Q(title__icontains=data['query']) |
            Q(subtitle__icontains=data['query']) |
            Q(description__icontains=data['query']) |
            Q(authors__first_name__icontains=data['query']) |
            Q(authors__last_name__icontains=data['query']) |
            Q(publisher__name__icontains=data['query']) |
            Q(keywords__icontains=data['query'])
        ).distinct()
    
    if data.get('category_id'):
        # Include subcategories
        category = get_object_or_404(BookCategory, id=data['category_id'])
        category_ids = [category.id] + category.get_all_subcategories()
        queryset = queryset.filter(category_id__in=category_ids)
    
    if data.get('author_id'):
        queryset = queryset.filter(authors=data['author_id'])
    
    if data.get('publisher_id'):
        queryset = queryset.filter(publisher_id=data['publisher_id'])
    
    if data.get('library_id'):
        queryset = queryset.filter(library_id=data['library_id'])
    
    if data.get('book_type'):
        queryset = queryset.filter(book_type=data['book_type'])
    
    if data.get('language'):
        queryset = queryset.filter(language=data['language'])
    
    if data.get('is_available') is not None:
        if data['is_available']:
            queryset = queryset.filter(
                Q(book_type='PHYSICAL', available_copies__gt=0) |
                Q(book_type='DIGITAL') |
                Q(book_type='BOTH')
            )
    
    if data.get('is_featured') is not None:
        queryset = queryset.filter(is_featured=data['is_featured'])
    
    if data.get('is_new_arrival') is not None:
        queryset = queryset.filter(is_new_arrival=data['is_new_arrival'])
    
    if data.get('is_popular') is not None:
        queryset = queryset.filter(is_popular=data['is_popular'])
    
    if data.get('is_premium') is not None:
        queryset = queryset.filter(is_premium=data['is_premium'])
    
    if data.get('min_rating'):
        queryset = queryset.filter(average_rating__gte=data['min_rating'])
    
    if data.get('publication_year_from'):
        queryset = queryset.filter(publication_date__year__gte=data['publication_year_from'])
    
    if data.get('publication_year_to'):
        queryset = queryset.filter(publication_date__year__lte=data['publication_year_to'])
    
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
    sort_by = data.get('sort_by', 'title')
    if sort_by == 'author':
        queryset = queryset.order_by('authors__last_name', 'authors__first_name')
    elif sort_by == 'publication_date':
        queryset = queryset.order_by('-publication_date')
    elif sort_by == 'rating':
        queryset = queryset.order_by('-average_rating')
    elif sort_by == 'popularity':
        queryset = queryset.order_by('-total_reservations', '-view_count')
    elif sort_by == 'newest':
        queryset = queryset.order_by('-created_at')
    else:
        queryset = queryset.order_by('title')
    
    # Serialize results
    serializer = BookListSerializer(
        queryset.distinct(), many=True, context={'request': request}
    )
    
    return Response({
        'count': queryset.distinct().count(),
        'results': serializer.data
    })


class BookReservationListCreateView(generics.ListCreateAPIView):
    """List and create book reservations"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get_serializer_class(self):
        if self.request.method == 'POST':
            return BookReservationCreateSerializer
        return BookReservationSerializer
    
    def get_queryset(self):
        user = self.request.user
        queryset = BookReservation.objects.filter(is_deleted=False)
        
        # Filter by user unless admin
        if not user.is_admin:
            queryset = queryset.filter(user=user)
        
        return queryset.select_related(
            'user', 'book', 'pickup_library', 'return_library'
        ).order_by('-reservation_date')


class BookReservationDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Book reservation detail view"""
    serializer_class = BookReservationSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'id'
    
    def get_queryset(self):
        user = self.request.user
        queryset = BookReservation.objects.filter(is_deleted=False)
        
        # Users can only access their own reservations unless admin
        if not user.is_admin:
            queryset = queryset.filter(user=user)
        
        return queryset.select_related('user', 'book', 'pickup_library')
    
    def destroy(self, request, *args, **kwargs):
        """Cancel reservation instead of deleting"""
        reservation = self.get_object()
        
        if reservation.status not in ['PENDING', 'CONFIRMED']:
            return Response(
                {'error': 'Cannot cancel reservation in current status'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        reservation.status = 'CANCELLED'
        reservation.save()
        
        # Update book availability if physical
        if reservation.reservation_type == 'PHYSICAL':
            reservation.book.available_copies += 1
            reservation.book.save()
        
        return Response({'message': 'Reservation cancelled successfully'})


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def renew_reservation(request, reservation_id):
    """Renew a book reservation"""
    try:
        reservation = BookReservation.objects.get(
            id=reservation_id,
            user=request.user,
            is_deleted=False
        )
        
        success, message = reservation.renew_reservation()
        
        if success:
            return Response({
                'message': message,
                'reservation': BookReservationSerializer(reservation).data
            })
        else:
            return Response(
                {'error': message},
                status=status.HTTP_400_BAD_REQUEST
            )
            
    except BookReservation.DoesNotExist:
        return Response(
            {'error': 'Reservation not found'},
            status=status.HTTP_404_NOT_FOUND
        )


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def grant_digital_access(request, reservation_id):
    """Grant digital access to a book"""
    try:
        reservation = BookReservation.objects.get(
            id=reservation_id,
            user=request.user,
            reservation_type='DIGITAL',
            is_deleted=False
        )
        
        success, message = reservation.grant_digital_access()
        
        if success:
            return Response({
                'message': message,
                'access_password': reservation.digital_access_password,
                'expires_at': reservation.digital_access_expires_at,
                'reservation': BookReservationSerializer(reservation).data
            })
        else:
            return Response(
                {'error': message},
                status=status.HTTP_400_BAD_REQUEST
            )
            
    except BookReservation.DoesNotExist:
        return Response(
            {'error': 'Reservation not found'},
            status=status.HTTP_404_NOT_FOUND
        )


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def access_digital_book(request):
    """Access digital book content"""
    serializer = DigitalBookAccessSerializer(data=request.data, context={'request': request})
    serializer.is_valid(raise_exception=True)
    
    reservation = serializer.validated_data['reservation']
    
    # Check access count limit
    if reservation.access_count >= reservation.max_access_count:
        return Response(
            {'error': 'Maximum access count exceeded'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Create access session
    from apps.core.utils import generate_secure_token, get_user_ip
    
    access_session = BookDigitalAccess.objects.create(
        user=request.user,
        book=reservation.book,
        reservation=reservation,
        access_token=generate_secure_token(),
        ip_address=get_user_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', ''),
        expires_at=reservation.digital_access_expires_at,
        created_by=request.user
    )
    
    # Increment access count
    reservation.access_count += 1
    reservation.save()
    
    return Response({
        'session': BookDigitalAccessSerializer(access_session).data,
        'book_url': f'/api/v1/books/digital/{access_session.session_id}/content/',
        'access_token': access_session.access_token
    })


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def serve_digital_book(request, session_id):
    """Serve digital book content"""
    try:
        access_session = BookDigitalAccess.objects.get(
            session_id=session_id,
            user=request.user,
            is_active=True
        )
        
        if access_session.is_expired:
            return Response(
                {'error': 'Access session has expired'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Verify access token
        provided_token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if provided_token != access_session.access_token:
            return Response(
                {'error': 'Invalid access token'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        book = access_session.book
        
        if not book.digital_file:
            return Response(
                {'error': 'Digital file not available'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Update last activity
        access_session.last_activity = timezone.now()
        access_session.save()
        
        # Serve the file
        file_path = book.digital_file.path
        if not os.path.exists(file_path):
            raise Http404("File not found")
        
        with open(file_path, 'rb') as f:
            response = HttpResponse(f.read(), content_type='application/pdf')
            response['Content-Disposition'] = f'inline; filename="{book.title}.pdf"'
            response['X-Accel-Redirect'] = f'/protected/books/{book.digital_file.name}'
            return response
            
    except BookDigitalAccess.DoesNotExist:
        return Response(
            {'error': 'Access session not found'},
            status=status.HTTP_404_NOT_FOUND
        )


class BookReviewListCreateView(generics.ListCreateAPIView):
    """List and create book reviews"""
    serializer_class = BookReviewSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        book_id = self.kwargs.get('book_id')
        queryset = BookReview.objects.filter(
            is_approved=True,
            is_deleted=False
        ).select_related('user', 'book')
        
        if book_id:
            queryset = queryset.filter(book_id=book_id)
        
        return queryset.order_by('-created_at')
    
    def perform_create(self, serializer):
        book_id = self.kwargs.get('book_id')
        if book_id:
            book = get_object_or_404(Book, id=book_id, is_deleted=False)
            serializer.save(book=book, created_by=self.request.user)
        else:
            serializer.save(created_by=self.request.user)


class BookWishlistListCreateView(generics.ListCreateAPIView):
    """List and create wishlist items"""
    serializer_class = BookWishlistSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return BookWishlist.objects.filter(
            user=self.request.user,
            is_deleted=False
        ).select_related('book').order_by('priority', '-created_at')


class BookWishlistDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Wishlist item detail view"""
    serializer_class = BookWishlistSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'id'
    
    def get_queryset(self):
        return BookWishlist.objects.filter(
            user=self.request.user,
            is_deleted=False
        )


class BookReadingListListCreateView(generics.ListCreateAPIView):
    """List and create reading lists"""
    serializer_class = BookReadingListSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return BookReadingList.objects.filter(
            user=self.request.user,
            is_deleted=False
        ).prefetch_related('books')


class BookReadingListDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Reading list detail view"""
    serializer_class = BookReadingListSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'id'
    
    def get_queryset(self):
        return BookReadingList.objects.filter(
            user=self.request.user,
            is_deleted=False
        )


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def add_book_to_reading_list(request, list_id):
    """Add book to reading list"""
    try:
        reading_list = BookReadingList.objects.get(
            id=list_id,
            user=request.user,
            is_deleted=False
        )
        
        book_id = request.data.get('book_id')
        if not book_id:
            return Response(
                {'error': 'book_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        book = get_object_or_404(Book, id=book_id, is_deleted=False)
        
        # Check if book is already in the list
        if BookReadingListItem.objects.filter(
            reading_list=reading_list,
            book=book,
            is_deleted=False
        ).exists():
            return Response(
                {'error': 'Book is already in the reading list'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Add book to list
        item = BookReadingListItem.objects.create(
            reading_list=reading_list,
            book=book,
            order=reading_list.books.count() + 1,
            notes=request.data.get('notes', ''),
            created_by=request.user
        )
        
        return Response({
            'message': 'Book added to reading list',
            'item': BookReadingListItemSerializer(item).data
        })
        
    except BookReadingList.DoesNotExist:
        return Response(
            {'error': 'Reading list not found'},
            status=status.HTTP_404_NOT_FOUND
        )


class BookRecommendationListView(generics.ListAPIView):
    """List book recommendations for user"""
    serializer_class = BookRecommendationSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return BookRecommendation.objects.filter(
            user=self.request.user,
            expires_at__gt=timezone.now(),
            dismissed=False,
            is_deleted=False
        ).select_related('book').order_by('-confidence_score')


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_user_book_summary(request):
    """Get user's book activity summary"""
    user = request.user
    
    # Current reservations
    current_reservations = BookReservation.objects.filter(
        user=user,
        status__in=['CONFIRMED', 'READY_FOR_PICKUP', 'CHECKED_OUT'],
        is_deleted=False
    ).select_related('book')
    
    # Overdue books
    overdue_reservations = BookReservation.objects.filter(
        user=user,
        status='CHECKED_OUT',
        due_date__lt=timezone.now(),
        is_deleted=False
    ).select_related('book')
    
    # Recent reviews
    recent_reviews = BookReview.objects.filter(
        user=user,
        is_deleted=False
    ).select_related('book')[:5]
    
    # Wishlist count
    wishlist_count = BookWishlist.objects.filter(
        user=user,
        is_deleted=False
    ).count()
    
    # Reading lists count
    reading_lists_count = BookReadingList.objects.filter(
        user=user,
        is_deleted=False
    ).count()
    
    # Statistics
    total_reservations = BookReservation.objects.filter(
        user=user,
        is_deleted=False
    ).count()
    
    completed_reservations = BookReservation.objects.filter(
        user=user,
        status='RETURNED',
        is_deleted=False
    ).count()
    
    return Response({
        'current_reservations': BookReservationSerializer(current_reservations, many=True).data,
        'overdue_reservations': BookReservationSerializer(overdue_reservations, many=True).data,
        'recent_reviews': BookReviewSerializer(recent_reviews, many=True).data,
        'wishlist_count': wishlist_count,
        'reading_lists_count': reading_lists_count,
        'statistics': {
            'total_reservations': total_reservations,
            'completed_reservations': completed_reservations,
            'books_read': completed_reservations,  # Assuming completed = read
            'completion_rate': (completed_reservations / total_reservations * 100) if total_reservations > 0 else 0
        }
    })


# Admin Views
class BookManagementView(generics.ListCreateAPIView):
    """Admin view for managing books"""
    serializer_class = BookDetailSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def get_queryset(self):
        if self.request.user.is_super_admin:
            return Book.objects.filter(is_deleted=False)
        elif self.request.user.role == 'ADMIN':
            admin_profile = getattr(self.request.user, 'admin_profile', None)
            if admin_profile and admin_profile.managed_library:
                return Book.objects.filter(
                    library=admin_profile.managed_library,
                    is_deleted=False
                )
        return Book.objects.none()
    
    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)


class BookStatisticsView(generics.ListAPIView):
    """View book statistics"""
    serializer_class = BookStatisticsSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def get_queryset(self):
        book_id = self.kwargs.get('book_id')
        queryset = BookStatistics.objects.all()
        
        if book_id:
            queryset = queryset.filter(book_id=book_id)
        
        # Filter based on user permissions
        if not self.request.user.is_super_admin:
            admin_profile = getattr(self.request.user, 'admin_profile', None)
            if admin_profile and admin_profile.managed_library:
                queryset = queryset.filter(book__library=admin_profile.managed_library)
            else:
                queryset = queryset.none()
        
        return queryset.select_related('book').order_by('-date')