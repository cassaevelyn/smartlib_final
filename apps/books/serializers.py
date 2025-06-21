"""
Serializers for books app
"""
from rest_framework import serializers
from django.utils import timezone
from apps.core.serializers import BaseModelSerializer
from .models import (
    BookCategory, Author, Publisher, Book, BookReservation,
    BookDigitalAccess, BookReview, BookWishlist, BookReadingList,
    BookReadingListItem, BookStatistics, BookRecommendation
)


class BookCategorySerializer(BaseModelSerializer):
    """Serializer for book categories"""
    parent_category_name = serializers.CharField(
        source='parent_category.name', read_only=True
    )
    subcategories_count = serializers.SerializerMethodField()
    books_count = serializers.SerializerMethodField()
    full_path = serializers.ReadOnlyField()
    
    class Meta:
        model = BookCategory
        fields = [
            'id', 'name', 'code', 'description', 'parent_category',
            'parent_category_name', 'icon', 'color', 'is_active',
            'sort_order', 'subcategories_count', 'books_count',
            'full_path', 'created_at'
        ]
        read_only_fields = ['id', 'code', 'created_at']
    
    def get_subcategories_count(self, obj):
        return obj.subcategories.filter(is_deleted=False).count()
    
    def get_books_count(self, obj):
        return obj.get_all_books_count()


class AuthorSerializer(BaseModelSerializer):
    """Serializer for authors"""
    full_name = serializers.ReadOnlyField()
    books_count = serializers.ReadOnlyField()
    age = serializers.SerializerMethodField()
    
    class Meta:
        model = Author
        fields = [
            'id', 'first_name', 'middle_name', 'last_name', 'full_name',
            'biography', 'birth_date', 'death_date', 'age', 'nationality',
            'website', 'photo', 'books_count', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']
    
    def get_age(self, obj):
        if obj.birth_date:
            end_date = obj.death_date or timezone.now().date()
            return (end_date - obj.birth_date).days // 365
        return None


class PublisherSerializer(BaseModelSerializer):
    """Serializer for publishers"""
    books_count = serializers.ReadOnlyField()
    
    class Meta:
        model = Publisher
        fields = [
            'id', 'name', 'description', 'website', 'email', 'phone',
            'address', 'city', 'country', 'logo', 'books_count', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']


class BookListSerializer(serializers.ModelSerializer):
    """Simplified serializer for book list view"""
    category_name = serializers.CharField(source='category.name', read_only=True)
    authors_list = serializers.ReadOnlyField()
    publisher_name = serializers.CharField(source='publisher.name', read_only=True)
    library_name = serializers.CharField(source='library.name', read_only=True)
    book_type_display = serializers.CharField(source='get_book_type_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    is_available = serializers.ReadOnlyField()
    estimated_availability = serializers.SerializerMethodField()
    
    class Meta:
        model = Book
        fields = [
            'id', 'title', 'subtitle', 'book_code', 'isbn', 'category_name',
            'authors_list', 'publisher_name', 'library_name', 'book_type',
            'book_type_display', 'status', 'status_display', 'is_available',
            'physical_copies', 'available_copies', 'cover_image', 'thumbnail',
            'average_rating', 'total_reviews', 'is_featured', 'is_new_arrival',
            'is_popular', 'is_premium', 'estimated_availability'
        ]
    
    def get_estimated_availability(self, obj):
        if obj.is_available:
            return None
        return obj.get_estimated_availability_date()


class BookDetailSerializer(BaseModelSerializer):
    """Detailed serializer for book detail view"""
    category = BookCategorySerializer(read_only=True)
    authors = AuthorSerializer(many=True, read_only=True)
    publisher = PublisherSerializer(read_only=True)
    library_name = serializers.CharField(source='library.name', read_only=True)
    book_type_display = serializers.CharField(source='get_book_type_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    language_display = serializers.CharField(source='get_language_display', read_only=True)
    is_available = serializers.ReadOnlyField()
    current_reservations = serializers.ReadOnlyField()
    estimated_availability = serializers.SerializerMethodField()
    user_can_reserve = serializers.SerializerMethodField()
    user_has_reserved = serializers.SerializerMethodField()
    user_has_reviewed = serializers.SerializerMethodField()
    similar_books = serializers.SerializerMethodField()
    recent_reviews = serializers.SerializerMethodField()
    
    class Meta:
        model = Book
        fields = [
            'id', 'title', 'subtitle', 'book_code', 'isbn', 'isbn13',
            'category', 'authors', 'publisher', 'library_name',
            'publication_date', 'edition', 'pages', 'language',
            'language_display', 'description', 'table_of_contents',
            'summary', 'keywords', 'tags', 'book_type', 'book_type_display',
            'status', 'status_display', 'is_available', 'physical_copies',
            'available_copies', 'current_reservations', 'max_concurrent_digital_access',
            'digital_access_duration_hours', 'shelf_location', 'call_number',
            'is_featured', 'is_new_arrival', 'is_popular', 'requires_approval',
            'is_premium', 'rental_price_per_day', 'cover_image', 'thumbnail',
            'total_reservations', 'total_checkouts', 'average_rating',
            'total_reviews', 'view_count', 'estimated_availability',
            'user_can_reserve', 'user_has_reserved', 'user_has_reviewed',
            'similar_books', 'recent_reviews', 'created_at'
        ]
        read_only_fields = [
            'id', 'book_code', 'total_reservations', 'total_checkouts',
            'average_rating', 'total_reviews', 'view_count', 'created_at'
        ]
    
    def get_estimated_availability(self, obj):
        if obj.is_available:
            return None
        return obj.get_estimated_availability_date()
    
    def get_user_can_reserve(self, obj):
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            can_reserve, _ = obj.can_user_reserve(request.user)
            return can_reserve
        return False
    
    def get_user_has_reserved(self, obj):
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            return obj.reservations.filter(
                user=request.user,
                status__in=['PENDING', 'CONFIRMED', 'READY_FOR_PICKUP', 'CHECKED_OUT'],
                is_deleted=False
            ).exists()
        return False
    
    def get_user_has_reviewed(self, obj):
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            return obj.reviews.filter(
                user=request.user,
                is_deleted=False
            ).exists()
        return False
    
    def get_similar_books(self, obj):
        similar_books = Book.objects.filter(
            category=obj.category,
            is_deleted=False
        ).exclude(id=obj.id)[:5]
        return BookListSerializer(similar_books, many=True).data
    
    def get_recent_reviews(self, obj):
        reviews = obj.reviews.filter(
            is_approved=True,
            is_deleted=False
        ).select_related('user')[:5]
        return BookReviewSerializer(reviews, many=True).data


class BookReservationSerializer(BaseModelSerializer):
    """Serializer for book reservations"""
    user_display = serializers.CharField(source='user.get_full_name', read_only=True)
    book_title = serializers.CharField(source='book.title', read_only=True)
    book_cover = serializers.ImageField(source='book.cover_image', read_only=True)
    library_name = serializers.CharField(source='pickup_library.name', read_only=True)
    reservation_type_display = serializers.CharField(
        source='get_reservation_type_display', read_only=True
    )
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    is_overdue = serializers.ReadOnlyField()
    days_until_due = serializers.ReadOnlyField()
    can_renew = serializers.ReadOnlyField()
    
    class Meta:
        model = BookReservation
        fields = [
            'id', 'user', 'user_display', 'book', 'book_title', 'book_cover',
            'reservation_code', 'reservation_type', 'reservation_type_display',
            'status', 'status_display', 'reservation_date', 'pickup_deadline',
            'pickup_date', 'due_date', 'return_date', 'is_overdue',
            'days_until_due', 'can_renew', 'digital_access_granted_at',
            'digital_access_expires_at', 'access_count', 'max_access_count',
            'pickup_library', 'library_name', 'return_library', 'issued_by',
            'returned_to', 'reminder_sent', 'overdue_notices_sent',
            'late_fee', 'damage_fee', 'penalty_points', 'purpose', 'notes',
            'renewal_count', 'max_renewals', 'created_at'
        ]
        read_only_fields = [
            'id', 'reservation_code', 'reservation_date', 'pickup_date',
            'return_date', 'digital_access_granted_at', 'digital_access_expires_at',
            'access_count', 'issued_by', 'returned_to', 'reminder_sent',
            'overdue_notices_sent', 'late_fee', 'damage_fee', 'penalty_points',
            'renewal_count', 'created_at'
        ]
    
    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


class BookReservationCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating book reservations"""
    
    class Meta:
        model = BookReservation
        fields = [
            'book', 'reservation_type', 'pickup_library', 'purpose', 'notes'
        ]
    
    def validate(self, attrs):
        book = attrs['book']
        reservation_type = attrs['reservation_type']
        user = self.context['request'].user
        
        # Check if book can be reserved
        can_reserve, message = book.can_user_reserve(user, reservation_type)
        if not can_reserve:
            raise serializers.ValidationError(message)
        
        return attrs
    
    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        validated_data['created_by'] = self.context['request'].user
        return super().create(validated_data)


class BookDigitalAccessSerializer(serializers.ModelSerializer):
    """Serializer for digital book access sessions"""
    user_display = serializers.CharField(source='user.get_full_name', read_only=True)
    book_title = serializers.CharField(source='book.title', read_only=True)
    is_expired = serializers.ReadOnlyField()
    
    class Meta:
        model = BookDigitalAccess
        fields = [
            'id', 'user', 'user_display', 'book', 'book_title',
            'reservation', 'session_id', 'started_at', 'last_activity',
            'expires_at', 'ended_at', 'is_expired', 'pages_viewed',
            'total_time_spent', 'is_active'
        ]
        read_only_fields = [
            'id', 'session_id', 'started_at', 'last_activity',
            'ended_at', 'total_time_spent'
        ]


class BookReviewSerializer(BaseModelSerializer):
    """Serializer for book reviews"""
    user_display = serializers.CharField(source='user.get_full_name', read_only=True)
    user_avatar = serializers.ImageField(source='user.avatar', read_only=True)
    book_title = serializers.CharField(source='book.title', read_only=True)
    helpfulness_ratio = serializers.ReadOnlyField()
    
    class Meta:
        model = BookReview
        fields = [
            'id', 'user', 'user_display', 'user_avatar', 'book',
            'book_title', 'reservation', 'overall_rating', 'content_rating',
            'readability_rating', 'usefulness_rating', 'title', 'review_text',
            'pros', 'cons', 'would_recommend', 'target_audience',
            'is_approved', 'helpful_count', 'not_helpful_count',
            'helpfulness_ratio', 'created_at'
        ]
        read_only_fields = [
            'id', 'is_approved', 'helpful_count', 'not_helpful_count',
            'created_at'
        ]
    
    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


class BookWishlistSerializer(BaseModelSerializer):
    """Serializer for book wishlist"""
    book = BookListSerializer(read_only=True)
    book_id = serializers.UUIDField(write_only=True)
    priority_display = serializers.SerializerMethodField()
    
    class Meta:
        model = BookWishlist
        fields = [
            'id', 'book', 'book_id', 'priority', 'priority_display',
            'notes', 'notify_when_available', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']
    
    def get_priority_display(self, obj):
        priorities = {1: 'High', 2: 'Medium', 3: 'Low'}
        return priorities.get(obj.priority, 'Unknown')
    
    def create(self, validated_data):
        book_id = validated_data.pop('book_id')
        validated_data['book_id'] = book_id
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


class BookReadingListItemSerializer(serializers.ModelSerializer):
    """Serializer for reading list items"""
    book = BookListSerializer(read_only=True)
    
    class Meta:
        model = BookReadingListItem
        fields = [
            'id', 'book', 'order', 'notes', 'is_read', 'read_date', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']


class BookReadingListSerializer(BaseModelSerializer):
    """Serializer for reading lists"""
    books_count = serializers.ReadOnlyField()
    items = BookReadingListItemSerializer(
        source='bookreadinglistitem_set', many=True, read_only=True
    )
    
    class Meta:
        model = BookReadingList
        fields = [
            'id', 'name', 'description', 'is_public', 'books_count',
            'items', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']
    
    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


class BookStatisticsSerializer(serializers.ModelSerializer):
    """Serializer for book statistics"""
    book_title = serializers.CharField(source='book.title', read_only=True)
    
    class Meta:
        model = BookStatistics
        fields = [
            'id', 'book', 'book_title', 'date', 'views', 'reservations',
            'checkouts', 'returns', 'digital_access_sessions', 'unique_users',
            'average_session_duration', 'pages_per_session', 'new_reviews',
            'average_daily_rating'
        ]
        read_only_fields = ['id']


class BookRecommendationSerializer(serializers.ModelSerializer):
    """Serializer for book recommendations"""
    book = BookListSerializer(read_only=True)
    recommendation_type_display = serializers.CharField(
        source='get_recommendation_type_display', read_only=True
    )
    is_expired = serializers.ReadOnlyField()
    
    class Meta:
        model = BookRecommendation
        fields = [
            'id', 'book', 'recommendation_type', 'recommendation_type_display',
            'confidence_score', 'reason', 'viewed', 'clicked', 'reserved',
            'dismissed', 'is_expired', 'generated_at', 'expires_at'
        ]
        read_only_fields = [
            'id', 'confidence_score', 'reason', 'algorithm_version',
            'generated_at', 'expires_at'
        ]


class BookSearchSerializer(serializers.Serializer):
    """Serializer for book search parameters"""
    query = serializers.CharField(required=False, allow_blank=True)
    category_id = serializers.UUIDField(required=False)
    author_id = serializers.UUIDField(required=False)
    publisher_id = serializers.UUIDField(required=False)
    library_id = serializers.UUIDField(required=False)
    book_type = serializers.ChoiceField(choices=Book.BOOK_TYPES, required=False)
    language = serializers.ChoiceField(choices=Book.LANGUAGES, required=False)
    is_available = serializers.BooleanField(required=False)
    is_featured = serializers.BooleanField(required=False)
    is_new_arrival = serializers.BooleanField(required=False)
    is_popular = serializers.BooleanField(required=False)
    is_premium = serializers.BooleanField(required=False)
    min_rating = serializers.DecimalField(
        max_digits=3, decimal_places=2, required=False, min_value=0, max_value=5
    )
    publication_year_from = serializers.IntegerField(required=False, min_value=1000)
    publication_year_to = serializers.IntegerField(required=False, max_value=2030)
    sort_by = serializers.ChoiceField(
        choices=[
            ('title', 'Title'),
            ('author', 'Author'),
            ('publication_date', 'Publication Date'),
            ('rating', 'Rating'),
            ('popularity', 'Popularity'),
            ('newest', 'Newest'),
        ],
        required=False,
        default='title'
    )
    
    def validate(self, attrs):
        if attrs.get('publication_year_from') and attrs.get('publication_year_to'):
            if attrs['publication_year_from'] > attrs['publication_year_to']:
                raise serializers.ValidationError(
                    "Publication year 'from' must be less than or equal to 'to'"
                )
        return attrs


class DigitalBookAccessSerializer(serializers.Serializer):
    """Serializer for digital book access request"""
    reservation_id = serializers.UUIDField()
    access_password = serializers.CharField()
    
    def validate(self, attrs):
        try:
            reservation = BookReservation.objects.get(
                id=attrs['reservation_id'],
                user=self.context['request'].user,
                reservation_type='DIGITAL',
                status='CHECKED_OUT',
                is_deleted=False
            )
            
            # Verify access password
            if reservation.digital_access_password != attrs['access_password']:
                raise serializers.ValidationError("Invalid access password")
            
            # Check if access is still valid
            if reservation.digital_access_expires_at and timezone.now() > reservation.digital_access_expires_at:
                raise serializers.ValidationError("Digital access has expired")
            
            attrs['reservation'] = reservation
            return attrs
            
        except BookReservation.DoesNotExist:
            raise serializers.ValidationError("Invalid reservation")