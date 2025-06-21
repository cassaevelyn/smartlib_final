from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils.safestring import mark_safe
from .models import (
    BookCategory, Author, Publisher, Book, BookReservation,
    BookDigitalAccess, BookReview, BookWishlist, BookReadingList,
    BookReadingListItem, BookStatistics, BookRecommendation
)


@admin.register(BookCategory)
class BookCategoryAdmin(admin.ModelAdmin):
    list_display = [
        'name', 'code', 'parent_category', 'books_count_display',
        'is_active', 'sort_order', 'created_at'
    ]
    list_filter = ['is_active', 'parent_category']
    search_fields = ['name', 'code', 'description']
    ordering = ['sort_order', 'name']
    readonly_fields = ['code', 'created_at', 'updated_at']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'code', 'description', 'parent_category')
        }),
        ('Display Settings', {
            'fields': ('icon', 'color', 'sort_order', 'is_active')
        }),
    )
    
    def books_count_display(self, obj):
        count = obj.get_all_books_count()
        return format_html('<strong>{}</strong>', count)
    books_count_display.short_description = 'Books Count'


@admin.register(Author)
class AuthorAdmin(admin.ModelAdmin):
    list_display = [
        'full_name', 'nationality', 'birth_date', 'books_count',
        'created_at'
    ]
    list_filter = ['nationality', 'birth_date']
    search_fields = ['first_name', 'last_name', 'middle_name']
    ordering = ['last_name', 'first_name']
    readonly_fields = ['created_at', 'updated_at']
    
    fieldsets = (
        ('Personal Information', {
            'fields': ('first_name', 'middle_name', 'last_name', 'photo')
        }),
        ('Biography', {
            'fields': ('biography', 'birth_date', 'death_date', 'nationality')
        }),
        ('Contact', {
            'fields': ('website',)
        }),
    )


@admin.register(Publisher)
class PublisherAdmin(admin.ModelAdmin):
    list_display = [
        'name', 'city', 'country', 'books_count', 'created_at'
    ]
    list_filter = ['country', 'city']
    search_fields = ['name', 'description']
    ordering = ['name']
    readonly_fields = ['created_at', 'updated_at']


@admin.register(Book)
class BookAdmin(admin.ModelAdmin):
    list_display = [
        'title', 'book_code', 'authors_display', 'category',
        'book_type', 'status_display', 'library', 'available_copies',
        'average_rating', 'is_featured'
    ]
    list_filter = [
        'book_type', 'status', 'category', 'library', 'language',
        'is_featured', 'is_new_arrival', 'is_popular', 'is_premium'
    ]
    search_fields = ['title', 'subtitle', 'isbn', 'isbn13', 'book_code']
    readonly_fields = [
        'book_code', 'total_reservations', 'total_checkouts',
        'average_rating', 'total_reviews', 'view_count',
        'created_at', 'updated_at'
    ]
    ordering = ['title']
    filter_horizontal = ['authors']
    
    fieldsets = (
        ('Basic Information', {
            'fields': (
                'title', 'subtitle', 'book_code', 'isbn', 'isbn13',
                'category', 'authors', 'publisher'
            )
        }),
        ('Publication Details', {
            'fields': (
                'publication_date', 'edition', 'pages', 'language'
            )
        }),
        ('Content', {
            'fields': (
                'description', 'table_of_contents', 'summary', 'keywords', 'tags'
            ),
            'classes': ('collapse',)
        }),
        ('Physical Properties', {
            'fields': (
                'book_type', 'physical_copies', 'available_copies',
                'library', 'shelf_location', 'call_number'
            )
        }),
        ('Digital Properties', {
            'fields': (
                'digital_file', 'digital_file_size', 'digital_access_password',
                'max_concurrent_digital_access', 'digital_access_duration_hours'
            ),
            'classes': ('collapse',)
        }),
        ('Status & Features', {
            'fields': (
                'status', 'is_featured', 'is_new_arrival', 'is_popular',
                'requires_approval', 'is_premium', 'rental_price_per_day'
            )
        }),
        ('Media', {
            'fields': ('cover_image', 'thumbnail'),
            'classes': ('collapse',)
        }),
        ('Statistics', {
            'fields': (
                'total_reservations', 'total_checkouts', 'average_rating',
                'total_reviews', 'view_count'
            ),
            'classes': ('collapse',)
        }),
    )
    
    def authors_display(self, obj):
        return obj.authors_list
    authors_display.short_description = 'Authors'
    
    def status_display(self, obj):
        colors = {
            'AVAILABLE': 'green',
            'RESERVED': 'orange',
            'CHECKED_OUT': 'blue',
            'MAINTENANCE': 'red',
            'LOST': 'darkred',
            'DAMAGED': 'red',
            'RETIRED': 'gray'
        }
        color = colors.get(obj.status, 'black')
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color, obj.get_status_display()
        )
    status_display.short_description = 'Status'
    
    actions = ['mark_featured', 'mark_popular', 'mark_available']
    
    def mark_featured(self, request, queryset):
        updated = queryset.update(is_featured=True)
        self.message_user(request, f'{updated} books marked as featured.')
    mark_featured.short_description = 'Mark selected books as featured'
    
    def mark_popular(self, request, queryset):
        updated = queryset.update(is_popular=True)
        self.message_user(request, f'{updated} books marked as popular.')
    mark_popular.short_description = 'Mark selected books as popular'
    
    def mark_available(self, request, queryset):
        updated = queryset.update(status='AVAILABLE')
        self.message_user(request, f'{updated} books marked as available.')
    mark_available.short_description = 'Mark selected books as available'


@admin.register(BookReservation)
class BookReservationAdmin(admin.ModelAdmin):
    list_display = [
        'reservation_code', 'user', 'book_title', 'reservation_type',
        'status_display', 'reservation_date', 'due_date', 'is_overdue_display'
    ]
    list_filter = [
        'reservation_type', 'status', 'reservation_date', 'due_date',
        'pickup_library', 'return_library'
    ]
    search_fields = [
        'reservation_code', 'user__email', 'user__first_name',
        'user__last_name', 'book__title'
    ]
    readonly_fields = [
        'reservation_code', 'reservation_date', 'is_overdue',
        'days_until_due', 'created_at', 'updated_at'
    ]
    date_hierarchy = 'reservation_date'
    ordering = ['-reservation_date']
    
    fieldsets = (
        ('Reservation Information', {
            'fields': (
                'user', 'book', 'reservation_code', 'reservation_type', 'status'
            )
        }),
        ('Dates and Deadlines', {
            'fields': (
                'reservation_date', 'pickup_deadline', 'pickup_date',
                'due_date', 'return_date'
            )
        }),
        ('Digital Access', {
            'fields': (
                'digital_access_granted_at', 'digital_access_expires_at',
                'access_count', 'max_access_count'
            ),
            'classes': ('collapse',)
        }),
        ('Physical Management', {
            'fields': (
                'pickup_library', 'return_library', 'issued_by', 'returned_to'
            ),
            'classes': ('collapse',)
        }),
        ('Fees and Penalties', {
            'fields': (
                'late_fee', 'damage_fee', 'penalty_points'
            ),
            'classes': ('collapse',)
        }),
        ('Additional Information', {
            'fields': (
                'purpose', 'notes', 'condition_at_pickup', 'condition_at_return',
                'renewal_count', 'max_renewals'
            ),
            'classes': ('collapse',)
        }),
    )
    
    def book_title(self, obj):
        return obj.book.title
    book_title.short_description = 'Book'
    
    def status_display(self, obj):
        colors = {
            'PENDING': 'orange',
            'CONFIRMED': 'blue',
            'READY_FOR_PICKUP': 'green',
            'CHECKED_OUT': 'purple',
            'RETURNED': 'darkgreen',
            'CANCELLED': 'red',
            'EXPIRED': 'gray',
            'OVERDUE': 'darkred'
        }
        color = colors.get(obj.status, 'black')
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color, obj.get_status_display()
        )
    status_display.short_description = 'Status'
    
    def is_overdue_display(self, obj):
        if obj.is_overdue:
            return format_html('<span style="color: red; font-weight: bold;">Yes</span>')
        return format_html('<span style="color: green;">No</span>')
    is_overdue_display.short_description = 'Overdue'
    
    actions = ['mark_returned', 'send_reminders', 'mark_overdue']
    
    def mark_returned(self, request, queryset):
        updated = queryset.filter(status='CHECKED_OUT').update(
            status='RETURNED',
            return_date=timezone.now()
        )
        self.message_user(request, f'{updated} reservations marked as returned.')
    mark_returned.short_description = 'Mark selected reservations as returned'


@admin.register(BookDigitalAccess)
class BookDigitalAccessAdmin(admin.ModelAdmin):
    list_display = [
        'user', 'book_title', 'session_id', 'started_at',
        'expires_at', 'is_active', 'total_time_spent'
    ]
    list_filter = ['is_active', 'started_at', 'expires_at']
    search_fields = ['user__email', 'book__title', 'session_id']
    readonly_fields = [
        'session_id', 'started_at', 'last_activity', 'total_time_spent',
        'created_at', 'updated_at'
    ]
    ordering = ['-started_at']
    
    def book_title(self, obj):
        return obj.book.title
    book_title.short_description = 'Book'
    
    def has_add_permission(self, request):
        return False


@admin.register(BookReview)
class BookReviewAdmin(admin.ModelAdmin):
    list_display = [
        'book_title', 'user', 'overall_rating', 'title',
        'is_approved', 'helpful_count', 'created_at'
    ]
    list_filter = [
        'overall_rating', 'is_approved', 'would_recommend', 'created_at'
    ]
    search_fields = ['book__title', 'user__email', 'title', 'review_text']
    readonly_fields = [
        'helpful_count', 'not_helpful_count', 'reported_count',
        'created_at', 'updated_at'
    ]
    ordering = ['-created_at']
    
    fieldsets = (
        ('Review Information', {
            'fields': ('user', 'book', 'reservation', 'title', 'review_text')
        }),
        ('Ratings', {
            'fields': (
                'overall_rating', 'content_rating', 'readability_rating',
                'usefulness_rating'
            )
        }),
        ('Additional Details', {
            'fields': (
                'pros', 'cons', 'would_recommend', 'target_audience'
            ),
            'classes': ('collapse',)
        }),
        ('Moderation', {
            'fields': ('is_approved', 'approved_by', 'approved_at')
        }),
        ('Interaction Stats', {
            'fields': (
                'helpful_count', 'not_helpful_count', 'reported_count'
            ),
            'classes': ('collapse',)
        }),
    )
    
    def book_title(self, obj):
        return obj.book.title
    book_title.short_description = 'Book'
    
    actions = ['approve_reviews', 'reject_reviews']
    
    def approve_reviews(self, request, queryset):
        from django.utils import timezone
        updated = queryset.update(
            is_approved=True,
            approved_by=request.user,
            approved_at=timezone.now()
        )
        self.message_user(request, f'{updated} reviews approved.')
    approve_reviews.short_description = 'Approve selected reviews'
    
    def reject_reviews(self, request, queryset):
        updated = queryset.update(is_approved=False)
        self.message_user(request, f'{updated} reviews rejected.')
    reject_reviews.short_description = 'Reject selected reviews'


@admin.register(BookWishlist)
class BookWishlistAdmin(admin.ModelAdmin):
    list_display = [
        'user', 'book_title', 'priority_display', 'notify_when_available', 'created_at'
    ]
    list_filter = ['priority', 'notify_when_available', 'created_at']
    search_fields = ['user__email', 'book__title']
    ordering = ['-created_at']
    
    def book_title(self, obj):
        return obj.book.title
    book_title.short_description = 'Book'
    
    def priority_display(self, obj):
        priorities = {1: 'High', 2: 'Medium', 3: 'Low'}
        colors = {1: 'red', 2: 'orange', 3: 'green'}
        priority_text = priorities.get(obj.priority, 'Unknown')
        color = colors.get(obj.priority, 'black')
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color, priority_text
        )
    priority_display.short_description = 'Priority'


@admin.register(BookReadingList)
class BookReadingListAdmin(admin.ModelAdmin):
    list_display = [
        'name', 'user', 'books_count', 'is_public', 'created_at'
    ]
    list_filter = ['is_public', 'created_at']
    search_fields = ['name', 'user__email', 'description']
    ordering = ['-created_at']


class BookReadingListItemInline(admin.TabularInline):
    model = BookReadingListItem
    extra = 0
    fields = ['book', 'order', 'is_read', 'read_date', 'notes']


@admin.register(BookStatistics)
class BookStatisticsAdmin(admin.ModelAdmin):
    list_display = [
        'book_title', 'date', 'views', 'reservations',
        'checkouts', 'returns', 'unique_users'
    ]
    list_filter = ['date']
    search_fields = ['book__title']
    readonly_fields = ['created_at', 'updated_at']
    date_hierarchy = 'date'
    ordering = ['-date']
    
    def book_title(self, obj):
        return obj.book.title
    book_title.short_description = 'Book'
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False


@admin.register(BookRecommendation)
class BookRecommendationAdmin(admin.ModelAdmin):
    list_display = [
        'user', 'book_title', 'recommendation_type', 'confidence_score',
        'viewed', 'clicked', 'reserved', 'generated_at'
    ]
    list_filter = [
        'recommendation_type', 'viewed', 'clicked', 'reserved',
        'dismissed', 'generated_at'
    ]
    search_fields = ['user__email', 'book__title']
    readonly_fields = [
        'generated_at', 'algorithm_version', 'created_at', 'updated_at'
    ]
    ordering = ['-generated_at']
    
    def book_title(self, obj):
        return obj.book.title
    book_title.short_description = 'Book'
    
    def has_add_permission(self, request):
        return False