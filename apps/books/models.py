"""
Book models for Smart Lib
"""
from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator
from django.contrib.auth import get_user_model
from apps.core.models import BaseModel, TimeStampedModel
from apps.core.utils import generate_unique_code, hash_sensitive_data
from datetime import timedelta
import uuid

User = get_user_model()


class BookCategory(BaseModel):
    """
    Model for book categories and subjects
    """
    name = models.CharField(max_length=100, unique=True)
    code = models.CharField(max_length=20, unique=True, blank=True)
    description = models.TextField(blank=True)
    parent_category = models.ForeignKey(
        'self',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='subcategories'
    )
    icon = models.CharField(max_length=50, blank=True)
    color = models.CharField(max_length=7, default='#007bff')  # Hex color
    is_active = models.BooleanField(default=True)
    sort_order = models.PositiveIntegerField(default=0)
    
    class Meta:
        db_table = 'books_category'
        ordering = ['sort_order', 'name']
        verbose_name_plural = 'Book Categories'
    
    def __str__(self):
        if self.parent_category:
            return f"{self.parent_category.name} > {self.name}"
        return self.name
    
    def save(self, *args, **kwargs):
        if not self.code:
            self.code = generate_unique_code('CAT', 4)
        super().save(*args, **kwargs)
    
    @property
    def full_path(self):
        """Get full category path"""
        if self.parent_category:
            return f"{self.parent_category.full_path} > {self.name}"
        return self.name
    
    def get_all_books_count(self):
        """Get total books in this category and subcategories"""
        from django.db.models import Q
        categories = [self.id]
        categories.extend(self.get_all_subcategories())
        return Book.objects.filter(
            category_id__in=categories,
            is_deleted=False
        ).count()
    
    def get_all_subcategories(self):
        """Get all subcategory IDs recursively"""
        subcategory_ids = []
        for subcategory in self.subcategories.filter(is_deleted=False):
            subcategory_ids.append(subcategory.id)
            subcategory_ids.extend(subcategory.get_all_subcategories())
        return subcategory_ids


class Author(BaseModel):
    """
    Model for book authors
    """
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    middle_name = models.CharField(max_length=100, blank=True)
    biography = models.TextField(blank=True)
    birth_date = models.DateField(null=True, blank=True)
    death_date = models.DateField(null=True, blank=True)
    nationality = models.CharField(max_length=100, blank=True)
    website = models.URLField(blank=True)
    photo = models.ImageField(upload_to='authors/photos/', blank=True)
    
    class Meta:
        db_table = 'books_author'
        ordering = ['last_name', 'first_name']
        indexes = [
            models.Index(fields=['last_name', 'first_name']),
        ]
    
    def __str__(self):
        if self.middle_name:
            return f"{self.first_name} {self.middle_name} {self.last_name}"
        return f"{self.first_name} {self.last_name}"
    
    @property
    def full_name(self):
        return str(self)
    
    @property
    def books_count(self):
        return self.books.filter(is_deleted=False).count()


class Publisher(BaseModel):
    """
    Model for book publishers
    """
    name = models.CharField(max_length=200, unique=True)
    description = models.TextField(blank=True)
    website = models.URLField(blank=True)
    email = models.EmailField(blank=True)
    phone = models.CharField(max_length=20, blank=True)
    address = models.TextField(blank=True)
    city = models.CharField(max_length=100, blank=True)
    country = models.CharField(max_length=100, blank=True)
    logo = models.ImageField(upload_to='publishers/logos/', blank=True)
    
    class Meta:
        db_table = 'books_publisher'
        ordering = ['name']
    
    def __str__(self):
        return self.name
    
    @property
    def books_count(self):
        return self.books.filter(is_deleted=False).count()


class Book(BaseModel):
    """
    Model for books (both physical and digital)
    """
    BOOK_TYPES = [
        ('PHYSICAL', 'Physical Book'),
        ('DIGITAL', 'Digital Book'),
        ('BOTH', 'Physical & Digital'),
    ]
    
    BOOK_STATUS = [
        ('AVAILABLE', 'Available'),
        ('RESERVED', 'Reserved'),
        ('CHECKED_OUT', 'Checked Out'),
        ('MAINTENANCE', 'Under Maintenance'),
        ('LOST', 'Lost'),
        ('DAMAGED', 'Damaged'),
        ('RETIRED', 'Retired'),
    ]
    
    LANGUAGES = [
        ('EN', 'English'),
        ('UR', 'Urdu'),
        ('AR', 'Arabic'),
        ('FR', 'French'),
        ('ES', 'Spanish'),
        ('DE', 'German'),
        ('ZH', 'Chinese'),
        ('JA', 'Japanese'),
        ('RU', 'Russian'),
        ('PT', 'Portuguese'),
    ]
    
    # Basic Information
    title = models.CharField(max_length=500)
    subtitle = models.CharField(max_length=500, blank=True)
    isbn = models.CharField(max_length=20, unique=True, blank=True)
    isbn13 = models.CharField(max_length=20, unique=True, blank=True)
    book_code = models.CharField(max_length=30, unique=True, blank=True)
    
    # Classification
    category = models.ForeignKey(BookCategory, on_delete=models.PROTECT, related_name='books')
    authors = models.ManyToManyField(Author, related_name='books')
    publisher = models.ForeignKey(Publisher, on_delete=models.PROTECT, related_name='books')
    
    # Publication Details
    publication_date = models.DateField(null=True, blank=True)
    edition = models.CharField(max_length=50, blank=True)
    pages = models.PositiveIntegerField(null=True, blank=True)
    language = models.CharField(max_length=5, choices=LANGUAGES, default='EN')
    
    # Content
    description = models.TextField(blank=True)
    table_of_contents = models.TextField(blank=True)
    summary = models.TextField(blank=True)
    keywords = models.JSONField(default=list, blank=True)
    
    # Physical Properties
    book_type = models.CharField(max_length=10, choices=BOOK_TYPES, default='PHYSICAL')
    physical_copies = models.PositiveIntegerField(default=0)
    available_copies = models.PositiveIntegerField(default=0)
    
    # Digital Properties
    digital_file = models.FileField(upload_to='books/digital/', blank=True)
    digital_file_size = models.PositiveIntegerField(null=True, blank=True)  # Size in bytes
    digital_access_password = models.CharField(max_length=100, blank=True)
    max_concurrent_digital_access = models.PositiveIntegerField(default=1)
    digital_access_duration_hours = models.PositiveIntegerField(default=24)
    
    # Library Assignment
    library = models.ForeignKey('library.Library', on_delete=models.CASCADE, related_name='books')
    shelf_location = models.CharField(max_length=100, blank=True)
    call_number = models.CharField(max_length=100, blank=True)
    
    # Status and Availability
    status = models.CharField(max_length=15, choices=BOOK_STATUS, default='AVAILABLE')
    is_featured = models.BooleanField(default=False)
    is_new_arrival = models.BooleanField(default=False)
    is_popular = models.BooleanField(default=False)
    requires_approval = models.BooleanField(default=False)
    
    # Media
    cover_image = models.ImageField(upload_to='books/covers/', blank=True)
    thumbnail = models.ImageField(upload_to='books/thumbnails/', blank=True)
    
    # Statistics
    total_reservations = models.PositiveIntegerField(default=0)
    total_checkouts = models.PositiveIntegerField(default=0)
    average_rating = models.DecimalField(max_digits=3, decimal_places=2, default=0.00)
    total_reviews = models.PositiveIntegerField(default=0)
    view_count = models.PositiveIntegerField(default=0)
    
    # Pricing (for premium books)
    is_premium = models.BooleanField(default=False)
    rental_price_per_day = models.DecimalField(max_digits=8, decimal_places=2, default=0.00)
    
    # Metadata
    tags = models.JSONField(default=list, blank=True)
    additional_metadata = models.JSONField(default=dict, blank=True)
    
    class Meta:
        db_table = 'books_book'
        ordering = ['title']
        indexes = [
            models.Index(fields=['title']),
            models.Index(fields=['isbn']),
            models.Index(fields=['category', 'status']),
            models.Index(fields=['library', 'status']),
            models.Index(fields=['is_featured', 'is_popular']),
        ]
    
    def __str__(self):
        return f"{self.title} ({self.book_code})"
    
    def save(self, *args, **kwargs):
        if not self.book_code:
            self.book_code = generate_unique_code('BK', 6)
        
        # Hash digital access password
        if self.digital_access_password and not self.digital_access_password.startswith('hashed_'):
            self.digital_access_password = f"hashed_{hash_sensitive_data(self.digital_access_password)}"
        
        super().save(*args, **kwargs)
    
    @property
    def is_available(self):
        """Check if book is available for reservation"""
        if self.book_type == 'PHYSICAL':
            return self.status == 'AVAILABLE' and self.available_copies > 0
        elif self.book_type == 'DIGITAL':
            current_digital_access = self.digital_access.filter(
                is_active=True,
                expires_at__gt=timezone.now()
            ).count()
            return current_digital_access < self.max_concurrent_digital_access
        else:  # BOTH
            return (self.available_copies > 0) or (
                self.digital_access.filter(
                    is_active=True,
                    expires_at__gt=timezone.now()
                ).count() < self.max_concurrent_digital_access
            )
    
    @property
    def current_reservations(self):
        """Get current active reservations"""
        return self.reservations.filter(
            status__in=['PENDING', 'CONFIRMED', 'READY_FOR_PICKUP'],
            is_deleted=False
        ).count()
    
    @property
    def authors_list(self):
        """Get comma-separated list of authors"""
        return ", ".join([author.full_name for author in self.authors.all()])
    
    def can_user_reserve(self, user, reservation_type='PHYSICAL'):
        """Check if user can reserve this book"""
        if not self.is_available:
            return False, "Book is not available"
        
        # Check if user already has this book reserved
        existing_reservation = self.reservations.filter(
            user=user,
            status__in=['PENDING', 'CONFIRMED', 'READY_FOR_PICKUP', 'CHECKED_OUT'],
            is_deleted=False
        ).exists()
        
        if existing_reservation:
            return False, "You already have this book reserved"
        
        # Check user's reservation limit
        user_reservations = BookReservation.objects.filter(
            user=user,
            status__in=['PENDING', 'CONFIRMED', 'READY_FOR_PICKUP', 'CHECKED_OUT'],
            is_deleted=False
        ).count()
        
        max_reservations = 5  # This should come from library configuration
        if user_reservations >= max_reservations:
            return False, f"Maximum reservation limit ({max_reservations}) reached"
        
        # Check if premium book requires subscription
        if self.is_premium and not hasattr(user, 'current_subscription'):
            return False, "Premium book requires active subscription"
        
        # Check specific type availability
        if reservation_type == 'PHYSICAL' and self.available_copies <= 0:
            return False, "No physical copies available"
        
        if reservation_type == 'DIGITAL':
            current_digital_access = self.digital_access.filter(
                is_active=True,
                expires_at__gt=timezone.now()
            ).count()
            if current_digital_access >= self.max_concurrent_digital_access:
                return False, "Maximum digital access limit reached"
        
        return True, "Book can be reserved"
    
    def get_estimated_availability_date(self):
        """Get estimated date when book will be available"""
        if self.is_available:
            return timezone.now().date()
        
        # Find earliest return date from current reservations
        earliest_return = self.reservations.filter(
            status__in=['CHECKED_OUT'],
            is_deleted=False
        ).aggregate(
            earliest=models.Min('due_date')
        )['earliest']
        
        return earliest_return or (timezone.now().date() + timedelta(days=14))


class BookReservation(BaseModel):
    """
    Model for book reservations (both physical and digital)
    """
    RESERVATION_STATUS = [
        ('PENDING', 'Pending Approval'),
        ('CONFIRMED', 'Confirmed'),
        ('READY_FOR_PICKUP', 'Ready for Pickup'),
        ('CHECKED_OUT', 'Checked Out'),
        ('RETURNED', 'Returned'),
        ('CANCELLED', 'Cancelled'),
        ('EXPIRED', 'Expired'),
        ('OVERDUE', 'Overdue'),
    ]
    
    RESERVATION_TYPES = [
        ('PHYSICAL', 'Physical Book'),
        ('DIGITAL', 'Digital Access'),
    ]
    
    # Basic Information
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='book_reservations')
    book = models.ForeignKey(Book, on_delete=models.CASCADE, related_name='reservations')
    reservation_code = models.CharField(max_length=30, unique=True, blank=True)
    reservation_type = models.CharField(max_length=10, choices=RESERVATION_TYPES, default='PHYSICAL')
    status = models.CharField(max_length=20, choices=RESERVATION_STATUS, default='CONFIRMED')
    
    # Dates and Times
    reservation_date = models.DateTimeField(auto_now_add=True)
    pickup_deadline = models.DateTimeField(null=True, blank=True)
    pickup_date = models.DateTimeField(null=True, blank=True)
    due_date = models.DateTimeField(null=True, blank=True)
    return_date = models.DateTimeField(null=True, blank=True)
    
    # Digital Access (for digital books)
    digital_access_granted_at = models.DateTimeField(null=True, blank=True)
    digital_access_expires_at = models.DateTimeField(null=True, blank=True)
    digital_access_password = models.CharField(max_length=100, blank=True)
    access_count = models.PositiveIntegerField(default=0)
    max_access_count = models.PositiveIntegerField(default=50)  # Limit PDF opens
    
    # Physical Pickup/Return
    pickup_library = models.ForeignKey(
        'library.Library',
        on_delete=models.CASCADE,
        related_name='book_pickups',
        null=True,
        blank=True
    )
    return_library = models.ForeignKey(
        'library.Library',
        on_delete=models.CASCADE,
        related_name='book_returns',
        null=True,
        blank=True
    )
    
    # Staff Management
    issued_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='issued_book_reservations'
    )
    returned_to = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='received_book_returns'
    )
    
    # Notifications and Reminders
    reminder_sent = models.BooleanField(default=False)
    overdue_notices_sent = models.PositiveIntegerField(default=0)
    
    # Penalties and Fees
    late_fee = models.DecimalField(max_digits=8, decimal_places=2, default=0.00)
    damage_fee = models.DecimalField(max_digits=8, decimal_places=2, default=0.00)
    penalty_points = models.PositiveIntegerField(default=0)
    
    # Additional Information
    purpose = models.CharField(max_length=200, blank=True)
    notes = models.TextField(blank=True)
    condition_at_pickup = models.TextField(blank=True)
    condition_at_return = models.TextField(blank=True)
    
    # Renewal
    renewal_count = models.PositiveIntegerField(default=0)
    max_renewals = models.PositiveIntegerField(default=2)
    
    class Meta:
        db_table = 'books_reservation'
        ordering = ['-reservation_date']
        indexes = [
            models.Index(fields=['user', 'status']),
            models.Index(fields=['book', 'status']),
            models.Index(fields=['status', 'due_date']),
            models.Index(fields=['reservation_date']),
        ]
    
    def __str__(self):
        return f"{self.user.get_full_name()} - {self.book.title} ({self.status})"
    
    def save(self, *args, **kwargs):
        if not self.reservation_code:
            self.reservation_code = generate_unique_code('BR', 8)
        
        # Set pickup deadline (3 days for physical books)
        if not self.pickup_deadline and self.reservation_type == 'PHYSICAL':
            self.pickup_deadline = timezone.now() + timedelta(days=3)
        
        # Set due date (14 days for physical, 24 hours for digital)
        if not self.due_date:
            if self.reservation_type == 'PHYSICAL':
                self.due_date = timezone.now() + timedelta(days=14)
            else:
                self.due_date = timezone.now() + timedelta(hours=self.book.digital_access_duration_hours)
        
        super().save(*args, **kwargs)
    
    @property
    def is_overdue(self):
        """Check if reservation is overdue"""
        if self.status in ['CHECKED_OUT'] and self.due_date:
            return timezone.now() > self.due_date
        return False
    
    @property
    def days_until_due(self):
        """Get days until due date"""
        if self.due_date:
            delta = self.due_date - timezone.now()
            return delta.days
        return None
    
    @property
    def can_renew(self):
        """Check if reservation can be renewed"""
        return (
            self.status == 'CHECKED_OUT' and
            self.renewal_count < self.max_renewals and
            not self.is_overdue
        )
    
    def grant_digital_access(self):
        """Grant digital access to the book"""
        if self.reservation_type != 'DIGITAL':
            return False, "Not a digital reservation"
        
        if self.status != 'CONFIRMED':
            return False, "Reservation must be confirmed first"
        
        # Generate access password
        from apps.core.utils import generate_secure_token
        self.digital_access_password = generate_secure_token()[:12]
        self.digital_access_granted_at = timezone.now()
        self.digital_access_expires_at = timezone.now() + timedelta(
            hours=self.book.digital_access_duration_hours
        )
        self.status = 'CHECKED_OUT'
        self.save()
        
        return True, "Digital access granted"
    
    def renew_reservation(self, renewal_period_days=14):
        """Renew the reservation"""
        if not self.can_renew:
            return False, "Reservation cannot be renewed"
        
        self.due_date = timezone.now() + timedelta(days=renewal_period_days)
        self.renewal_count += 1
        self.save()
        
        return True, f"Reservation renewed until {self.due_date.date()}"
    
    def mark_returned(self, returned_to_user, condition_notes=''):
        """Mark book as returned"""
        if self.status != 'CHECKED_OUT':
            return False, "Book is not checked out"
        
        self.status = 'RETURNED'
        self.return_date = timezone.now()
        self.returned_to = returned_to_user
        self.condition_at_return = condition_notes
        
        # Update book availability
        if self.reservation_type == 'PHYSICAL':
            self.book.available_copies += 1
            self.book.save()
        
        self.save()
        
        return True, "Book returned successfully"


class BookDigitalAccess(BaseModel):
    """
    Model to track digital book access sessions
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='digital_book_access')
    book = models.ForeignKey(Book, on_delete=models.CASCADE, related_name='digital_access')
    reservation = models.ForeignKey(
        BookReservation,
        on_delete=models.CASCADE,
        related_name='digital_access_sessions'
    )
    
    # Access Details
    access_token = models.CharField(max_length=100, unique=True)
    session_id = models.UUIDField(default=uuid.uuid4, unique=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    
    # Timing
    started_at = models.DateTimeField(auto_now_add=True)
    last_activity = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField()
    ended_at = models.DateTimeField(null=True, blank=True)
    
    # Usage Tracking
    pages_viewed = models.JSONField(default=list, blank=True)  # Track which pages were viewed
    total_time_spent = models.DurationField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'books_digital_access'
        ordering = ['-started_at']
    
    def __str__(self):
        return f"{self.user.get_full_name()} - {self.book.title} (Session)"
    
    @property
    def is_expired(self):
        """Check if access session is expired"""
        return timezone.now() > self.expires_at
    
    def end_session(self):
        """End the digital access session"""
        self.is_active = False
        self.ended_at = timezone.now()
        if self.started_at:
            self.total_time_spent = self.ended_at - self.started_at
        self.save()


class BookReview(BaseModel):
    """
    Model for book reviews and ratings
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='book_reviews')
    book = models.ForeignKey(Book, on_delete=models.CASCADE, related_name='reviews')
    reservation = models.ForeignKey(
        BookReservation,
        on_delete=models.CASCADE,
        related_name='review',
        null=True,
        blank=True
    )
    
    # Ratings
    overall_rating = models.PositiveIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)]
    )
    content_rating = models.PositiveIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)],
        null=True, blank=True
    )
    readability_rating = models.PositiveIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)],
        null=True, blank=True
    )
    usefulness_rating = models.PositiveIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)],
        null=True, blank=True
    )
    
    # Review Content
    title = models.CharField(max_length=200, blank=True)
    review_text = models.TextField()
    pros = models.TextField(blank=True)
    cons = models.TextField(blank=True)
    
    # Recommendation
    would_recommend = models.BooleanField(default=True)
    target_audience = models.CharField(max_length=200, blank=True)
    
    # Moderation
    is_approved = models.BooleanField(default=False)
    approved_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='approved_book_reviews'
    )
    approved_at = models.DateTimeField(null=True, blank=True)
    
    # Interaction
    helpful_count = models.PositiveIntegerField(default=0)
    not_helpful_count = models.PositiveIntegerField(default=0)
    reported_count = models.PositiveIntegerField(default=0)
    
    class Meta:
        db_table = 'books_review'
        unique_together = ['user', 'book']
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.book.title} - {self.user.get_full_name()} ({self.overall_rating}★)"
    
    @property
    def helpfulness_ratio(self):
        """Calculate helpfulness ratio"""
        total_votes = self.helpful_count + self.not_helpful_count
        if total_votes == 0:
            return 0
        return (self.helpful_count / total_votes) * 100


class BookWishlist(BaseModel):
    """
    Model for user book wishlists
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='book_wishlist')
    book = models.ForeignKey(Book, on_delete=models.CASCADE, related_name='wishlisted_by')
    priority = models.PositiveIntegerField(default=1)  # 1=High, 2=Medium, 3=Low
    notes = models.TextField(blank=True)
    notify_when_available = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'books_wishlist'
        unique_together = ['user', 'book']
        ordering = ['priority', '-created_at']
    
    def __str__(self):
        return f"{self.user.get_full_name()} - {self.book.title} (Wishlist)"


class BookReadingList(BaseModel):
    """
    Model for user reading lists/collections
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='reading_lists')
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    is_public = models.BooleanField(default=False)
    books = models.ManyToManyField(Book, through='BookReadingListItem', related_name='reading_lists')
    
    class Meta:
        db_table = 'books_reading_list'
        unique_together = ['user', 'name']
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.user.get_full_name()} - {self.name}"
    
    @property
    def books_count(self):
        return self.books.count()


class BookReadingListItem(BaseModel):
    """
    Through model for reading list items
    """
    reading_list = models.ForeignKey(BookReadingList, on_delete=models.CASCADE)
    book = models.ForeignKey(Book, on_delete=models.CASCADE)
    order = models.PositiveIntegerField(default=0)
    notes = models.TextField(blank=True)
    is_read = models.BooleanField(default=False)
    read_date = models.DateField(null=True, blank=True)
    
    class Meta:
        db_table = 'books_reading_list_item'
        unique_together = ['reading_list', 'book']
        ordering = ['order', 'created_at']
    
    def __str__(self):
        return f"{self.reading_list.name} - {self.book.title}"


class BookStatistics(TimeStampedModel):
    """
    Model for tracking book statistics and analytics
    """
    book = models.ForeignKey(Book, on_delete=models.CASCADE, related_name='statistics')
    date = models.DateField()
    
    # Daily Statistics
    views = models.PositiveIntegerField(default=0)
    reservations = models.PositiveIntegerField(default=0)
    checkouts = models.PositiveIntegerField(default=0)
    returns = models.PositiveIntegerField(default=0)
    digital_access_sessions = models.PositiveIntegerField(default=0)
    
    # User Engagement
    unique_users = models.PositiveIntegerField(default=0)
    average_session_duration = models.DurationField(null=True, blank=True)
    pages_per_session = models.DecimalField(max_digits=6, decimal_places=2, default=0.00)
    
    # Ratings and Reviews
    new_reviews = models.PositiveIntegerField(default=0)
    average_daily_rating = models.DecimalField(max_digits=3, decimal_places=2, default=0.00)
    
    class Meta:
        db_table = 'books_statistics'
        unique_together = ['book', 'date']
        ordering = ['book', '-date']
    
    def __str__(self):
        return f"{self.book.title} - {self.date}"


class BookRecommendation(BaseModel):
    """
    Model for AI-generated book recommendations
    """
    RECOMMENDATION_TYPES = [
        ('SIMILAR', 'Similar Books'),
        ('AUTHOR', 'Same Author'),
        ('CATEGORY', 'Same Category'),
        ('COLLABORATIVE', 'Users Also Liked'),
        ('TRENDING', 'Trending Now'),
        ('PERSONALIZED', 'Personalized'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='book_recommendations')
    book = models.ForeignKey(Book, on_delete=models.CASCADE, related_name='recommendations')
    recommendation_type = models.CharField(max_length=15, choices=RECOMMENDATION_TYPES)
    confidence_score = models.DecimalField(max_digits=5, decimal_places=4, default=0.0000)
    reason = models.TextField(blank=True)
    
    # Interaction Tracking
    viewed = models.BooleanField(default=False)
    clicked = models.BooleanField(default=False)
    reserved = models.BooleanField(default=False)
    dismissed = models.BooleanField(default=False)
    
    # Metadata
    algorithm_version = models.CharField(max_length=20, default='1.0')
    generated_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    
    class Meta:
        db_table = 'books_recommendation'
        unique_together = ['user', 'book', 'recommendation_type']
        ordering = ['-confidence_score', '-generated_at']
    
    def __str__(self):
        return f"{self.user.get_full_name()} - {self.book.title} ({self.recommendation_type})"
    
    @property
    def is_expired(self):
        """Check if recommendation is expired"""
        return timezone.now() > self.expires_at