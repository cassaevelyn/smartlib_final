import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  Box,
  Typography,
  Grid,
  Card,
  CardContent,
  CardMedia,
  Button,
  Chip,
  Divider,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Paper,
  Tabs,
  Tab,
  Rating,
  Avatar,
  TextField,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Alert,
  Breadcrumbs,
  Link as MuiLink,
} from '@mui/material'
import {
  MenuBook,
  Person,
  Business,
  Language,
  CalendarToday,
  LocalLibrary,
  Category,
  Description,
  Star,
  NavigateNext,
  ArrowBack,
  Add,
  CreditCard,
} from '@mui/icons-material'
import { motion } from 'framer-motion'
import { useForm, Controller } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { bookService } from '../../services/bookService'
import { recommendationService } from '../../services/recommendationService'
import { BookDetail, BookReview } from '../../types'
import { LoadingSpinner } from '../../components/ui/loading-spinner'
import { useToast } from '../../hooks/use-toast'
import { formatDate } from '../../lib/utils'
import { BookCard } from '../../components/books/BookCard'
import { useAuthStore } from '../../stores/authStore'

interface TabPanelProps {
  children?: React.ReactNode
  index: number
  value: number
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`book-tabpanel-${index}`}
      aria-labelledby={`book-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </div>
  )
}

// Schema for the review form
const reviewSchema = z.object({
  overall_rating: z.number().min(1, 'Rating is required'),
  content_rating: z.number().optional(),
  readability_rating: z.number().optional(),
  usefulness_rating: z.number().optional(),
  title: z.string().optional(),
  review_text: z.string().min(10, 'Review must be at least 10 characters'),
  pros: z.string().optional(),
  cons: z.string().optional(),
  would_recommend: z.boolean().default(true),
  target_audience: z.string().optional(),
})

type ReviewForm = z.infer<typeof reviewSchema>

// Schema for the reservation form
const reservationSchema = z.object({
  reservation_type: z.enum(['PHYSICAL', 'DIGITAL']),
  pickup_library: z.string().optional(),
  purpose: z.string().optional(),
  notes: z.string().optional(),
})

type ReservationForm = z.infer<typeof reservationSchema>

export function BookDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { toast } = useToast()
  const { user } = useAuthStore()
  
  const [book, setBook] = useState<BookDetail | null>(null)
  const [similarBooks, setSimilarBooks] = useState<BookDetail['similar_books']>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [tabValue, setTabValue] = useState(0)
  
  // Dialog states
  const [reviewDialogOpen, setReviewDialogOpen] = useState(false)
  const [reserveDialogOpen, setReserveDialogOpen] = useState(false)
  const [subscriptionDialogOpen, setSubscriptionDialogOpen] = useState(false)
  const [isSubmitting, setIsSubmitting] = useState(false)

  // Review form
  const {
    control: reviewControl,
    handleSubmit: handleReviewSubmit,
    formState: { errors: reviewErrors },
    reset: resetReviewForm,
  } = useForm<ReviewForm>({
    resolver: zodResolver(reviewSchema),
    defaultValues: {
      overall_rating: 0,
      content_rating: 0,
      readability_rating: 0,
      usefulness_rating: 0,
      title: '',
      review_text: '',
      pros: '',
      cons: '',
      would_recommend: true,
      target_audience: '',
    },
  })

  // Reservation form
  const {
    control: reserveControl,
    handleSubmit: handleReserveSubmit,
    formState: { errors: reserveErrors },
    reset: resetReserveForm,
    watch: watchReserve,
  } = useForm<ReservationForm>({
    resolver: zodResolver(reservationSchema),
    defaultValues: {
      reservation_type: 'PHYSICAL',
      pickup_library: '',
      purpose: '',
      notes: '',
    },
  })

  const reservationType = watchReserve('reservation_type')

  useEffect(() => {
    if (!id) return
    fetchBookDetails(id)
    fetchSimilarBooks(id)
  }, [id])

  const fetchBookDetails = async (bookId: string) => {
    try {
      setIsLoading(true)
      setError(null)
      
      const bookData = await bookService.getBook(bookId)
      setBook(bookData)
    } catch (error: any) {
      setError(error.message || 'Failed to fetch book details')
    } finally {
      setIsLoading(false)
    }
  }

  const fetchSimilarBooks = async (bookId: string) => {
    try {
      // Try to get recommendations from the recommendation service
      const recommendations = await recommendationService.getBooksRecommendations()
      
      // Use category-based recommendations as similar books
      if (recommendations.category_based && recommendations.category_based.length > 0) {
        setSimilarBooks(recommendations.category_based)
      }
    } catch (error) {
      // If recommendation service fails, we'll use the similar_books from the book details
      console.error('Failed to fetch recommendations:', error)
    }
  }

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue)
  }

  const onSubmitReview = async (data: ReviewForm) => {
    if (!id) return
    
    try {
      setIsSubmitting(true)
      
      await bookService.submitBookReview(id, data)
      
      toast({
        title: "Review Submitted",
        description: "Your review has been submitted successfully and is pending approval.",
        variant: "default",
      })
      
      setReviewDialogOpen(false)
      resetReviewForm()
      
      // Refresh book details to update reviews
      fetchBookDetails(id)
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || 'Failed to submit review',
        variant: "destructive",
      })
    } finally {
      setIsSubmitting(false)
    }
  }

  const onSubmitReservation = async (data: ReservationForm) => {
    if (!id) return
    
    try {
      setIsSubmitting(true)
      
      const reservationData = {
        ...data,
        book: id,
      }
      
      await bookService.createReservation(reservationData)
      
      toast({
        title: "Reservation Successful",
        description: "Your book reservation has been created successfully.",
        variant: "default",
      })
      
      setReserveDialogOpen(false)
      resetReserveForm()
      
      // Navigate to my reservations page
      navigate('/my-reservations')
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || 'Failed to create reservation',
        variant: "destructive",
      })
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleAddToWishlist = async () => {
    if (!id) return
    
    try {
      await bookService.addToWishlist(id)
      
      toast({
        title: "Added to Wishlist",
        description: "Book has been added to your wishlist.",
        variant: "default",
      })
      
      // Refresh book details
      fetchBookDetails(id)
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || 'Failed to add to wishlist',
        variant: "destructive",
      })
    }
  }

  const handleReserveClick = () => {
    // Check if premium book and user doesn't have subscription
    if (book?.is_premium && !user?.has_active_subscription) {
      setSubscriptionDialogOpen(true)
    } else {
      setReserveDialogOpen(true)
    }
  }

  if (isLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '50vh' }}>
        <LoadingSpinner size="lg" />
      </Box>
    )
  }

  if (error) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
        <Button
          variant="outlined"
          startIcon={<ArrowBack />}
          onClick={() => navigate('/books')}
        >
          Back to Books
        </Button>
      </Box>
    )
  }

  if (!book) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="warning" sx={{ mb: 3 }}>
          Book not found
        </Alert>
        <Button
          variant="outlined"
          startIcon={<ArrowBack />}
          onClick={() => navigate('/books')}
        >
          Back to Books
        </Button>
      </Box>
    )
  }

  // Check if user can access premium book
  const canAccessPremium = user?.has_active_subscription || !book.is_premium

  return (
    <Box sx={{ p: 3 }}>
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
      >
        {/* Breadcrumbs */}
        <Breadcrumbs separator={<NavigateNext fontSize="small" />} sx={{ mb: 2 }}>
          <MuiLink
            component="button"
            variant="body2"
            onClick={() => navigate('/books')}
            underline="hover"
            color="inherit"
          >
            Books
          </MuiLink>
          <Typography color="text.primary">{book.title}</Typography>
        </Breadcrumbs>

        {/* Book Header */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={3}>
            <Card>
              <CardMedia
                component="img"
                image={book.cover_image || 'https://images.pexels.com/photos/159866/books-book-pages-read-literature-159866.jpeg'}
                alt={book.title}
                sx={{ height: 'auto', maxHeight: 400, objectFit: 'contain' }}
              />
            </Card>
          </Grid>
          <Grid item xs={12} md={9}>
            <Box>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <Typography variant="h4" component="h1" gutterBottom>
                  {book.title}
                </Typography>
                {book.is_featured && (
                  <Chip
                    label="Featured"
                    size="small"
                    color="primary"
                    sx={{ ml: 2 }}
                  />
                )}
                {book.is_premium && (
                  <Chip
                    label="Premium"
                    size="small"
                    color="warning"
                    sx={{ ml: 1 }}
                  />
                )}
              </Box>
              
              {book.subtitle && (
                <Typography variant="h6" color="text.secondary" gutterBottom>
                  {book.subtitle}
                </Typography>
              )}
              
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <Rating value={book.average_rating} precision={0.1} readOnly />
                <Typography variant="body2" color="text.secondary" sx={{ ml: 1 }}>
                  {book.average_rating.toFixed(1)} ({book.total_reviews} reviews)
                </Typography>
              </Box>
              
              <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mb: 3 }}>
                <Chip
                  icon={<MenuBook />}
                  label={book.book_type_display}
                  variant="outlined"
                />
                <Chip
                  icon={<Category />}
                  label={book.category_name}
                  variant="outlined"
                />
                <Chip
                  icon={<Language />}
                  label={book.language_display}
                  variant="outlined"
                />
                {book.is_new_arrival && (
                  <Chip
                    label="New Arrival"
                    color="success"
                  />
                )}
                {book.is_popular && (
                  <Chip
                    label="Popular"
                    color="primary"
                  />
                )}
              </Box>
              
              <Grid container spacing={2} sx={{ mb: 3 }}>
                <Grid item xs={12} md={6}>
                  <List dense>
                    <ListItem>
                      <ListItemIcon>
                        <Person />
                      </ListItemIcon>
                      <ListItemText
                        primary="Author(s)"
                        secondary={book.authors_list}
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon>
                        <Business />
                      </ListItemIcon>
                      <ListItemText
                        primary="Publisher"
                        secondary={book.publisher_name}
                      />
                    </ListItem>
                    {book.publication_date && (
                      <ListItem>
                        <ListItemIcon>
                          <CalendarToday />
                        </ListItemIcon>
                        <ListItemText
                          primary="Publication Date"
                          secondary={formatDate(book.publication_date)}
                        />
                      </ListItem>
                    )}
                  </List>
                </Grid>
                <Grid item xs={12} md={6}>
                  <List dense>
                    <ListItem>
                      <ListItemIcon>
                        <LocalLibrary />
                      </ListItemIcon>
                      <ListItemText
                        primary="Library"
                        secondary={book.library_name}
                      />
                    </ListItem>
                    {book.isbn && (
                      <ListItem>
                        <ListItemIcon>
                          <MenuBook />
                        </ListItemIcon>
                        <ListItemText
                          primary="ISBN"
                          secondary={book.isbn}
                        />
                      </ListItem>
                    )}
                    {book.pages && (
                      <ListItem>
                        <ListItemIcon>
                          <Description />
                        </ListItemIcon>
                        <ListItemText
                          primary="Pages"
                          secondary={book.pages}
                        />
                      </ListItem>
                    )}
                  </List>
                </Grid>
              </Grid>
              
              <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
                <Button
                  variant="contained"
                  disabled={!book.user_can_reserve || book.user_has_reserved}
                  onClick={handleReserveClick}
                >
                  {book.user_has_reserved ? 'Already Reserved' : 'Reserve Book'}
                </Button>
                <Button
                  variant="outlined"
                  onClick={handleAddToWishlist}
                >
                  Add to Wishlist
                </Button>
                {!book.user_has_reviewed && (
                  <Button
                    variant="outlined"
                    onClick={() => setReviewDialogOpen(true)}
                  >
                    Write a Review
                  </Button>
                )}
              </Box>
              
              {!book.is_available && book.estimated_availability && (
                <Alert severity="info" sx={{ mt: 2 }}>
                  This book is currently unavailable. Estimated availability: {formatDate(book.estimated_availability)}
                </Alert>
              )}
              
              {book.is_premium && !user?.has_active_subscription && (
                <Alert severity="warning" sx={{ mt: 2 }}>
                  This is a premium book. Subscribe to a plan to access premium content.
                  <Button 
                    color="warning" 
                    size="small" 
                    sx={{ ml: 2 }}
                    onClick={() => navigate('/subscriptions')}
                  >
                    View Plans
                  </Button>
                </Alert>
              )}
            </Box>
          </Grid>
        </Grid>

        {/* Tabs for different sections */}
        <Box sx={{ width: '100%', mb: 4 }}>
          <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
            <Tabs
              value={tabValue}
              onChange={handleTabChange}
              aria-label="book details tabs"
              variant="scrollable"
              scrollButtons="auto"
            >
              <Tab label="Description" />
              <Tab label="Details" />
              <Tab label="Reviews" />
              <Tab label="Similar Books" />
            </Tabs>
          </Box>

          {/* Description Tab */}
          <TabPanel value={tabValue} index={0}>
            {!canAccessPremium ? (
              <Box sx={{ textAlign: 'center', py: 4 }}>
                <Typography variant="h6" gutterBottom>
                  Premium Content
                </Typography>
                <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
                  Subscribe to a plan to access premium book content
                </Typography>
                <Button
                  variant="contained"
                  color="warning"
                  startIcon={<CreditCard />}
                  onClick={() => navigate('/subscriptions')}
                >
                  View Subscription Plans
                </Button>
              </Box>
            ) : (
              <>
                <Typography variant="h6" gutterBottom>
                  Description
                </Typography>
                <Typography variant="body1" paragraph>
                  {book.description || 'No description available for this book.'}
                </Typography>
                
                {book.summary && (
                  <>
                    <Typography variant="h6" gutterBottom sx={{ mt: 3 }}>
                      Summary
                    </Typography>
                    <Typography variant="body1" paragraph>
                      {book.summary}
                    </Typography>
                  </>
                )}
              </>
            )}
          </TabPanel>

          {/* Details Tab */}
          <TabPanel value={tabValue} index={1}>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Card>
                  <CardContent>
                    <Typography variant="h6" gutterBottom>
                      Book Information
                    </Typography>
                    <List>
                      <ListItem>
                        <ListItemText
                          primary="Book Code"
                          secondary={book.book_code}
                        />
                      </ListItem>
                      {book.isbn13 && (
                        <ListItem>
                          <ListItemText
                            primary="ISBN-13"
                            secondary={book.isbn13}
                          />
                        </ListItem>
                      )}
                      {book.edition && (
                        <ListItem>
                          <ListItemText
                            primary="Edition"
                            secondary={book.edition}
                          />
                        </ListItem>
                      )}
                      <ListItem>
                        <ListItemText
                          primary="Language"
                          secondary={book.language_display}
                        />
                      </ListItem>
                    </List>
                  </CardContent>
                </Card>
                
                {book.table_of_contents && canAccessPremium && (
                  <Card sx={{ mt: 3 }}>
                    <CardContent>
                      <Typography variant="h6" gutterBottom>
                        Table of Contents
                      </Typography>
                      <Typography variant="body2" component="div" sx={{ whiteSpace: 'pre-line' }}>
                        {book.table_of_contents}
                      </Typography>
                    </CardContent>
                  </Card>
                )}
              </Grid>
              <Grid item xs={12} md={6}>
                <Card>
                  <CardContent>
                    <Typography variant="h6" gutterBottom>
                      Availability Information
                    </Typography>
                    <List>
                      <ListItem>
                        <ListItemText
                          primary="Status"
                          secondary={
                            <Chip
                              label={book.status_display}
                              size="small"
                              color={book.is_available ? 'success' : 'error'}
                              sx={{ mt: 0.5 }}
                            />
                          }
                        />
                      </ListItem>
                      {book.book_type !== 'DIGITAL' && (
                        <>
                          <ListItem>
                            <ListItemText
                              primary="Physical Copies"
                              secondary={`${book.available_copies} available out of ${book.physical_copies} total`}
                            />
                          </ListItem>
                          <ListItem>
                            <ListItemText
                              primary="Current Reservations"
                              secondary={book.current_reservations}
                            />
                          </ListItem>
                          {book.shelf_location && (
                            <ListItem>
                              <ListItemText
                                primary="Shelf Location"
                                secondary={book.shelf_location}
                              />
                            </ListItem>
                          )}
                          {book.call_number && (
                            <ListItem>
                              <ListItemText
                                primary="Call Number"
                                secondary={book.call_number}
                              />
                            </ListItem>
                          )}
                        </>
                      )}
                      {book.book_type !== 'PHYSICAL' && (
                        <>
                          <ListItem>
                            <ListItemText
                              primary="Digital Access"
                              secondary={`Maximum ${book.max_concurrent_digital_access} concurrent users`}
                            />
                          </ListItem>
                          <ListItem>
                            <ListItemText
                              primary="Access Duration"
                              secondary={`${book.digital_access_duration_hours} hours per access`}
                            />
                          </ListItem>
                        </>
                      )}
                    </List>
                  </CardContent>
                </Card>
                
                <Card sx={{ mt: 3 }}>
                  <CardContent>
                    <Typography variant="h6" gutterBottom>
                      Statistics
                    </Typography>
                    <Grid container spacing={2}>
                      <Grid item xs={6}>
                        <Typography variant="body2" color="text.secondary">
                          Total Reservations
                        </Typography>
                        <Typography variant="h6">{book.total_reservations}</Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2" color="text.secondary">
                          Total Checkouts
                        </Typography>
                        <Typography variant="h6">{book.total_checkouts}</Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2" color="text.secondary">
                          Average Rating
                        </Typography>
                        <Box sx={{ display: 'flex', alignItems: 'center' }}>
                          <Typography variant="h6" sx={{ mr: 1 }}>{book.average_rating.toFixed(1)}</Typography>
                          <Rating value={book.average_rating} precision={0.1} size="small" readOnly />
                        </Box>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2" color="text.secondary">
                          Total Reviews
                        </Typography>
                        <Typography variant="h6">{book.total_reviews}</Typography>
                      </Grid>
                    </Grid>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          </TabPanel>

          {/* Reviews Tab */}
          <TabPanel value={tabValue} index={2}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
              <Typography variant="h6">
                Reviews
              </Typography>
              {!book.user_has_reviewed && (
                <Button
                  variant="outlined"
                  startIcon={<Add />}
                  onClick={() => setReviewDialogOpen(true)}
                >
                  Write a Review
                </Button>
              )}
            </Box>
            
            {book.recent_reviews && book.recent_reviews.length > 0 ? (
              book.recent_reviews.map((review) => (
                <Paper key={review.id} sx={{ p: 2, mb: 2 }}>
                  <Box sx={{ display: 'flex', alignItems: 'flex-start', mb: 2 }}>
                    <Avatar src={review.user_avatar} sx={{ mr: 2 }}>
                      {review.user_display.charAt(0)}
                    </Avatar>
                    <Box sx={{ flexGrow: 1 }}>
                      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <Typography variant="subtitle1">{review.user_display}</Typography>
                        <Rating value={review.overall_rating} size="small" readOnly />
                      </Box>
                      <Typography variant="caption" color="text.secondary">
                        {formatDate(review.created_at)}
                      </Typography>
                    </Box>
                  </Box>
                  
                  {review.title && (
                    <Typography variant="subtitle1" gutterBottom>
                      {review.title}
                    </Typography>
                  )}
                  
                  <Typography variant="body1" paragraph>
                    {review.review_text}
                  </Typography>
                  
                  {(review.pros || review.cons) && (
                    <Grid container spacing={2} sx={{ mb: 2 }}>
                      {review.pros && (
                        <Grid item xs={12} sm={6}>
                          <Typography variant="subtitle2" color="success.main">
                            Pros:
                          </Typography>
                          <Typography variant="body2">{review.pros}</Typography>
                        </Grid>
                      )}
                      {review.cons && (
                        <Grid item xs={12} sm={6}>
                          <Typography variant="subtitle2" color="error.main">
                            Cons:
                          </Typography>
                          <Typography variant="body2">{review.cons}</Typography>
                        </Grid>
                      )}
                    </Grid>
                  )}
                  
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <Typography variant="body2" color="text.secondary">
                      {review.would_recommend ? 'Would recommend' : 'Would not recommend'}
                    </Typography>
                    <Chip
                      label={`${review.helpful_count} found helpful`}
                      size="small"
                      variant="outlined"
                    />
                  </Box>
                </Paper>
              ))
            ) : (
              <Box sx={{ textAlign: 'center', py: 4 }}>
                <Typography variant="body1" color="text.secondary">
                  No reviews yet. Be the first to review this book!
                </Typography>
              </Box>
            )}
          </TabPanel>

          {/* Similar Books Tab */}
          <TabPanel value={tabValue} index={3}>
            <Typography variant="h6" gutterBottom>
              Similar Books
            </Typography>
            
            {similarBooks && similarBooks.length > 0 ? (
              <Grid container spacing={3}>
                {similarBooks.map((similarBook) => (
                  <Grid item xs={12} sm={6} md={4} lg={3} key={similarBook.id}>
                    <BookCard book={similarBook} />
                  </Grid>
                ))}
              </Grid>
            ) : book.similar_books && book.similar_books.length > 0 ? (
              <Grid container spacing={3}>
                {book.similar_books.map((similarBook) => (
                  <Grid item xs={12} sm={6} md={4} lg={3} key={similarBook.id}>
                    <BookCard book={similarBook} />
                  </Grid>
                ))}
              </Grid>
            ) : (
              <Box sx={{ textAlign: 'center', py: 4 }}>
                <Typography variant="body1" color="text.secondary">
                  No similar books found.
                </Typography>
              </Box>
            )}
          </TabPanel>
        </Box>

        {/* Review Dialog */}
        <Dialog
          open={reviewDialogOpen}
          onClose={() => !isSubmitting && setReviewDialogOpen(false)}
          maxWidth="md"
          fullWidth
        >
          <DialogTitle>Write a Review</DialogTitle>
          <DialogContent>
            <Box component="form" sx={{ mt: 2 }}>
              <Grid container spacing={3}>
                <Grid item xs={12}>
                  <Typography variant="subtitle1" gutterBottom>
                    Overall Rating
                  </Typography>
                  <Controller
                    name="overall_rating"
                    control={reviewControl}
                    render={({ field }) => (
                      <Rating
                        {...field}
                        onChange={(_, value) => field.onChange(value)}
                        size="large"
                      />
                    )}
                  />
                  {reviewErrors.overall_rating && (
                    <Typography color="error" variant="caption">
                      {reviewErrors.overall_rating.message}
                    </Typography>
                  )}
                </Grid>
                
                <Grid item xs={12} sm={4}>
                  <Typography variant="subtitle2" gutterBottom>
                    Content Rating
                  </Typography>
                  <Controller
                    name="content_rating"
                    control={reviewControl}
                    render={({ field }) => (
                      <Rating
                        {...field}
                        onChange={(_, value) => field.onChange(value)}
                        size="small"
                      />
                    )}
                  />
                </Grid>
                
                <Grid item xs={12} sm={4}>
                  <Typography variant="subtitle2" gutterBottom>
                    Readability Rating
                  </Typography>
                  <Controller
                    name="readability_rating"
                    control={reviewControl}
                    render={({ field }) => (
                      <Rating
                        {...field}
                        onChange={(_, value) => field.onChange(value)}
                        size="small"
                      />
                    )}
                  />
                </Grid>
                
                <Grid item xs={12} sm={4}>
                  <Typography variant="subtitle2" gutterBottom>
                    Usefulness Rating
                  </Typography>
                  <Controller
                    name="usefulness_rating"
                    control={reviewControl}
                    render={({ field }) => (
                      <Rating
                        {...field}
                        onChange={(_, value) => field.onChange(value)}
                        size="small"
                      />
                    )}
                  />
                </Grid>
                
                <Grid item xs={12}>
                  <Controller
                    name="title"
                    control={reviewControl}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="Review Title"
                        fullWidth
                        error={!!reviewErrors.title}
                        helperText={reviewErrors.title?.message}
                      />
                    )}
                  />
                </Grid>
                
                <Grid item xs={12}>
                  <Controller
                    name="review_text"
                    control={reviewControl}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="Review"
                        fullWidth
                        multiline
                        rows={4}
                        error={!!reviewErrors.review_text}
                        helperText={reviewErrors.review_text?.message}
                      />
                    )}
                  />
                </Grid>
                
                <Grid item xs={12} sm={6}>
                  <Controller
                    name="pros"
                    control={reviewControl}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="Pros"
                        fullWidth
                        multiline
                        rows={2}
                        error={!!reviewErrors.pros}
                        helperText={reviewErrors.pros?.message}
                      />
                    )}
                  />
                </Grid>
                
                <Grid item xs={12} sm={6}>
                  <Controller
                    name="cons"
                    control={reviewControl}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="Cons"
                        fullWidth
                        multiline
                        rows={2}
                        error={!!reviewErrors.cons}
                        helperText={reviewErrors.cons?.message}
                      />
                    )}
                  />
                </Grid>
                
                <Grid item xs={12}>
                  <Controller
                    name="target_audience"
                    control={reviewControl}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="Who would you recommend this book to?"
                        fullWidth
                        error={!!reviewErrors.target_audience}
                        helperText={reviewErrors.target_audience?.message}
                      />
                    )}
                  />
                </Grid>
              </Grid>
            </Box>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setReviewDialogOpen(false)} disabled={isSubmitting}>
              Cancel
            </Button>
            <Button
              variant="contained"
              onClick={handleReviewSubmit(onSubmitReview)}
              disabled={isSubmitting}
            >
              {isSubmitting ? <LoadingSpinner size="sm" /> : 'Submit Review'}
            </Button>
          </DialogActions>
        </Dialog>

        {/* Reserve Dialog */}
        <Dialog
          open={reserveDialogOpen}
          onClose={() => !isSubmitting && setReserveDialogOpen(false)}
          maxWidth="sm"
          fullWidth
        >
          <DialogTitle>Reserve Book</DialogTitle>
          <DialogContent>
            <Box component="form" sx={{ mt: 2 }}>
              <Grid container spacing={3}>
                <Grid item xs={12}>
                  <Controller
                    name="reservation_type"
                    control={reserveControl}
                    render={({ field }) => (
                      <TextField
                        select
                        {...field}
                        label="Reservation Type"
                        fullWidth
                        error={!!reserveErrors.reservation_type}
                        helperText={reserveErrors.reservation_type?.message}
                      >
                        {book.book_type === 'PHYSICAL' || book.book_type === 'BOTH' ? (
                          <MenuItem value="PHYSICAL">Physical Book</MenuItem>
                        ) : null}
                        {book.book_type === 'DIGITAL' || book.book_type === 'BOTH' ? (
                          <MenuItem value="DIGITAL">Digital Access</MenuItem>
                        ) : null}
                      </TextField>
                    )}
                  />
                </Grid>
                
                {reservationType === 'PHYSICAL' && (
                  <Grid item xs={12}>
                    <Controller
                      name="pickup_library"
                      control={reserveControl}
                      render={({ field }) => (
                        <TextField
                          select
                          {...field}
                          label="Pickup Library"
                          fullWidth
                          error={!!reserveErrors.pickup_library}
                          helperText={reserveErrors.pickup_library?.message}
                        >
                          <MenuItem value={book.library}>
                            {book.library_name}
                          </MenuItem>
                        </TextField>
                      )}
                    />
                  </Grid>
                )}
                
                <Grid item xs={12}>
                  <Controller
                    name="purpose"
                    control={reserveControl}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="Purpose"
                        fullWidth
                        error={!!reserveErrors.purpose}
                        helperText={reserveErrors.purpose?.message}
                      />
                    )}
                  />
                </Grid>
                
                <Grid item xs={12}>
                  <Controller
                    name="notes"
                    control={reserveControl}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="Additional Notes"
                        fullWidth
                        multiline
                        rows={3}
                        error={!!reserveErrors.notes}
                        helperText={reserveErrors.notes?.message}
                      />
                    )}
                  />
                </Grid>
              </Grid>
              
              {reservationType === 'PHYSICAL' && (
                <Alert severity="info" sx={{ mt: 3 }}>
                  Physical books must be picked up within 3 days of reservation confirmation.
                </Alert>
              )}
              
              {reservationType === 'DIGITAL' && (
                <Alert severity="info" sx={{ mt: 3 }}>
                  Digital access will be granted immediately and will be valid for {book.digital_access_duration_hours} hours.
                </Alert>
              )}
            </Box>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setReserveDialogOpen(false)} disabled={isSubmitting}>
              Cancel
            </Button>
            <Button
              variant="contained"
              onClick={handleReserveSubmit(onSubmitReservation)}
              disabled={isSubmitting}
            >
              {isSubmitting ? <LoadingSpinner size="sm" /> : 'Reserve Book'}
            </Button>
          </DialogActions>
        </Dialog>

        {/* Subscription Dialog */}
        <Dialog
          open={subscriptionDialogOpen}
          onClose={() => setSubscriptionDialogOpen(false)}
          maxWidth="sm"
          fullWidth
        >
          <DialogTitle>Premium Content</DialogTitle>
          <DialogContent>
            <Typography variant="h6" gutterBottom>
              This is a premium book
            </Typography>
            <Typography variant="body1" paragraph>
              You need an active subscription to access premium books.
            </Typography>
            <Alert severity="info" sx={{ mb: 3 }}>
              Subscribe to a plan to enjoy:
              <ul>
                <li>Access to premium books</li>
                <li>Access to premium seats</li>
                <li>Priority registration for events</li>
                <li>Increased reservation limits</li>
                <li>And many more benefits!</li>
              </ul>
            </Alert>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setSubscriptionDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="contained"
              color="warning"
              startIcon={<CreditCard />}
              onClick={() => {
                setSubscriptionDialogOpen(false)
                navigate('/subscriptions')
              }}
            >
              View Subscription Plans
            </Button>
          </DialogActions>
        </Dialog>
      </motion.div>
    </Box>
  )
}