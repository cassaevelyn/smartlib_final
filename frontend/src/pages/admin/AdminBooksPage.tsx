import { useState, useEffect } from 'react'
import {
  Box,
  Typography,
  Card,
  CardContent,
  Button,
  TextField,
  InputAdornment,
  Chip,
  Divider,
  Alert,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  IconButton,
  Tooltip,
  MenuItem,
  Grid,
} from '@mui/material'
import { DataGrid, GridColDef, GridRenderCellParams, GridToolbar } from '@mui/x-data-grid'
import {
  Search,
  MenuBook,
  Category,
  Person,
  Business,
  LocalLibrary,
  Add,
  Visibility,
  Edit,
  Delete,
  FilterList,
  Star,
} from '@mui/icons-material'
import { motion } from 'framer-motion'
import { adminService } from '../../services/adminService'
import { bookService } from '../../services/bookService'
import { Book } from '../../types'
import { LoadingSpinner } from '../../components/ui/loading-spinner'
import { useToast } from '../../hooks/use-toast'
import { formatDate } from '../../lib/utils'

export function AdminBooksPage() {
  const { toast } = useToast()
  
  const [books, setBooks] = useState<Book[]>([])
  const [categories, setCategories] = useState<any[]>([])
  const [authors, setAuthors] = useState<any[]>([])
  const [publishers, setPublishers] = useState<any[]>([])
  const [libraries, setLibraries] = useState<any[]>([])
  const [selectedBook, setSelectedBook] = useState<Book | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  
  // Filter states
  const [categoryFilter, setCategoryFilter] = useState<string>('')
  const [authorFilter, setAuthorFilter] = useState<string>('')
  const [publisherFilter, setPublisherFilter] = useState<string>('')
  const [libraryFilter, setLibraryFilter] = useState<string>('')
  const [bookTypeFilter, setBookTypeFilter] = useState<string>('')
  const [statusFilter, setStatusFilter] = useState<string>('')
  const [featuredFilter, setFeaturedFilter] = useState<string>('')
  const [newArrivalFilter, setNewArrivalFilter] = useState<string>('')
  const [popularFilter, setPopularFilter] = useState<string>('')
  const [premiumFilter, setPremiumFilter] = useState<string>('')
  
  // Dialog states
  const [viewDialogOpen, setViewDialogOpen] = useState(false)
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [statusDialogOpen, setStatusDialogOpen] = useState(false)
  const [isProcessing, setIsProcessing] = useState(false)
  const [newStatus, setNewStatus] = useState<string>('')

  useEffect(() => {
    fetchCategories()
    fetchAuthors()
    fetchPublishers()
    fetchLibraries()
    fetchBooks()
  }, [])

  const fetchCategories = async () => {
    try {
      const response = await bookService.getCategories()
      setCategories(response.results)
    } catch (error: any) {
      console.error('Failed to fetch categories:', error)
    }
  }

  const fetchAuthors = async () => {
    try {
      const response = await bookService.getAuthors()
      setAuthors(response.results)
    } catch (error: any) {
      console.error('Failed to fetch authors:', error)
    }
  }

  const fetchPublishers = async () => {
    try {
      const response = await bookService.getPublishers()
      setPublishers(response.results)
    } catch (error: any) {
      console.error('Failed to fetch publishers:', error)
    }
  }

  const fetchLibraries = async () => {
    try {
      const response = await adminService.getAdminLibraries()
      setLibraries(response.results)
    } catch (error: any) {
      console.error('Failed to fetch libraries:', error)
    }
  }

  const fetchBooks = async () => {
    try {
      setIsLoading(true)
      setError(null)
      
      // In a real app, this would be an actual API call
      // For now, we'll simulate the data
      
      // Simulated books data
      const booksData: Book[] = [
        {
          id: '1',
          title: 'Clean Code: A Handbook of Agile Software Craftsmanship',
          subtitle: 'A Handbook of Agile Software Craftsmanship',
          book_code: 'BK-001',
          isbn: '9780132350884',
          category_name: 'Software Engineering',
          authors_list: 'Robert C. Martin',
          publisher_name: 'Prentice Hall',
          library_name: 'Main Library',
          book_type: 'PHYSICAL',
          book_type_display: 'Physical Book',
          status: 'AVAILABLE',
          status_display: 'Available',
          is_available: true,
          physical_copies: 3,
          available_copies: 2,
          cover_image: 'https://images.pexels.com/photos/159866/books-book-pages-read-literature-159866.jpeg',
          thumbnail: 'https://images.pexels.com/photos/159866/books-book-pages-read-literature-159866.jpeg',
          average_rating: 4.7,
          total_reviews: 15,
          is_featured: true,
          is_new_arrival: false,
          is_popular: true,
          is_premium: false,
          created_at: new Date(Date.now() - 180 * 24 * 60 * 60 * 1000).toISOString(),
          updated_at: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
        },
        {
          id: '2',
          title: 'Design Patterns: Elements of Reusable Object-Oriented Software',
          subtitle: '',
          book_code: 'BK-002',
          isbn: '9780201633610',
          category_name: 'Software Engineering',
          authors_list: 'Erich Gamma, Richard Helm, Ralph Johnson, John Vlissides',
          publisher_name: 'Addison-Wesley Professional',
          library_name: 'Main Library',
          book_type: 'BOTH',
          book_type_display: 'Physical & Digital',
          status: 'AVAILABLE',
          status_display: 'Available',
          is_available: true,
          physical_copies: 2,
          available_copies: 1,
          cover_image: 'https://images.pexels.com/photos/1370295/pexels-photo-1370295.jpeg',
          thumbnail: 'https://images.pexels.com/photos/1370295/pexels-photo-1370295.jpeg',
          average_rating: 4.5,
          total_reviews: 10,
          is_featured: false,
          is_new_arrival: true,
          is_popular: true,
          is_premium: false,
          created_at: new Date(Date.now() - 150 * 24 * 60 * 60 * 1000).toISOString(),
          updated_at: new Date(Date.now() - 20 * 24 * 60 * 60 * 1000).toISOString(),
        },
        {
          id: '3',
          title: 'The Pragmatic Programmer: Your Journey to Mastery',
          subtitle: 'Your Journey to Mastery',
          book_code: 'BK-003',
          isbn: '9780201616224',
          category_name: 'Software Engineering',
          authors_list: 'Andrew Hunt, David Thomas',
          publisher_name: 'Addison-Wesley Professional',
          library_name: 'Digital Hub',
          book_type: 'DIGITAL',
          book_type_display: 'Digital Book',
          status: 'AVAILABLE',
          status_display: 'Available',
          is_available: true,
          physical_copies: 0,
          available_copies: 0,
          cover_image: 'https://images.pexels.com/photos/1370296/pexels-photo-1370296.jpeg',
          thumbnail: 'https://images.pexels.com/photos/1370296/pexels-photo-1370296.jpeg',
          average_rating: 4.8,
          total_reviews: 8,
          is_featured: true,
          is_new_arrival: false,
          is_popular: true,
          is_premium: true,
          created_at: new Date(Date.now() - 120 * 24 * 60 * 60 * 1000).toISOString(),
          updated_at: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000).toISOString(),
        },
        {
          id: '4',
          title: 'Refactoring: Improving the Design of Existing Code',
          subtitle: '',
          book_code: 'BK-004',
          isbn: '9780134757599',
          category_name: 'Software Engineering',
          authors_list: 'Martin Fowler',
          publisher_name: 'Addison-Wesley Professional',
          library_name: 'Main Library',
          book_type: 'PHYSICAL',
          book_type_display: 'Physical Book',
          status: 'CHECKED_OUT',
          status_display: 'Checked Out',
          is_available: false,
          physical_copies: 2,
          available_copies: 0,
          cover_image: 'https://images.pexels.com/photos/1370298/pexels-photo-1370298.jpeg',
          thumbnail: 'https://images.pexels.com/photos/1370298/pexels-photo-1370298.jpeg',
          average_rating: 4.6,
          total_reviews: 12,
          is_featured: false,
          is_new_arrival: true,
          is_popular: false,
          is_premium: false,
          created_at: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString(),
          updated_at: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString(),
        },
        {
          id: '5',
          title: 'Introduction to Algorithms',
          subtitle: '',
          book_code: 'BK-005',
          isbn: '9780262033848',
          category_name: 'Computer Science',
          authors_list: 'Thomas H. Cormen, Charles E. Leiserson, Ronald L. Rivest, Clifford Stein',
          publisher_name: 'MIT Press',
          library_name: 'Digital Hub',
          book_type: 'BOTH',
          book_type_display: 'Physical & Digital',
          status: 'MAINTENANCE',
          status_display: 'Under Maintenance',
          is_available: false,
          physical_copies: 1,
          available_copies: 0,
          cover_image: 'https://images.pexels.com/photos/1370299/pexels-photo-1370299.jpeg',
          thumbnail: 'https://images.pexels.com/photos/1370299/pexels-photo-1370299.jpeg',
          average_rating: 4.9,
          total_reviews: 20,
          is_featured: true,
          is_new_arrival: false,
          is_popular: true,
          is_premium: false,
          created_at: new Date(Date.now() - 200 * 24 * 60 * 60 * 1000).toISOString(),
          updated_at: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString(),
        },
      ]
      
      setBooks(booksData)
    } catch (error: any) {
      setError(error.message || 'Failed to fetch books')
    } finally {
      setIsLoading(false)
    }
  }

  const handleCreateBook = () => {
    toast({
      title: "Feature Not Implemented",
      description: "Book creation functionality would be implemented here.",
      variant: "default",
    })
  }

  const handleEditBook = (book: Book) => {
    setSelectedBook(book)
    toast({
      title: "Feature Not Implemented",
      description: "Book editing functionality would be implemented here.",
      variant: "default",
    })
  }

  const handleDeleteBook = async () => {
    if (!selectedBook) return
    
    try {
      setIsProcessing(true)
      
      // In a real app, this would be an actual API call
      // For now, we'll simulate the deletion
      
      // Update local state
      setBooks(prevBooks => prevBooks.filter(book => book.id !== selectedBook.id))
      
      toast({
        title: "Book Deleted",
        description: `"${selectedBook.title}" has been deleted successfully.`,
        variant: "default",
      })
      
      setDeleteDialogOpen(false)
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || 'Failed to delete book',
        variant: "destructive",
      })
    } finally {
      setIsProcessing(false)
    }
  }

  const handleChangeBookStatus = async () => {
    if (!selectedBook || !newStatus) return
    
    try {
      setIsProcessing(true)
      
      // In a real app, this would be an actual API call
      // For now, we'll simulate the update
      
      // Update local state
      setBooks(prevBooks =>
        prevBooks.map(book =>
          book.id === selectedBook.id ? {
            ...book,
            status: newStatus as Book['status'],
            status_display: getStatusDisplay(newStatus),
            is_available: newStatus === 'AVAILABLE'
          } : book
        )
      )
      
      toast({
        title: "Status Updated",
        description: `"${selectedBook.title}" status has been updated to ${getStatusDisplay(newStatus)}.`,
        variant: "default",
      })
      
      setStatusDialogOpen(false)
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || 'Failed to update book status',
        variant: "destructive",
      })
    } finally {
      setIsProcessing(false)
    }
  }

  const getStatusDisplay = (status: string): string => {
    switch (status) {
      case 'AVAILABLE':
        return 'Available'
      case 'RESERVED':
        return 'Reserved'
      case 'CHECKED_OUT':
        return 'Checked Out'
      case 'MAINTENANCE':
        return 'Under Maintenance'
      case 'LOST':
        return 'Lost'
      case 'DAMAGED':
        return 'Damaged'
      case 'RETIRED':
        return 'Retired'
      default:
        return status
    }
  }

  const filteredBooks = books.filter(book => {
    const matchesSearch = searchQuery === '' || 
      book.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      book.authors_list.toLowerCase().includes(searchQuery.toLowerCase()) ||
      book.isbn?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      book.book_code.toLowerCase().includes(searchQuery.toLowerCase())
    
    const matchesCategory = categoryFilter === '' || book.category_name === categoryFilter
    const matchesAuthor = authorFilter === '' || book.authors_list.includes(authorFilter)
    const matchesPublisher = publisherFilter === '' || book.publisher_name === publisherFilter
    const matchesLibrary = libraryFilter === '' || book.library_name === libraryFilter
    const matchesBookType = bookTypeFilter === '' || book.book_type === bookTypeFilter
    const matchesStatus = statusFilter === '' || book.status === statusFilter
    
    const matchesFeatured = featuredFilter === '' || 
      (featuredFilter === 'true' && book.is_featured) ||
      (featuredFilter === 'false' && !book.is_featured)
    
    const matchesNewArrival = newArrivalFilter === '' || 
      (newArrivalFilter === 'true' && book.is_new_arrival) ||
      (newArrivalFilter === 'false' && !book.is_new_arrival)
    
    const matchesPopular = popularFilter === '' || 
      (popularFilter === 'true' && book.is_popular) ||
      (popularFilter === 'false' && !book.is_popular)
    
    const matchesPremium = premiumFilter === '' || 
      (premiumFilter === 'true' && book.is_premium) ||
      (premiumFilter === 'false' && !book.is_premium)
    
    return matchesSearch && matchesCategory && matchesAuthor && matchesPublisher && 
           matchesLibrary && matchesBookType && matchesStatus && matchesFeatured && 
           matchesNewArrival && matchesPopular && matchesPremium
  })

  const columns: GridColDef[] = [
    {
      field: 'title',
      headerName: 'Title',
      flex: 1,
      renderCell: (params: GridRenderCellParams<Book>) => (
        <Box sx={{ display: 'flex', alignItems: 'center' }}>
          <MenuBook sx={{ mr: 1 }} />
          <Tooltip title={params.row.title}>
            <Typography variant="body2" noWrap>
              {params.row.title.length > 40 ? params.row.title.substring(0, 40) + '...' : params.row.title}
            </Typography>
          </Tooltip>
        </Box>
      ),
    },
    {
      field: 'authors_list',
      headerName: 'Authors',
      width: 200,
      renderCell: (params: GridRenderCellParams<Book>) => (
        <Tooltip title={params.row.authors_list}>
          <Typography variant="body2" noWrap>
            {params.row.authors_list.length > 30 ? params.row.authors_list.substring(0, 30) + '...' : params.row.authors_list}
          </Typography>
        </Tooltip>
      ),
    },
    {
      field: 'category_name',
      headerName: 'Category',
      width: 150,
    },
    {
      field: 'library_name',
      headerName: 'Library',
      width: 150,
    },
    {
      field: 'book_type_display',
      headerName: 'Type',
      width: 150,
    },
    {
      field: 'status_display',
      headerName: 'Status',
      width: 150,
      renderCell: (params: GridRenderCellParams<Book>) => (
        <Chip
          label={params.row.status_display}
          size="small"
          color={
            params.row.status === 'AVAILABLE'
              ? 'success'
              : params.row.status === 'RESERVED' || params.row.status === 'CHECKED_OUT'
              ? 'warning'
              : 'error'
          }
          variant="outlined"
        />
      ),
    },
    {
      field: 'average_rating',
      headerName: 'Rating',
      width: 120,
      renderCell: (params: GridRenderCellParams<Book>) => (
        <Box sx={{ display: 'flex', alignItems: 'center' }}>
          <Star sx={{ color: 'gold', mr: 0.5 }} fontSize="small" />
          {params.row.average_rating.toFixed(1)} ({params.row.total_reviews})
        </Box>
      ),
    },
    {
      field: 'is_featured',
      headerName: 'Featured',
      width: 120,
      renderCell: (params: GridRenderCellParams<Book>) => (
        <Chip
          label={params.row.is_featured ? 'Yes' : 'No'}
          size="small"
          color={params.row.is_featured ? 'primary' : 'default'}
          variant="outlined"
        />
      ),
    },
    {
      field: 'actions',
      headerName: 'Actions',
      width: 200,
      sortable: false,
      renderCell: (params: GridRenderCellParams<Book>) => (
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Tooltip title="View Details">
            <IconButton
              size="small"
              onClick={() => {
                setSelectedBook(params.row)
                setViewDialogOpen(true)
              }}
            >
              <Visibility fontSize="small" />
            </IconButton>
          </Tooltip>
          
          <Tooltip title="Edit Book">
            <IconButton
              size="small"
              color="primary"
              onClick={() => handleEditBook(params.row)}
            >
              <Edit fontSize="small" />
            </IconButton>
          </Tooltip>
          
          <Tooltip title="Delete Book">
            <IconButton
              size="small"
              color="error"
              onClick={() => {
                setSelectedBook(params.row)
                setDeleteDialogOpen(true)
              }}
            >
              <Delete fontSize="small" />
            </IconButton>
          </Tooltip>
          
          <Tooltip title="Change Status">
            <IconButton
              size="small"
              color="warning"
              onClick={() => {
                setSelectedBook(params.row)
                setNewStatus(params.row.status)
                setStatusDialogOpen(true)
              }}
            >
              <FilterList fontSize="small" />
            </IconButton>
          </Tooltip>
        </Box>
      ),
    },
  ]

  return (
    <Box sx={{ p: 3 }}>
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
      >
        <Box sx={{ mb: 4 }}>
          <Typography variant="h4" component="h1" gutterBottom>
            Book Management
          </Typography>
          <Typography variant="body1" color="text.secondary">
            Manage books, their status, and configurations.
          </Typography>
        </Box>

        {error && (
          <Alert severity="error" sx={{ mb: 3 }}>
            {error}
          </Alert>
        )}

        <Card sx={{ mb: 4 }}>
          <CardContent>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
              <Typography variant="h6">
                Books
              </Typography>
              <Button
                variant="contained"
                startIcon={<Add />}
                onClick={handleCreateBook}
              >
                Add Book
              </Button>
            </Box>
            
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={4}>
                <TextField
                  fullWidth
                  placeholder="Search by title, author, ISBN, or code"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  InputProps={{
                    startAdornment: (
                      <InputAdornment position="start">
                        <Search />
                      </InputAdornment>
                    ),
                  }}
                />
              </Grid>
              <Grid item xs={12} md={4}>
                <TextField
                  select
                  fullWidth
                  label="Category"
                  value={categoryFilter}
                  onChange={(e) => setCategoryFilter(e.target.value)}
                >
                  <MenuItem value="">All Categories</MenuItem>
                  {categories.map((category) => (
                    <MenuItem key={category.id} value={category.name}>
                      {category.name}
                    </MenuItem>
                  ))}
                </TextField>
              </Grid>
              <Grid item xs={12} md={4}>
                <TextField
                  select
                  fullWidth
                  label="Library"
                  value={libraryFilter}
                  onChange={(e) => setLibraryFilter(e.target.value)}
                >
                  <MenuItem value="">All Libraries</MenuItem>
                  {libraries.map((library) => (
                    <MenuItem key={library.id} value={library.name}>
                      {library.name}
                    </MenuItem>
                  ))}
                </TextField>
              </Grid>
              <Grid item xs={12} md={3}>
                <TextField
                  select
                  fullWidth
                  label="Book Type"
                  value={bookTypeFilter}
                  onChange={(e) => setBookTypeFilter(e.target.value)}
                >
                  <MenuItem value="">All Types</MenuItem>
                  <MenuItem value="PHYSICAL">Physical</MenuItem>
                  <MenuItem value="DIGITAL">Digital</MenuItem>
                  <MenuItem value="BOTH">Physical & Digital</MenuItem>
                </TextField>
              </Grid>
              <Grid item xs={12} md={3}>
                <TextField
                  select
                  fullWidth
                  label="Status"
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                >
                  <MenuItem value="">All Statuses</MenuItem>
                  <MenuItem value="AVAILABLE">Available</MenuItem>
                  <MenuItem value="RESERVED">Reserved</MenuItem>
                  <MenuItem value="CHECKED_OUT">Checked Out</MenuItem>
                  <MenuItem value="MAINTENANCE">Under Maintenance</MenuItem>
                  <MenuItem value="LOST">Lost</MenuItem>
                  <MenuItem value="DAMAGED">Damaged</MenuItem>
                  <MenuItem value="RETIRED">Retired</MenuItem>
                </TextField>
              </Grid>
              <Grid item xs={12} md={3}>
                <TextField
                  select
                  fullWidth
                  label="Featured"
                  value={featuredFilter}
                  onChange={(e) => setFeaturedFilter(e.target.value)}
                >
                  <MenuItem value="">All</MenuItem>
                  <MenuItem value="true">Featured</MenuItem>
                  <MenuItem value="false">Not Featured</MenuItem>
                </TextField>
              </Grid>
              <Grid item xs={12} md={3}>
                <TextField
                  select
                  fullWidth
                  label="New Arrival"
                  value={newArrivalFilter}
                  onChange={(e) => setNewArrivalFilter(e.target.value)}
                >
                  <MenuItem value="">All</MenuItem>
                  <MenuItem value="true">New Arrival</MenuItem>
                  <MenuItem value="false">Not New Arrival</MenuItem>
                </TextField>
              </Grid>
            </Grid>
            
            <Box sx={{ height: 600, width: '100%' }}>
              {isLoading ? (
                <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%' }}>
                  <LoadingSpinner size="lg" />
                </Box>
              ) : (
                <DataGrid
                  rows={filteredBooks}
                  columns={columns}
                  initialState={{
                    pagination: {
                      paginationModel: { page: 0, pageSize: 10 },
                    },
                    sorting: {
                      sortModel: [{ field: 'created_at', sort: 'desc' }],
                    },
                  }}
                  pageSizeOptions={[10, 25, 50]}
                  checkboxSelection
                  disableRowSelectionOnClick
                  components={{
                    Toolbar: GridToolbar,
                  }}
                />
              )}
            </Box>
          </CardContent>
        </Card>

        {/* View Book Details Dialog */}
        <Dialog
          open={viewDialogOpen}
          onClose={() => setViewDialogOpen(false)}
          maxWidth="md"
          fullWidth
        >
          <DialogTitle>Book Details</DialogTitle>
          <DialogContent dividers>
            {selectedBook && (
              <Grid container spacing={2}>
                <Grid item xs={12} md={4}>
                  <Box sx={{ textAlign: 'center', mb: 2 }}>
                    <img
                      src={selectedBook.cover_image || 'https://via.placeholder.com/200x300?text=No+Cover'}
                      alt={selectedBook.title}
                      style={{ maxWidth: '100%', maxHeight: 300, objectFit: 'contain' }}
                    />
                  </Box>
                </Grid>
                <Grid item xs={12} md={8}>
                  <Typography variant="h6" gutterBottom>
                    {selectedBook.title}
                  </Typography>
                  {selectedBook.subtitle && (
                    <Typography variant="subtitle1" color="text.secondary" gutterBottom>
                      {selectedBook.subtitle}
                    </Typography>
                  )}
                  
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                    <Star sx={{ color: 'gold', mr: 0.5 }} />
                    <Typography variant="body2">
                      {selectedBook.average_rating.toFixed(1)} ({selectedBook.total_reviews} reviews)
                    </Typography>
                  </Box>
                  
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mb: 2 }}>
                    <Chip
                      icon={<MenuBook />}
                      label={selectedBook.book_type_display}
                      variant="outlined"
                    />
                    <Chip
                      icon={<Category />}
                      label={selectedBook.category_name}
                      variant="outlined"
                    />
                    <Chip
                      label={selectedBook.status_display}
                      color={
                        selectedBook.status === 'AVAILABLE'
                          ? 'success'
                          : selectedBook.status === 'RESERVED' || selectedBook.status === 'CHECKED_OUT'
                          ? 'warning'
                          : 'error'
                      }
                    />
                    {selectedBook.is_featured && (
                      <Chip label="Featured" color="primary" />
                    )}
                    {selectedBook.is_new_arrival && (
                      <Chip label="New Arrival" color="success" />
                    )}
                    {selectedBook.is_popular && (
                      <Chip label="Popular" color="info" />
                    )}
                    {selectedBook.is_premium && (
                      <Chip label="Premium" color="warning" />
                    )}
                  </Box>
                  
                  <Typography variant="subtitle1" gutterBottom>
                    Book Information
                  </Typography>
                  <Grid container spacing={1}>
                    <Grid item xs={12} sm={6}>
                      <Typography variant="body2" color="text.secondary">
                        Authors
                      </Typography>
                      <Typography variant="body1" gutterBottom>
                        {selectedBook.authors_list}
                      </Typography>
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <Typography variant="body2" color="text.secondary">
                        Publisher
                      </Typography>
                      <Typography variant="body1" gutterBottom>
                        {selectedBook.publisher_name}
                      </Typography>
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <Typography variant="body2" color="text.secondary">
                        ISBN
                      </Typography>
                      <Typography variant="body1" gutterBottom>
                        {selectedBook.isbn || 'N/A'}
                      </Typography>
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <Typography variant="body2" color="text.secondary">
                        Book Code
                      </Typography>
                      <Typography variant="body1" gutterBottom>
                        {selectedBook.book_code}
                      </Typography>
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <Typography variant="body2" color="text.secondary">
                        Library
                      </Typography>
                      <Typography variant="body1" gutterBottom>
                        {selectedBook.library_name}
                      </Typography>
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <Typography variant="body2" color="text.secondary">
                        Copies
                      </Typography>
                      <Typography variant="body1" gutterBottom>
                        {selectedBook.available_copies} available out of {selectedBook.physical_copies} total
                      </Typography>
                    </Grid>
                    <Grid item xs={12}>
                      <Typography variant="body2" color="text.secondary">
                        Created At
                      </Typography>
                      <Typography variant="body1" gutterBottom>
                        {formatDate(selectedBook.created_at)}
                      </Typography>
                    </Grid>
                  </Grid>
                </Grid>
              </Grid>
            )}
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setViewDialogOpen(false)}>
              Close
            </Button>
            <Button
              variant="outlined"
              color="primary"
              onClick={() => {
                setViewDialogOpen(false)
                handleEditBook(selectedBook!)
              }}
            >
              Edit
            </Button>
            <Button
              variant="outlined"
              color="warning"
              onClick={() => {
                setViewDialogOpen(false)
                setNewStatus(selectedBook!.status)
                setStatusDialogOpen(true)
              }}
            >
              Change Status
            </Button>
          </DialogActions>
        </Dialog>

        {/* Delete Book Dialog */}
        <Dialog
          open={deleteDialogOpen}
          onClose={() => !isProcessing && setDeleteDialogOpen(false)}
          maxWidth="xs"
          fullWidth
        >
          <DialogTitle>Delete Book</DialogTitle>
          <DialogContent>
            <Typography variant="body1">
              Are you sure you want to delete "{selectedBook?.title}"?
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
              This action cannot be undone.
            </Typography>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setDeleteDialogOpen(false)} disabled={isProcessing}>
              Cancel
            </Button>
            <Button
              variant="contained"
              color="error"
              onClick={handleDeleteBook}
              disabled={isProcessing}
              startIcon={isProcessing ? <LoadingSpinner size="sm" /> : <Delete />}
            >
              Delete
            </Button>
          </DialogActions>
        </Dialog>

        {/* Change Status Dialog */}
        <Dialog
          open={statusDialogOpen}
          onClose={() => !isProcessing && setStatusDialogOpen(false)}
          maxWidth="xs"
          fullWidth
        >
          <DialogTitle>Change Book Status</DialogTitle>
          <DialogContent>
            <Typography variant="body1" gutterBottom>
              Change status for "{selectedBook?.title}"
            </Typography>
            <TextField
              select
              fullWidth
              label="New Status"
              value={newStatus}
              onChange={(e) => setNewStatus(e.target.value)}
              margin="normal"
            >
              <MenuItem value="AVAILABLE">Available</MenuItem>
              <MenuItem value="RESERVED">Reserved</MenuItem>
              <MenuItem value="CHECKED_OUT">Checked Out</MenuItem>
              <MenuItem value="MAINTENANCE">Under Maintenance</MenuItem>
              <MenuItem value="LOST">Lost</MenuItem>
              <MenuItem value="DAMAGED">Damaged</MenuItem>
              <MenuItem value="RETIRED">Retired</MenuItem>
            </TextField>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setStatusDialogOpen(false)} disabled={isProcessing}>
              Cancel
            </Button>
            <Button
              variant="contained"
              color="primary"
              onClick={handleChangeBookStatus}
              disabled={isProcessing || newStatus === selectedBook?.status}
              startIcon={isProcessing ? <LoadingSpinner size="sm" /> : <FilterList />}
            >
              Update Status
            </Button>
          </DialogActions>
        </Dialog>
      </motion.div>
    </Box>
  )
}