import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Box,
  Typography,
  Grid,
  Card,
  CardContent,
  Button,
  TextField,
  InputAdornment,
  MenuItem,
  Chip,
  FormControl,
  InputLabel,
  Select,
  Pagination,
  Alert,
  Divider,
  IconButton,
} from '@mui/material'
import {
  Search,
  FilterList,
  Close,
} from '@mui/icons-material'
import { motion } from 'framer-motion'
import { bookService } from '../../services/bookService'
import { Book, BookSearchFilters, PaginatedResponse } from '../../types'
import { BookCard } from '../../components/books/BookCard'
import { LoadingSpinner } from '../../components/ui/loading-spinner'

export function BooksPage() {
  const navigate = useNavigate()
  const [books, setBooks] = useState<Book[]>([])
  const [categories, setCategories] = useState<any[]>([])
  const [authors, setAuthors] = useState<any[]>([])
  const [publishers, setPublishers] = useState<any[]>([])
  const [libraries, setLibraries] = useState<any[]>([])
  
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [totalPages, setTotalPages] = useState(1)
  const [currentPage, setCurrentPage] = useState(1)
  const [showFilters, setShowFilters] = useState(false)

  // Filter states
  const [filters, setFilters] = useState<BookSearchFilters>({
    query: '',
    category_id: '',
    author_id: '',
    publisher_id: '',
    library_id: '',
    book_type: '',
    language: '',
    is_available: undefined,
    is_featured: undefined,
    is_new_arrival: undefined,
    is_popular: undefined,
    is_premium: undefined,
    min_rating: undefined,
    publication_year_from: undefined,
    publication_year_to: undefined,
    sort_by: 'title',
  })

  useEffect(() => {
    fetchBooks()
    fetchCategories()
    fetchAuthors()
    fetchPublishers()
  }, [currentPage])

  const fetchBooks = async () => {
    try {
      setIsLoading(true)
      setError(null)

      // Build query parameters
      const params: any = {
        page: currentPage,
      }

      // Add filters to params
      Object.entries(filters).forEach(([key, value]) => {
        if (value !== '' && value !== undefined) {
          params[key] = value
        }
      })

      let response: PaginatedResponse<Book>
      
      if (Object.keys(params).length > 1) {
        // If we have filters beyond just the page, use search endpoint
        response = await bookService.searchBooks(filters)
      } else {
        // Otherwise use the regular endpoint
        response = await bookService.getBooks(params)
      }

      setBooks(response.results)
      setTotalPages(Math.ceil(response.count / 20)) // Assuming 20 items per page
    } catch (error: any) {
      setError(error.message || 'Failed to fetch books')
    } finally {
      setIsLoading(false)
    }
  }

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

  const handleSearch = () => {
    setCurrentPage(1)
    fetchBooks()
  }

  const handleResetFilters = () => {
    setFilters({
      query: '',
      category_id: '',
      author_id: '',
      publisher_id: '',
      library_id: '',
      book_type: '',
      language: '',
      is_available: undefined,
      is_featured: undefined,
      is_new_arrival: undefined,
      is_popular: undefined,
      is_premium: undefined,
      min_rating: undefined,
      publication_year_from: undefined,
      publication_year_to: undefined,
      sort_by: 'title',
    })
    setCurrentPage(1)
  }

  const handlePageChange = (event: React.ChangeEvent<unknown>, value: number) => {
    setCurrentPage(value)
  }

  return (
    <Box sx={{ p: 3 }}>
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
      >
        <Box sx={{ mb: 4 }}>
          <Typography variant="h4" component="h1" gutterBottom>
            Books
          </Typography>
          <Typography variant="body1" color="text.secondary">
            Browse and discover our collection of books.
          </Typography>
        </Box>

        {/* Search and Filters */}
        <Card sx={{ mb: 4 }}>
          <CardContent>
            <Grid container spacing={2} alignItems="center">
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Search Books"
                  value={filters.query}
                  onChange={(e) => setFilters({ ...filters, query: e.target.value })}
                  onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
                  InputProps={{
                    startAdornment: (
                      <InputAdornment position="start">
                        <Search />
                      </InputAdornment>
                    ),
                  }}
                />
              </Grid>
              <Grid item xs={12} md={3}>
                <FormControl fullWidth>
                  <InputLabel>Category</InputLabel>
                  <Select
                    value={filters.category_id}
                    label="Category"
                    onChange={(e) => setFilters({ ...filters, category_id: e.target.value })}
                  >
                    <MenuItem value="">All Categories</MenuItem>
                    {categories.map((category) => (
                      <MenuItem key={category.id} value={category.id}>
                        {category.name}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12} md={3}>
                <Box sx={{ display: 'flex', gap: 1 }}>
                  <Button
                    variant="outlined"
                    startIcon={<FilterList />}
                    onClick={() => setShowFilters(!showFilters)}
                    sx={{ flexGrow: 1 }}
                  >
                    {showFilters ? 'Hide Filters' : 'Show Filters'}
                  </Button>
                  <Button
                    variant="contained"
                    onClick={handleSearch}
                  >
                    Search
                  </Button>
                </Box>
              </Grid>

              {showFilters && (
                <>
                  <Grid item xs={12}>
                    <Divider sx={{ my: 2 }}>Advanced Filters</Divider>
                  </Grid>
                  <Grid item xs={12} md={3}>
                    <FormControl fullWidth>
                      <InputLabel>Author</InputLabel>
                      <Select
                        value={filters.author_id}
                        label="Author"
                        onChange={(e) => setFilters({ ...filters, author_id: e.target.value })}
                      >
                        <MenuItem value="">All Authors</MenuItem>
                        {authors.map((author) => (
                          <MenuItem key={author.id} value={author.id}>
                            {author.full_name}
                          </MenuItem>
                        ))}
                      </Select>
                    </FormControl>
                  </Grid>
                  <Grid item xs={12} md={3}>
                    <FormControl fullWidth>
                      <InputLabel>Publisher</InputLabel>
                      <Select
                        value={filters.publisher_id}
                        label="Publisher"
                        onChange={(e) => setFilters({ ...filters, publisher_id: e.target.value })}
                      >
                        <MenuItem value="">All Publishers</MenuItem>
                        {publishers.map((publisher) => (
                          <MenuItem key={publisher.id} value={publisher.id}>
                            {publisher.name}
                          </MenuItem>
                        ))}
                      </Select>
                    </FormControl>
                  </Grid>
                  <Grid item xs={12} md={3}>
                    <FormControl fullWidth>
                      <InputLabel>Book Type</InputLabel>
                      <Select
                        value={filters.book_type}
                        label="Book Type"
                        onChange={(e) => setFilters({ ...filters, book_type: e.target.value })}
                      >
                        <MenuItem value="">All Types</MenuItem>
                        <MenuItem value="PHYSICAL">Physical</MenuItem>
                        <MenuItem value="DIGITAL">Digital</MenuItem>
                        <MenuItem value="BOTH">Physical & Digital</MenuItem>
                      </Select>
                    </FormControl>
                  </Grid>
                  <Grid item xs={12} md={3}>
                    <FormControl fullWidth>
                      <InputLabel>Language</InputLabel>
                      <Select
                        value={filters.language}
                        label="Language"
                        onChange={(e) => setFilters({ ...filters, language: e.target.value })}
                      >
                        <MenuItem value="">All Languages</MenuItem>
                        <MenuItem value="EN">English</MenuItem>
                        <MenuItem value="UR">Urdu</MenuItem>
                        <MenuItem value="AR">Arabic</MenuItem>
                        <MenuItem value="FR">French</MenuItem>
                        <MenuItem value="ES">Spanish</MenuItem>
                        <MenuItem value="DE">German</MenuItem>
                      </Select>
                    </FormControl>
                  </Grid>
                  <Grid item xs={12} md={3}>
                    <FormControl fullWidth>
                      <InputLabel>Availability</InputLabel>
                      <Select
                        value={filters.is_available === undefined ? '' : filters.is_available.toString()}
                        label="Availability"
                        onChange={(e) => {
                          const value = e.target.value
                          setFilters({ 
                            ...filters, 
                            is_available: value === '' ? undefined : value === 'true'
                          })
                        }}
                      >
                        <MenuItem value="">Any</MenuItem>
                        <MenuItem value="true">Available</MenuItem>
                        <MenuItem value="false">Unavailable</MenuItem>
                      </Select>
                    </FormControl>
                  </Grid>
                  <Grid item xs={12} md={3}>
                    <FormControl fullWidth>
                      <InputLabel>Sort By</InputLabel>
                      <Select
                        value={filters.sort_by}
                        label="Sort By"
                        onChange={(e) => setFilters({ ...filters, sort_by: e.target.value as any })}
                      >
                        <MenuItem value="title">Title</MenuItem>
                        <MenuItem value="author">Author</MenuItem>
                        <MenuItem value="publication_date">Publication Date</MenuItem>
                        <MenuItem value="rating">Rating</MenuItem>
                        <MenuItem value="popularity">Popularity</MenuItem>
                        <MenuItem value="newest">Newest</MenuItem>
                      </Select>
                    </FormControl>
                  </Grid>
                  <Grid item xs={12} md={3}>
                    <TextField
                      fullWidth
                      label="Publication Year From"
                      type="number"
                      value={filters.publication_year_from || ''}
                      onChange={(e) => setFilters({ 
                        ...filters, 
                        publication_year_from: e.target.value ? parseInt(e.target.value) : undefined
                      })}
                      InputProps={{ inputProps: { min: 1000, max: 2030 } }}
                    />
                  </Grid>
                  <Grid item xs={12} md={3}>
                    <TextField
                      fullWidth
                      label="Publication Year To"
                      type="number"
                      value={filters.publication_year_to || ''}
                      onChange={(e) => setFilters({ 
                        ...filters, 
                        publication_year_to: e.target.value ? parseInt(e.target.value) : undefined
                      })}
                      InputProps={{ inputProps: { min: 1000, max: 2030 } }}
                    />
                  </Grid>
                  <Grid item xs={12} sx={{ display: 'flex', justifyContent: 'flex-end' }}>
                    <Button
                      variant="outlined"
                      color="secondary"
                      onClick={handleResetFilters}
                      startIcon={<Close />}
                    >
                      Reset Filters
                    </Button>
                  </Grid>
                </>
              )}
            </Grid>
          </CardContent>
        </Card>

        {/* Error Message */}
        {error && (
          <Alert severity="error" sx={{ mb: 3 }}>
            {error}
          </Alert>
        )}

        {/* Loading State */}
        {isLoading ? (
          <Box sx={{ display: 'flex', justifyContent: 'center', py: 8 }}>
            <LoadingSpinner size="lg" />
          </Box>
        ) : (
          <>
            {/* Books Grid */}
            {books.length === 0 ? (
              <Box sx={{ textAlign: 'center', py: 8 }}>
                <Typography variant="h6" color="text.secondary" gutterBottom>
                  No books found
                </Typography>
                <Typography variant="body1" color="text.secondary">
                  Try adjusting your search or filters
                </Typography>
              </Box>
            ) : (
              <Grid container spacing={3}>
                {books.map((book) => (
                  <Grid item xs={12} sm={6} md={4} lg={3} key={book.id}>
                    <BookCard book={book} />
                  </Grid>
                ))}
              </Grid>
            )}

            {/* Pagination */}
            {totalPages > 1 && (
              <Box sx={{ display: 'flex', justifyContent: 'center', mt: 4 }}>
                <Pagination
                  count={totalPages}
                  page={currentPage}
                  onChange={handlePageChange}
                  color="primary"
                />
              </Box>
            )}
          </>
        )}
      </motion.div>
    </Box>
  )
}