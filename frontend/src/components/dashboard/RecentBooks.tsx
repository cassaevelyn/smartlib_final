import { useState, useEffect } from 'react'
import { 
  Box, 
  Typography, 
  Card, 
  CardContent, 
  CardMedia, 
  Button, 
  Chip,
  Divider,
  Grid,
  Rating,
} from '@mui/material'
import { MenuBook, ChevronRight } from '@mui/icons-material'
import { motion } from 'framer-motion'
import { useNavigate } from 'react-router-dom'
import { bookService } from '../../services/bookService'
import { recommendationService } from '../../services/recommendationService'
import { Book } from '../../types'
import { truncateText } from '../../lib/utils'
import { LoadingSpinner } from '../ui/loading-spinner'
import { BookCard } from '../books/BookCard'

export function RecentBooks() {
  const navigate = useNavigate()
  const [books, setBooks] = useState<Book[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetchBooks()
  }, [])

  const fetchBooks = async () => {
    try {
      setIsLoading(true)
      setError(null)
      
      // Get recommended books from the recommendation service
      const recommendations = await recommendationService.getBooksRecommendations()
      
      // Use popular books from recommendations
      if (recommendations.popular && recommendations.popular.length > 0) {
        setBooks(recommendations.popular)
      } else {
        // Fallback to regular book service if recommendations are empty
        const response = await bookService.getBooks({ 
          is_popular: true,
          page_size: 4
        })
        
        setBooks(response.results)
      }
    } catch (error: any) {
      // If recommendation service fails, fallback to regular book service
      try {
        const response = await bookService.getBooks({ 
          is_popular: true,
          page_size: 4
        })
        
        setBooks(response.results)
      } catch (fallbackError: any) {
        setError(fallbackError.message || 'Failed to fetch books')
      }
    } finally {
      setIsLoading(false)
    }
  }

  if (isLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
        <LoadingSpinner size="md" />
      </Box>
    )
  }

  if (error) {
    return (
      <Box sx={{ p: 2 }}>
        <Typography color="error">{error}</Typography>
      </Box>
    )
  }

  if (books.length === 0) {
    return (
      <Box sx={{ p: 3, textAlign: 'center' }}>
        <Typography variant="body1" color="text.secondary">
          No books found.
        </Typography>
        <Button
          variant="outlined"
          startIcon={<MenuBook />}
          onClick={() => navigate('/books')}
          sx={{ mt: 2 }}
        >
          Browse Books
        </Button>
      </Box>
    )
  }

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center' }}>
          <MenuBook color="primary" />
          <Typography variant="h5" component="h2" sx={{ ml: 1 }}>
            Popular Books
          </Typography>
        </Box>
        <Button
          variant="text"
          endIcon={<ChevronRight />}
          onClick={() => navigate('/books')}
        >
          View All
        </Button>
      </Box>
      <Divider sx={{ mb: 2 }} />
      
      <Grid container spacing={3}>
        {books.map((book, index) => (
          <Grid item xs={12} sm={6} md={3} key={book.id}>
            <BookCard book={book} />
          </Grid>
        ))}
      </Grid>
    </Box>
  )
}