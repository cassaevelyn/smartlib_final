import { Box, Card, CardContent, CardMedia, Typography, Chip, Button, Rating } from '@mui/material'
import { useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { Book } from '../../types'
import { truncateText } from '../../lib/utils'
import { useAuthStore } from '../../stores/authStore'

interface BookCardProps {
  book: Book
  onClick?: () => void
}

export function BookCard({ book, onClick }: BookCardProps) {
  const navigate = useNavigate()
  const { user } = useAuthStore()

  const handleClick = () => {
    if (onClick) {
      onClick()
    } else {
      navigate(`/books/${book.id}`)
    }
  }

  // Check if user can access premium book
  const canAccessPremium = user?.has_active_subscription || !book.is_premium

  return (
    <motion.div
      whileHover={{ y: -5, transition: { duration: 0.2 } }}
      whileTap={{ scale: 0.98 }}
    >
      <Card sx={{ height: '100%', display: 'flex', flexDirection: 'column', position: 'relative' }}>
        {!canAccessPremium && (
          <Box
            sx={{
              position: 'absolute',
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              bgcolor: 'rgba(0, 0, 0, 0.6)',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              zIndex: 10,
              p: 2,
              textAlign: 'center',
            }}
          >
            <Typography variant="h6" color="white" gutterBottom>
              Premium Content
            </Typography>
            <Typography variant="body2" color="white" sx={{ mb: 2 }}>
              Subscribe to access premium books
            </Typography>
            <Button
              variant="contained"
              color="warning"
              onClick={(e) => {
                e.stopPropagation();
                navigate('/subscriptions');
              }}
            >
              View Plans
            </Button>
          </Box>
        )}
        <CardMedia
          component="img"
          height="160"
          image={book.cover_image || 'https://images.pexels.com/photos/159866/books-book-pages-read-literature-159866.jpeg'}
          alt={book.title}
        />
        <CardContent sx={{ flexGrow: 1 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 1 }}>
            <Typography variant="h6" component="div" sx={{ fontSize: '1rem' }}>
              {truncateText(book.title, 40)}
            </Typography>
          </Box>
          
          <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
            {truncateText(book.authors_list, 30)}
          </Typography>
          
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
            <Rating value={book.average_rating} precision={0.1} size="small" readOnly />
            <Typography variant="body2" color="text.secondary" sx={{ ml: 1 }}>
              ({book.total_reviews})
            </Typography>
          </Box>
          
          <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', mb: 1 }}>
            <Chip
              label={book.book_type_display}
              size="small"
              variant="outlined"
            />
            {book.is_new_arrival && (
              <Chip
                label="New"
                size="small"
                color="success"
              />
            )}
            {book.is_premium && (
              <Chip
                label="Premium"
                size="small"
                color="warning"
              />
            )}
          </Box>
          
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <Chip
              label={book.status_display}
              size="small"
              color={book.is_available ? 'success' : 'error'}
            />
            <Button
              size="small"
              onClick={handleClick}
            >
              View Details
            </Button>
          </Box>
        </CardContent>
      </Card>
    </motion.div>
  )
}