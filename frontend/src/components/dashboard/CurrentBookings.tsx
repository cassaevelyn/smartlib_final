import { useState, useEffect } from 'react'
import { 
  Box, 
  Typography, 
  Card, 
  CardContent, 
  Button, 
  Chip,
  Divider,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  IconButton,
} from '@mui/material'
import { 
  EventSeat, 
  ChevronRight, 
  AccessTime, 
  LocationOn,
  QrCode,
  Logout,
} from '@mui/icons-material'
import { motion } from 'framer-motion'
import { useNavigate } from 'react-router-dom'
import { seatService } from '../../services/seatService'
import { SeatBooking } from '../../types'
import { formatDate, formatTime } from '../../lib/utils'
import { LoadingSpinner } from '../ui/loading-spinner'

export function CurrentBookings() {
  const navigate = useNavigate()
  const [bookings, setBookings] = useState<SeatBooking[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const fetchBookings = async () => {
      try {
        setIsLoading(true)
        setError(null)
        
        // Get today's bookings
        const today = new Date().toISOString().split('T')[0]
        const response = await seatService.getBookings({ 
          booking_date: today,
          status: 'CONFIRMED,CHECKED_IN'
        })
        
        setBookings(response.results)
      } catch (error: any) {
        setError(error.message || 'Failed to fetch bookings')
      } finally {
        setIsLoading(false)
      }
    }

    fetchBookings()
  }, [])

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

  if (bookings.length === 0) {
    return (
      <Box sx={{ p: 3, textAlign: 'center' }}>
        <Typography variant="body1" color="text.secondary">
          No current bookings found.
        </Typography>
        <Button
          variant="outlined"
          startIcon={<EventSeat />}
          onClick={() => navigate('/seats/book')}
          sx={{ mt: 2 }}
        >
          Book a Seat
        </Button>
      </Box>
    )
  }

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center' }}>
          <EventSeat color="primary" />
          <Typography variant="h5" component="h2" sx={{ ml: 1 }}>
            Current Bookings
          </Typography>
        </Box>
        <Button
          variant="text"
          endIcon={<ChevronRight />}
          onClick={() => navigate('/my-bookings')}
        >
          View All
        </Button>
      </Box>
      <Divider sx={{ mb: 2 }} />
      
      <List>
        {bookings.map((booking, index) => (
          <motion.div
            key={booking.id}
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.3, delay: index * 0.1 }}
          >
            <Card sx={{ mb: 2 }}>
              <CardContent>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 1 }}>
                  <Typography variant="h6">
                    Seat {booking.seat_display}
                  </Typography>
                  <Chip
                    label={booking.status_display}
                    size="small"
                    color={booking.status === 'CONFIRMED' ? 'primary' : booking.status === 'CHECKED_IN' ? 'success' : 'default'}
                  />
                </Box>
                
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                  <LocationOn fontSize="small" color="action" sx={{ mr: 0.5 }} />
                  <Typography variant="body2" color="text.secondary">
                    {booking.library_name}
                  </Typography>
                </Box>
                
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                  <AccessTime fontSize="small" color="action" sx={{ mr: 0.5 }} />
                  <Typography variant="body2" color="text.secondary">
                    {formatDate(booking.booking_date)} • {booking.start_time} - {booking.end_time} ({booking.duration_hours} hours)
                  </Typography>
                </Box>
                
                <Box sx={{ display: 'flex', justifyContent: 'flex-end', gap: 1 }}>
                  {booking.can_check_in && (
                    <Button
                      size="small"
                      variant="outlined"
                      startIcon={<QrCode />}
                      onClick={() => navigate(`/my-bookings?action=checkin&id=${booking.id}`)}
                    >
                      Check In
                    </Button>
                  )}
                  
                  {booking.can_check_out && (
                    <Button
                      size="small"
                      variant="outlined"
                      startIcon={<Logout />}
                      onClick={() => navigate(`/my-bookings?action=checkout&id=${booking.id}`)}
                    >
                      Check Out
                    </Button>
                  )}
                  
                  <Button
                    size="small"
                    onClick={() => navigate(`/my-bookings?id=${booking.id}`)}
                  >
                    Details
                  </Button>
                </Box>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </List>
    </Box>
  )
}