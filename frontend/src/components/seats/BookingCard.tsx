import { Box, Card, CardContent, Typography, Chip, Button, Divider } from '@mui/material'
import { LocationOn, AccessTime, CalendarToday, QrCode, Logout, Cancel } from '@mui/icons-material'
import { motion } from 'framer-motion'
import { SeatBooking } from '../../types'
import { formatDate, formatTime, getStatusColor } from '../../lib/utils'

interface BookingCardProps {
  booking: SeatBooking
  onCheckIn?: (booking: SeatBooking) => void
  onCheckOut?: (booking: SeatBooking) => void
  onCancel?: (booking: SeatBooking) => void
  onViewDetails?: (booking: SeatBooking) => void
}

export function BookingCard({ booking, onCheckIn, onCheckOut, onCancel, onViewDetails }: BookingCardProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
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
              className={getStatusColor(booking.status)}
            />
          </Box>
          
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
            <LocationOn fontSize="small" color="action" sx={{ mr: 0.5 }} />
            <Typography variant="body2" color="text.secondary">
              {booking.library_name}
            </Typography>
          </Box>
          
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
            <CalendarToday fontSize="small" color="action" sx={{ mr: 0.5 }} />
            <Typography variant="body2" color="text.secondary">
              {formatDate(booking.booking_date)}
            </Typography>
          </Box>
          
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
            <AccessTime fontSize="small" color="action" sx={{ mr: 0.5 }} />
            <Typography variant="body2" color="text.secondary">
              {booking.start_time} - {booking.end_time} ({booking.duration_hours} hours)
            </Typography>
          </Box>
          
          <Box sx={{ display: 'flex', justifyContent: 'flex-end', gap: 1 }}>
            {booking.can_check_in && onCheckIn && (
              <Button
                size="small"
                variant="outlined"
                startIcon={<QrCode />}
                onClick={() => onCheckIn(booking)}
              >
                Check In
              </Button>
            )}
            
            {booking.can_check_out && onCheckOut && (
              <Button
                size="small"
                variant="outlined"
                startIcon={<Logout />}
                onClick={() => onCheckOut(booking)}
              >
                Check Out
              </Button>
            )}
            
            {booking.status === 'CONFIRMED' && onCancel && (
              <Button
                size="small"
                variant="outlined"
                color="error"
                startIcon={<Cancel />}
                onClick={() => onCancel(booking)}
              >
                Cancel
              </Button>
            )}
            
            {onViewDetails && (
              <Button
                size="small"
                onClick={() => onViewDetails(booking)}
              >
                Details
              </Button>
            )}
          </Box>
        </CardContent>
      </Card>
    </motion.div>
  )
}