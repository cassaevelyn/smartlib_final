import { Box, Card, CardContent, Typography, Chip, Button, Tooltip } from '@mui/material'
import { PowerSettingsNew, Wifi, Monitor, WbSunny, Accessible, Star } from '@mui/icons-material'
import { motion } from 'framer-motion'
import { useNavigate } from 'react-router-dom'
import { Seat } from '../../types'

interface SeatCardProps {
  seat: Seat
  onSelect?: (seat: Seat) => void
  selected?: boolean
  showBookButton?: boolean
  date?: string
}

export function SeatCard({ seat, onSelect, selected = false, showBookButton = true, date }: SeatCardProps) {
  const navigate = useNavigate()

  return (
    <motion.div
      whileHover={{ y: -5, transition: { duration: 0.2 } }}
      whileTap={{ scale: 0.98 }}
    >
      <Card
        sx={{
          height: '100%',
          cursor: seat.is_available && onSelect ? 'pointer' : 'default',
          opacity: seat.is_available ? 1 : 0.7,
          border: selected ? 2 : 0,
          borderColor: 'primary.main',
        }}
        onClick={() => seat.is_available && onSelect && onSelect(seat)}
      >
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 1 }}>
            <Typography variant="h6" component="div">
              Seat {seat.seat_number}
            </Typography>
            <Chip
              label={seat.status_display}
              size="small"
              color={
                seat.status === 'AVAILABLE'
                  ? 'success'
                  : seat.status === 'OCCUPIED' || seat.status === 'RESERVED'
                  ? 'warning'
                  : 'error'
              }
            />
          </Box>

          <Typography variant="body2" color="text.secondary" gutterBottom>
            {seat.library_name} • {seat.floor_name} • {seat.section_name}
          </Typography>

          <Chip
            label={seat.seat_type_display}
            size="small"
            variant="outlined"
            sx={{ mb: 2 }}
          />

          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mb: 2 }}>
            {seat.has_power_outlet && (
              <Tooltip title="Power Outlet">
                <Chip
                  icon={<PowerSettingsNew fontSize="small" />}
                  label="Power"
                  size="small"
                  variant="outlined"
                />
              </Tooltip>
            )}
            {seat.has_ethernet && (
              <Tooltip title="Ethernet Connection">
                <Chip
                  icon={<Wifi fontSize="small" />}
                  label="Ethernet"
                  size="small"
                  variant="outlined"
                />
              </Tooltip>
            )}
            {seat.has_monitor && (
              <Tooltip title="External Monitor">
                <Chip
                  icon={<Monitor fontSize="small" />}
                  label="Monitor"
                  size="small"
                  variant="outlined"
                />
              </Tooltip>
            )}
            {seat.is_near_window && (
              <Tooltip title="Near Window">
                <Chip
                  icon={<WbSunny fontSize="small" />}
                  label="Window"
                  size="small"
                  variant="outlined"
                />
              </Tooltip>
            )}
            {seat.is_accessible && (
              <Tooltip title="Accessible">
                <Chip
                  icon={<Accessible fontSize="small" />}
                  label="Accessible"
                  size="small"
                  variant="outlined"
                />
              </Tooltip>
            )}
          </Box>

          <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
            <Star sx={{ color: 'gold', mr: 0.5 }} fontSize="small" />
            <Typography variant="body2">
              {seat.average_rating.toFixed(1)} ({seat.total_bookings} bookings)
            </Typography>
          </Box>

          {seat.current_booking && (
            <Typography variant="body2" color="error" sx={{ mb: 2 }}>
              Currently booked until {seat.current_booking.end_time}
            </Typography>
          )}

          {showBookButton && (
            <Button
              variant="contained"
              fullWidth
              disabled={!seat.is_available}
              onClick={(e) => {
                e.stopPropagation()
                navigate(`/seats/book?seat=${seat.id}${date ? `&date=${date}` : ''}`)
              }}
            >
              {seat.is_available ? 'Book Now' : 'Unavailable'}
            </Button>
          )}
        </CardContent>
      </Card>
    </motion.div>
  )
}