import { Box, Card, CardContent, CardMedia, Typography, Chip, Button } from '@mui/material'
import { useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { Event } from '../../types'
import { formatDate, formatTime, truncateText } from '../../lib/utils'
import { AccessTime, LocationOn } from '@mui/icons-material'

interface EventCardProps {
  event: Event
  onClick?: () => void
}

export function EventCard({ event, onClick }: EventCardProps) {
  const navigate = useNavigate()

  const handleClick = () => {
    if (onClick) {
      onClick()
    } else {
      navigate(`/events/${event.id}`)
    }
  }

  return (
    <motion.div
      whileHover={{ y: -5, transition: { duration: 0.2 } }}
      whileTap={{ scale: 0.98 }}
    >
      <Card sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
        <CardMedia
          component="img"
          height="160"
          image={event.banner_image || 'https://images.pexels.com/photos/7103/writing-notes-idea-conference.jpg'}
          alt={event.title}
        />
        <CardContent sx={{ flexGrow: 1 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 1 }}>
            <Typography variant="h6" component="div" sx={{ fontSize: '1rem' }}>
              {truncateText(event.title, 40)}
            </Typography>
            <Chip
              label={event.event_type_display}
              size="small"
              color="primary"
              variant="outlined"
            />
          </Box>
          
          <Box sx={{ display: 'flex', alignItems: 'center', mt: 1 }}>
            <AccessTime fontSize="small" color="action" sx={{ mr: 0.5 }} />
            <Typography variant="body2" color="text.secondary" component="span">
              {formatDate(event.start_date)} • {formatTime(event.start_time)} - {formatTime(event.end_time)}
            </Typography>
          </Box>
          
          <Box sx={{ display: 'flex', alignItems: 'center', mt: 0.5, mb: 1 }}>
            <LocationOn fontSize="small" color="action" sx={{ mr: 0.5 }} />
            <Typography variant="body2" color="text.secondary">
              {event.library_name} {event.is_online && '(Online)'}
            </Typography>
          </Box>
          
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mt: 1 }}>
            <Chip
              label={event.is_registration_open ? 'Registration Open' : event.status_display}
              size="small"
              color={event.is_registration_open ? 'success' : 'default'}
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