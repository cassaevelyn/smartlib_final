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
} from '@mui/material'
import { Event, LocationOn, AccessTime, ChevronRight } from '@mui/icons-material'
import { motion } from 'framer-motion'
import { useNavigate } from 'react-router-dom'
import { eventService } from '../../services/eventService'
import { recommendationService } from '../../services/recommendationService'
import { Event as EventType } from '../../types'
import { formatDate, formatTime } from '../../lib/utils'
import { LoadingSpinner } from '../ui/loading-spinner'
import { EventCard } from '../events/EventCard'

export function UpcomingEvents() {
  const navigate = useNavigate()
  const [events, setEvents] = useState<EventType[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetchEvents()
  }, [])

  const fetchEvents = async () => {
    try {
      setIsLoading(true)
      setError(null)
      
      // Get recommended events from the recommendation service
      const recommendations = await recommendationService.getEventsRecommendations()
      
      // Use upcoming events from recommendations
      if (recommendations.category_based && recommendations.category_based.length > 0) {
        setEvents(recommendations.category_based)
      } else if (recommendations.popular && recommendations.popular.length > 0) {
        setEvents(recommendations.popular)
      } else {
        // Fallback to regular event service if recommendations are empty
        const response = await eventService.getEvents({ 
          status: 'REGISTRATION_OPEN',
          page_size: 2
        })
        
        setEvents(response.results)
      }
    } catch (error: any) {
      // If recommendation service fails, fallback to regular event service
      try {
        const response = await eventService.getEvents({ 
          status: 'REGISTRATION_OPEN',
          page_size: 2
        })
        
        setEvents(response.results)
      } catch (fallbackError: any) {
        setError(fallbackError.message || 'Failed to fetch events')
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

  if (events.length === 0) {
    return (
      <Box sx={{ p: 3, textAlign: 'center' }}>
        <Typography variant="body1" color="text.secondary">
          No upcoming events found.
        </Typography>
        <Button
          variant="outlined"
          startIcon={<Event />}
          onClick={() => navigate('/events')}
          sx={{ mt: 2 }}
        >
          Browse Events
        </Button>
      </Box>
    )
  }

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center' }}>
          <Event color="primary" />
          <Typography variant="h5" component="h2" sx={{ ml: 1 }}>
            Upcoming Events
          </Typography>
        </Box>
        <Button
          variant="text"
          endIcon={<ChevronRight />}
          onClick={() => navigate('/events')}
        >
          View All
        </Button>
      </Box>
      <Divider sx={{ mb: 2 }} />
      
      <Grid container spacing={3}>
        {events.map((event, index) => (
          <Grid item xs={12} md={6} key={event.id}>
            <EventCard event={event} />
          </Grid>
        ))}
      </Grid>
    </Box>
  )
}