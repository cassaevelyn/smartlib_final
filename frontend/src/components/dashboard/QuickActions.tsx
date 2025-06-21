import { Grid, Button, Box, Typography } from '@mui/material'
import { 
  EventSeat, 
  MenuBook, 
  Event, 
  Search,
  Add,
  CalendarToday,
  List as ListIcon,
  CreditCard,
} from '@mui/icons-material'
import { useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { useAuthStore } from '../../stores/authStore'

export function QuickActions() {
  const navigate = useNavigate()
  const { user } = useAuthStore()

  const actions = [
    { 
      title: 'Book a Seat', 
      icon: <EventSeat />, 
      color: '#4f46e5', 
      onClick: () => navigate('/seats/book'),
      description: 'Reserve a study space'
    },
    { 
      title: 'Find Books', 
      icon: <Search />, 
      color: '#0891b2', 
      onClick: () => navigate('/books'),
      description: 'Search the library catalog'
    },
    { 
      title: 'Browse Events', 
      icon: <Event />, 
      color: '#16a34a', 
      onClick: () => navigate('/events'),
      description: 'Discover upcoming events'
    },
    { 
      title: 'My Bookings', 
      icon: <CalendarToday />, 
      color: '#9333ea', 
      onClick: () => navigate('/my-bookings'),
      description: 'View your seat reservations'
    },
    { 
      title: 'My Reservations', 
      icon: <MenuBook />, 
      color: '#ea580c', 
      onClick: () => navigate('/my-reservations'),
      description: 'Manage your book loans'
    },
    { 
      title: 'My Events', 
      icon: <ListIcon />, 
      color: '#db2777', 
      onClick: () => navigate('/my-events'),
      description: 'See your registered events'
    },
    { 
      title: 'Subscriptions', 
      icon: <CreditCard />, 
      color: '#2563eb', 
      onClick: () => navigate('/subscriptions'),
      description: 'Manage your subscription'
    },
  ]

  return (
    <Box sx={{ mb: 4 }}>
      <Typography variant="h5" component="h2" sx={{ mb: 2 }}>
        Quick Actions
      </Typography>
      
      <Grid container spacing={2}>
        {actions.map((action, index) => (
          <Grid item xs={6} sm={4} md={3} lg={2} key={action.title}>
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3, delay: index * 0.1 }}
              whileHover={{ y: -5, transition: { duration: 0.2 } }}
              whileTap={{ scale: 0.95 }}
            >
              <Button
                variant="outlined"
                fullWidth
                onClick={action.onClick}
                sx={{
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  justifyContent: 'center',
                  p: 2,
                  height: '100%',
                  borderColor: action.color,
                  color: action.color,
                  '&:hover': {
                    borderColor: action.color,
                    backgroundColor: `${action.color}10`,
                  },
                }}
              >
                <Box sx={{ 
                  display: 'flex', 
                  alignItems: 'center', 
                  justifyContent: 'center',
                  bgcolor: `${action.color}20`,
                  borderRadius: '50%',
                  p: 1,
                  mb: 1,
                }}>
                  {action.icon}
                </Box>
                <Typography variant="body2" sx={{ fontWeight: 'bold', mb: 0.5 }}>
                  {action.title}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {action.description}
                </Typography>
              </Button>
            </motion.div>
          </Grid>
        ))}
      </Grid>
    </Box>
  )
}