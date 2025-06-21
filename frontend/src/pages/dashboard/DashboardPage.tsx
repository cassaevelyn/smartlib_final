import { useEffect, useState } from 'react'
import { 
  Box, 
  Grid, 
  Paper, 
  Typography, 
  Card, 
  CardContent, 
  Divider,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Avatar,
  Chip,
  Button,
  IconButton,
} from '@mui/material'
import { 
  EventSeat, 
  MenuBook, 
  Event, 
  EmojiEvents,
  AccessTime,
  CalendarToday,
  ChevronRight,
  Notifications,
} from '@mui/icons-material'
import { motion } from 'framer-motion'
import { useNavigate } from 'react-router-dom'
import { useAuthStore } from '../../stores/authStore'
import { dashboardService } from '../../services/dashboardService'
import { DashboardStats, RecentActivity } from '../../types'
import { formatDate, formatRelativeTime } from '../../lib/utils'
import { LoadingSpinner } from '../../components/ui/loading-spinner'
import { QuickActions } from '../../components/dashboard/QuickActions'
import { StatsOverview } from '../../components/dashboard/StatsOverview'
import { CurrentBookings } from '../../components/dashboard/CurrentBookings'
import { RecentBooks } from '../../components/dashboard/RecentBooks'
import { UpcomingEvents } from '../../components/dashboard/UpcomingEvents'
import { ActivityList } from '../../components/dashboard/ActivityList'
import { SubscriptionStatus } from '../../components/dashboard/SubscriptionStatus'

export function DashboardPage() {
  const navigate = useNavigate()
  const { user } = useAuthStore()
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [activities, setActivities] = useState<RecentActivity[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const fetchDashboardData = async () => {
      try {
        setIsLoading(true)
        setError(null)
        
        const statsData = await dashboardService.getDashboardStats()
        const activitiesData = await dashboardService.getRecentActivities()
        
        setStats(statsData)
        setActivities(activitiesData)
      } catch (error: any) {
        setError(error.message || 'Failed to load dashboard data')
      } finally {
        setIsLoading(false)
      }
    }

    fetchDashboardData()
  }, [])

  const getActivityIcon = (type: string) => {
    switch (type) {
      case 'SEAT_BOOKING':
        return <EventSeat color="primary" />
      case 'BOOK_RESERVATION':
        return <MenuBook color="secondary" />
      case 'EVENT_REGISTRATION':
        return <Event color="success" />
      case 'REVIEW_SUBMISSION':
        return <EmojiEvents color="warning" />
      default:
        return <Notifications color="info" />
    }
  }

  if (isLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '50vh' }}>
        <LoadingSpinner size="lg" />
      </Box>
    )
  }

  if (error) {
    return (
      <Box sx={{ p: 3 }}>
        <Paper sx={{ p: 3, bgcolor: 'error.light', color: 'error.contrastText' }}>
          <Typography variant="h6">Error Loading Dashboard</Typography>
          <Typography variant="body1">{error}</Typography>
          <Button 
            variant="contained" 
            sx={{ mt: 2 }}
            onClick={() => window.location.reload()}
          >
            Retry
          </Button>
        </Paper>
      </Box>
    )
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
            Welcome, {user?.first_name}!
          </Typography>
          <Typography variant="body1" color="text.secondary">
            Here's what's happening with your Smart Lib account today.
          </Typography>
        </Box>

        {/* Quick Actions */}
        <QuickActions />

        {/* Subscription Status */}
        <SubscriptionStatus />

        {/* Stats Overview */}
        {stats && <StatsOverview stats={stats} />}

        {/* Main Content */}
        <Grid container spacing={4}>
          <Grid item xs={12} md={8}>
            <CurrentBookings />
            
            <Box sx={{ mt: 4 }}>
              <RecentBooks />
            </Box>
            
            <Box sx={{ mt: 4 }}>
              <UpcomingEvents />
            </Box>
          </Grid>
          
          <Grid item xs={12} md={4}>
            <ActivityList 
              activities={activities}
              title="Recent Activity"
              icon={<Notifications color="primary" />}
              onViewAll={() => navigate('/profile')}
              emptyMessage="No recent activities"
            />
          </Grid>
        </Grid>
      </motion.div>
    </Box>
  )
}