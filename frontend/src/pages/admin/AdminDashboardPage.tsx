import { useState, useEffect } from 'react'
import {
  Box,
  Typography,
  Grid,
  Card,
  CardContent,
  Button,
  Divider,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Avatar,
  Chip,
} from '@mui/material'
import {
  Dashboard,
  People,
  EventSeat,
  MenuBook,
  Event,
  TrendingUp,
  Person,
  Notifications,
  CheckCircle,
  Warning,
  Error as ErrorIcon,
  Info,
  ChevronRight,
} from '@mui/icons-material'
import { motion } from 'framer-motion'
import { useNavigate } from 'react-router-dom'
import { adminService } from '../../services/adminService'
import { useAuthStore } from '../../stores/authStore'
import { LoadingSpinner } from '../../components/ui/loading-spinner'
import { formatDate, formatRelativeTime } from '../../lib/utils'

export function AdminDashboardPage() {
  const navigate = useNavigate()
  const { user } = useAuthStore()
  
  const [stats, setStats] = useState<any>(null)
  const [pendingApprovals, setPendingApprovals] = useState<any[]>([])
  const [recentActivities, setRecentActivities] = useState<any[]>([])
  const [alerts, setAlerts] = useState<any[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetchDashboardData()
  }, [])

  const fetchDashboardData = async () => {
    try {
      setIsLoading(true)
      setError(null)
      
      // In a real app, this would be an actual API call
      // For now, we'll simulate the data
      
      // Simulated stats data
      const statsData = {
        users: {
          total: 1250,
          active: 980,
          pending_approval: 15,
          new_today: 8,
        },
        seats: {
          total: 500,
          available: 320,
          occupied: 180,
          maintenance: 10,
          bookings_today: 85,
        },
        books: {
          total: 8500,
          available: 7200,
          checked_out: 1250,
          overdue: 50,
          reservations_today: 35,
        },
        events: {
          total: 120,
          upcoming: 45,
          in_progress: 5,
          completed: 70,
          registrations_today: 25,
        },
      }
      
      // Simulated pending approvals
      const pendingApprovalsData = [
        {
          id: '1',
          name: 'John Smith',
          email: 'john.smith@example.com',
          crn: 'ICAP-CA-2023-9876',
          registration_date: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
        },
        {
          id: '2',
          name: 'Sarah Johnson',
          email: 'sarah.johnson@example.com',
          crn: 'ICAP-CA-2023-9877',
          registration_date: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString(),
        },
        {
          id: '3',
          name: 'Michael Brown',
          email: 'michael.brown@example.com',
          crn: 'ICAP-CA-2023-9878',
          registration_date: new Date(Date.now() - 4 * 24 * 60 * 60 * 1000).toISOString(),
        },
      ]
      
      // Simulated recent activities
      const recentActivitiesData = [
        {
          id: '1',
          type: 'USER_REGISTRATION',
          description: 'New user registered: Emily White',
          timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
        },
        {
          id: '2',
          type: 'BOOK_RESERVATION',
          description: 'Book "Clean Code" reserved by David Green',
          timestamp: new Date(Date.now() - 4 * 60 * 60 * 1000).toISOString(),
        },
        {
          id: '3',
          type: 'EVENT_CREATION',
          description: 'New event created: Python Programming Workshop',
          timestamp: new Date(Date.now() - 6 * 60 * 60 * 1000).toISOString(),
        },
        {
          id: '4',
          type: 'SEAT_BOOKING',
          description: 'Seat S001 booked by Robert Johnson',
          timestamp: new Date(Date.now() - 8 * 60 * 60 * 1000).toISOString(),
        },
        {
          id: '5',
          type: 'USER_APPROVAL',
          description: 'User James Wilson approved by Admin',
          timestamp: new Date(Date.now() - 10 * 60 * 60 * 1000).toISOString(),
        },
      ]
      
      // Simulated alerts
      const alertsData = [
        {
          id: '1',
          type: 'WARNING',
          title: 'High Seat Occupancy',
          message: 'Main Library is at 90% capacity',
          timestamp: new Date(Date.now() - 1 * 60 * 60 * 1000).toISOString(),
        },
        {
          id: '2',
          type: 'ERROR',
          title: 'System Error',
          message: 'Database backup failed at 02:00 AM',
          timestamp: new Date(Date.now() - 5 * 60 * 60 * 1000).toISOString(),
        },
        {
          id: '3',
          type: 'INFO',
          title: 'Maintenance Scheduled',
          message: 'System maintenance scheduled for tomorrow at 22:00',
          timestamp: new Date(Date.now() - 12 * 60 * 60 * 1000).toISOString(),
        },
      ]
      
      setStats(statsData)
      setPendingApprovals(pendingApprovalsData)
      setRecentActivities(recentActivitiesData)
      setAlerts(alertsData)
    } catch (error: any) {
      setError(error.message || 'Failed to fetch dashboard data')
    } finally {
      setIsLoading(false)
    }
  }

  const getActivityIcon = (type: string) => {
    switch (type) {
      case 'USER_REGISTRATION':
      case 'USER_APPROVAL':
        return <Person />
      case 'BOOK_RESERVATION':
        return <MenuBook />
      case 'EVENT_CREATION':
        return <Event />
      case 'SEAT_BOOKING':
        return <EventSeat />
      default:
        return <Info />
    }
  }

  const getAlertIcon = (type: string) => {
    switch (type) {
      case 'SUCCESS':
        return <CheckCircle color="success" />
      case 'WARNING':
        return <Warning color="warning" />
      case 'ERROR':
        return <ErrorIcon color="error" />
      case 'INFO':
      default:
        return <Info color="info" />
    }
  }

  if (isLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '50vh' }}>
        <LoadingSpinner size="lg" />
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
            Admin Dashboard
          </Typography>
          <Typography variant="body1" color="text.secondary">
            Welcome back, {user?.full_name}! Here's an overview of the system.
          </Typography>
        </Box>

        {/* Stats Cards */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} sm={6} md={3}>
            <motion.div
              whileHover={{ y: -5, transition: { duration: 0.2 } }}
              whileTap={{ scale: 0.98 }}
            >
              <Card sx={{ height: '100%', cursor: 'pointer' }} onClick={() => navigate('/admin/users')}>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                    <Avatar sx={{ bgcolor: 'primary.light', mr: 2 }}>
                      <People />
                    </Avatar>
                    <Typography variant="h6" component="div">
                      Users
                    </Typography>
                  </Box>
                  <Typography variant="h3" component="div" sx={{ mb: 1 }}>
                    {stats.users.total}
                  </Typography>
                  <Grid container spacing={1}>
                    <Grid item xs={6}>
                      <Typography variant="body2" color="text.secondary">
                        Active
                      </Typography>
                      <Typography variant="h6">
                        {stats.users.active}
                      </Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="body2" color="text.secondary">
                        Pending
                      </Typography>
                      <Typography variant="h6">
                        {stats.users.pending_approval}
                      </Typography>
                    </Grid>
                  </Grid>
                </CardContent>
              </Card>
            </motion.div>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <motion.div
              whileHover={{ y: -5, transition: { duration: 0.2 } }}
              whileTap={{ scale: 0.98 }}
            >
              <Card sx={{ height: '100%', cursor: 'pointer' }} onClick={() => navigate('/admin/seats')}>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                    <Avatar sx={{ bgcolor: 'secondary.light', mr: 2 }}>
                      <EventSeat />
                    </Avatar>
                    <Typography variant="h6" component="div">
                      Seats
                    </Typography>
                  </Box>
                  <Typography variant="h3" component="div" sx={{ mb: 1 }}>
                    {stats.seats.total}
                  </Typography>
                  <Grid container spacing={1}>
                    <Grid item xs={6}>
                      <Typography variant="body2" color="text.secondary">
                        Available
                      </Typography>
                      <Typography variant="h6">
                        {stats.seats.available}
                      </Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="body2" color="text.secondary">
                        Occupied
                      </Typography>
                      <Typography variant="h6">
                        {stats.seats.occupied}
                      </Typography>
                    </Grid>
                  </Grid>
                </CardContent>
              </Card>
            </motion.div>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <motion.div
              whileHover={{ y: -5, transition: { duration: 0.2 } }}
              whileTap={{ scale: 0.98 }}
            >
              <Card sx={{ height: '100%', cursor: 'pointer' }} onClick={() => navigate('/admin/books')}>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                    <Avatar sx={{ bgcolor: 'success.light', mr: 2 }}>
                      <MenuBook />
                    </Avatar>
                    <Typography variant="h6" component="div">
                      Books
                    </Typography>
                  </Box>
                  <Typography variant="h3" component="div" sx={{ mb: 1 }}>
                    {stats.books.total}
                  </Typography>
                  <Grid container spacing={1}>
                    <Grid item xs={6}>
                      <Typography variant="body2" color="text.secondary">
                        Available
                      </Typography>
                      <Typography variant="h6">
                        {stats.books.available}
                      </Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="body2" color="text.secondary">
                        Checked Out
                      </Typography>
                      <Typography variant="h6">
                        {stats.books.checked_out}
                      </Typography>
                    </Grid>
                  </Grid>
                </CardContent>
              </Card>
            </motion.div>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <motion.div
              whileHover={{ y: -5, transition: { duration: 0.2 } }}
              whileTap={{ scale: 0.98 }}
            >
              <Card sx={{ height: '100%', cursor: 'pointer' }} onClick={() => navigate('/admin/events')}>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                    <Avatar sx={{ bgcolor: 'warning.light', mr: 2 }}>
                      <Event />
                    </Avatar>
                    <Typography variant="h6" component="div">
                      Events
                    </Typography>
                  </Box>
                  <Typography variant="h3" component="div" sx={{ mb: 1 }}>
                    {stats.events.total}
                  </Typography>
                  <Grid container spacing={1}>
                    <Grid item xs={6}>
                      <Typography variant="body2" color="text.secondary">
                        Upcoming
                      </Typography>
                      <Typography variant="h6">
                        {stats.events.upcoming}
                      </Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="body2" color="text.secondary">
                        In Progress
                      </Typography>
                      <Typography variant="h6">
                        {stats.events.in_progress}
                      </Typography>
                    </Grid>
                  </Grid>
                </CardContent>
              </Card>
            </motion.div>
          </Grid>
        </Grid>

        {/* Main Content */}
        <Grid container spacing={3}>
          {/* Pending Approvals */}
          <Grid item xs={12} md={6}>
            <Card sx={{ height: '100%' }}>
              <CardContent>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                  <Typography variant="h6">
                    Pending Approvals
                  </Typography>
                  <Button
                    variant="text"
                    endIcon={<ChevronRight />}
                    onClick={() => navigate('/admin/users')}
                  >
                    View All
                  </Button>
                </Box>
                <Divider sx={{ mb: 2 }} />
                
                {pendingApprovals.length === 0 ? (
                  <Typography variant="body1" color="text.secondary" sx={{ textAlign: 'center', py: 2 }}>
                    No pending approvals
                  </Typography>
                ) : (
                  <List>
                    {pendingApprovals.map((user, index) => (
                      <motion.div
                        key={user.id}
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ duration: 0.3, delay: index * 0.1 }}
                      >
                        <ListItem
                          sx={{ 
                            mb: 1, 
                            borderRadius: 1,
                            '&:hover': { bgcolor: 'action.hover' }
                          }}
                        >
                          <ListItemIcon>
                            <Person />
                          </ListItemIcon>
                          <ListItemText
                            primary={user.name}
                            secondary={
                              <>
                                <Typography
                                  component="span"
                                  variant="body2"
                                  color="text.primary"
                                >
                                  {user.email} • {user.crn}
                                </Typography>
                                <Typography
                                  component="span"
                                  variant="caption"
                                  color="text.secondary"
                                  sx={{ display: 'block' }}
                                >
                                  Registered: {formatDate(user.registration_date)}
                                </Typography>
                              </>
                            }
                          />
                          <Box sx={{ display: 'flex', gap: 1 }}>
                            <Button
                              size="small"
                              variant="outlined"
                              color="success"
                              onClick={() => {
                                // This would approve the user in a real app
                                alert(`Approve user: ${user.name}`)
                              }}
                            >
                              Approve
                            </Button>
                            <Button
                              size="small"
                              variant="outlined"
                              color="error"
                              onClick={() => {
                                // This would reject the user in a real app
                                alert(`Reject user: ${user.name}`)
                              }}
                            >
                              Reject
                            </Button>
                          </Box>
                        </ListItem>
                      </motion.div>
                    ))}
                  </List>
                )}
              </CardContent>
            </Card>
          </Grid>

          {/* System Alerts */}
          <Grid item xs={12} md={6}>
            <Card sx={{ height: '100%' }}>
              <CardContent>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                  <Typography variant="h6">
                    System Alerts
                  </Typography>
                  <Button
                    variant="text"
                    endIcon={<ChevronRight />}
                    onClick={() => {
                      // This would navigate to a system alerts page in a real app
                      alert('View all system alerts')
                    }}
                  >
                    View All
                  </Button>
                </Box>
                <Divider sx={{ mb: 2 }} />
                
                {alerts.length === 0 ? (
                  <Typography variant="body1" color="text.secondary" sx={{ textAlign: 'center', py: 2 }}>
                    No system alerts
                  </Typography>
                ) : (
                  <List>
                    {alerts.map((alert, index) => (
                      <motion.div
                        key={alert.id}
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ duration: 0.3, delay: index * 0.1 }}
                      >
                        <ListItem
                          sx={{ 
                            mb: 1, 
                            borderRadius: 1,
                            borderLeft: 3,
                            borderColor: 
                              alert.type === 'SUCCESS' ? 'success.main' :
                              alert.type === 'WARNING' ? 'warning.main' :
                              alert.type === 'ERROR' ? 'error.main' :
                              'info.main',
                            '&:hover': { bgcolor: 'action.hover' }
                          }}
                        >
                          <ListItemIcon>
                            {getAlertIcon(alert.type)}
                          </ListItemIcon>
                          <ListItemText
                            primary={alert.title}
                            secondary={
                              <>
                                <Typography
                                  component="span"
                                  variant="body2"
                                  color="text.primary"
                                >
                                  {alert.message}
                                </Typography>
                                <Typography
                                  component="span"
                                  variant="caption"
                                  color="text.secondary"
                                  sx={{ display: 'block' }}
                                >
                                  {formatRelativeTime(alert.timestamp)}
                                </Typography>
                              </>
                            }
                          />
                        </ListItem>
                      </motion.div>
                    ))}
                  </List>
                )}
              </CardContent>
            </Card>
          </Grid>

          {/* Recent Activity */}
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                  <Typography variant="h6">
                    Recent Activity
                  </Typography>
                  <Button
                    variant="text"
                    endIcon={<ChevronRight />}
                    onClick={() => navigate('/admin/analytics')}
                  >
                    View Analytics
                  </Button>
                </Box>
                <Divider sx={{ mb: 2 }} />
                
                <Grid container spacing={2}>
                  {recentActivities.map((activity, index) => (
                    <Grid item xs={12} md={6} key={activity.id}>
                      <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.3, delay: index * 0.1 }}
                      >
                        <Card variant="outlined">
                          <CardContent>
                            <Box sx={{ display: 'flex', alignItems: 'flex-start' }}>
                              <Avatar sx={{ bgcolor: 'primary.light', mr: 2 }}>
                                {getActivityIcon(activity.type)}
                              </Avatar>
                              <Box>
                                <Typography variant="body1">
                                  {activity.description}
                                </Typography>
                                <Typography variant="caption" color="text.secondary">
                                  {formatRelativeTime(activity.timestamp)}
                                </Typography>
                              </Box>
                            </Box>
                          </CardContent>
                        </Card>
                      </motion.div>
                    </Grid>
                  ))}
                </Grid>
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        {/* Quick Links */}
        <Box sx={{ mt: 4 }}>
          <Typography variant="h6" gutterBottom>
            Quick Links
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={6} sm={3}>
              <Button
                variant="outlined"
                fullWidth
                startIcon={<People />}
                onClick={() => navigate('/admin/users')}
                sx={{ py: 1.5 }}
              >
                Manage Users
              </Button>
            </Grid>
            <Grid item xs={6} sm={3}>
              <Button
                variant="outlined"
                fullWidth
                startIcon={<EventSeat />}
                onClick={() => navigate('/admin/seats')}
                sx={{ py: 1.5 }}
              >
                Manage Seats
              </Button>
            </Grid>
            <Grid item xs={6} sm={3}>
              <Button
                variant="outlined"
                fullWidth
                startIcon={<MenuBook />}
                onClick={() => navigate('/admin/books')}
                sx={{ py: 1.5 }}
              >
                Manage Books
              </Button>
            </Grid>
            <Grid item xs={6} sm={3}>
              <Button
                variant="outlined"
                fullWidth
                startIcon={<TrendingUp />}
                onClick={() => navigate('/admin/analytics')}
                sx={{ py: 1.5 }}
              >
                View Analytics
              </Button>
            </Grid>
          </Grid>
        </Box>
      </motion.div>
    </Box>
  )
}