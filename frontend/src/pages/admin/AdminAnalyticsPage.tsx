import { useState, useEffect } from 'react'
import {
  Box,
  Typography,
  Card,
  CardContent,
  Grid,
  TextField,
  MenuItem,
  Button,
  Divider,
  Alert,
  Tabs,
  Tab,
  Paper,
} from '@mui/material'
import {
  BarChart as BarChartIcon,
  PieChart as PieChartIcon,
  Timeline as TimelineIcon,
  TrendingUp,
  EventSeat,
  MenuBook,
  Event,
  People,
  CalendarToday,
  DateRange,
  LocalLibrary,
  CreditCard,
} from '@mui/icons-material'
import { DatePicker } from '@mui/x-date-pickers/DatePicker'
import { motion } from 'framer-motion'
import { 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  Legend, 
  ResponsiveContainer,
  LineChart,
  Line,
  PieChart,
  Pie,
  Cell,
  AreaChart,
  Area
} from 'recharts'
import { adminService } from '../../services/adminService'
import { LoadingSpinner } from '../../components/ui/loading-spinner'
import { formatDate, formatCurrency } from '../../lib/utils'

interface TabPanelProps {
  children?: React.ReactNode
  index: number
  value: number
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`analytics-tabpanel-${index}`}
      aria-labelledby={`analytics-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </div>
  )
}

// Colors for charts
const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884D8', '#82CA9D'];

export function AdminAnalyticsPage() {
  const [tabValue, setTabValue] = useState(0)
  const [libraries, setLibraries] = useState<any[]>([])
  const [selectedLibrary, setSelectedLibrary] = useState<string>('')
  const [startDate, setStartDate] = useState<Date | null>(new Date(Date.now() - 30 * 24 * 60 * 60 * 1000))
  const [endDate, setEndDate] = useState<Date | null>(new Date())
  const [days, setDays] = useState<number>(30)
  
  // Analytics data states
  const [dashboardData, setDashboardData] = useState<any>(null)
  const [userData, setUserData] = useState<any>(null)
  const [bookData, setBookData] = useState<any>(null)
  const [seatData, setSeatData] = useState<any>(null)
  const [eventData, setEventData] = useState<any>(null)
  const [libraryData, setLibraryData] = useState<any>(null)
  const [subscriptionData, setSubscriptionData] = useState<any>(null)
  
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetchLibraries()
    fetchAnalyticsData()
  }, [days])

  const fetchLibraries = async () => {
    try {
      const response = await adminService.getAdminLibraries()
      setLibraries(response.results)
    } catch (error: any) {
      console.error('Failed to fetch libraries:', error)
    }
  }

  const fetchAnalyticsData = async () => {
    try {
      setIsLoading(true)
      setError(null)
      
      // Prepare parameters
      const params: any = { days }
      
      if (selectedLibrary) {
        params.library_id = selectedLibrary
      }
      
      // Fetch all analytics data in parallel
      const [
        dashboardResponse,
        userResponse,
        bookResponse,
        seatResponse,
        eventResponse,
        libraryResponse,
        subscriptionResponse
      ] = await Promise.all([
        adminService.getDashboardAnalytics(params),
        adminService.getUserAnalytics(params),
        adminService.getBookAnalytics(params),
        adminService.getSeatAnalytics(params),
        adminService.getEventAnalytics(params),
        adminService.getLibraryAnalytics(params),
        adminService.getSubscriptionAnalytics(params)
      ]);
      
      // Set the data
      setDashboardData(dashboardResponse);
      setUserData(userResponse);
      setBookData(bookResponse);
      setSeatData(seatResponse);
      setEventData(eventResponse);
      setLibraryData(libraryResponse);
      setSubscriptionData(subscriptionResponse);
      
    } catch (error: any) {
      setError(error.message || 'Failed to fetch analytics data')
    } finally {
      setIsLoading(false)
    }
  }

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue)
  }

  const handleApplyFilters = () => {
    // Calculate days between start and end date
    if (startDate && endDate) {
      const diffTime = Math.abs(endDate.getTime() - startDate.getTime())
      const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24))
      setDays(diffDays)
    }
    
    fetchAnalyticsData()
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
            Analytics Dashboard
          </Typography>
          <Typography variant="body1" color="text.secondary">
            View comprehensive analytics and statistics for the Smart Lib system.
          </Typography>
        </Box>

        {error && (
          <Alert severity="error" sx={{ mb: 3 }}>
            {error}
          </Alert>
        )}

        {/* Filters */}
        <Card sx={{ mb: 4 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Filters
            </Typography>
            <Grid container spacing={2} alignItems="center">
              <Grid item xs={12} md={3}>
                <TextField
                  select
                  fullWidth
                  label="Library"
                  value={selectedLibrary}
                  onChange={(e) => setSelectedLibrary(e.target.value)}
                >
                  <MenuItem value="">All Libraries</MenuItem>
                  {libraries.map((library) => (
                    <MenuItem key={library.id} value={library.id}>
                      {library.name}
                    </MenuItem>
                  ))}
                </TextField>
              </Grid>
              <Grid item xs={12} md={3}>
                <DatePicker
                  label="Start Date"
                  value={startDate}
                  onChange={(newValue) => setStartDate(newValue)}
                  slotProps={{ textField: { fullWidth: true } }}
                />
              </Grid>
              <Grid item xs={12} md={3}>
                <DatePicker
                  label="End Date"
                  value={endDate}
                  onChange={(newValue) => setEndDate(newValue)}
                  slotProps={{ textField: { fullWidth: true } }}
                />
              </Grid>
              <Grid item xs={12} md={3}>
                <Button
                  variant="contained"
                  fullWidth
                  onClick={handleApplyFilters}
                  startIcon={<DateRange />}
                >
                  Apply Filters
                </Button>
              </Grid>
            </Grid>
          </CardContent>
        </Card>

        {/* Overview Cards */}
        <Box sx={{ mb: 4 }}>
          <Typography variant="h6" gutterBottom>
            System Overview
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} sm={6} md={3}>
              <Card>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                    <People color="primary" sx={{ mr: 1 }} />
                    <Typography variant="h6">Users</Typography>
                  </Box>
                  <Typography variant="h4">{dashboardData?.users?.total || 0}</Typography>
                  <Typography variant="body2" color="text.secondary">
                    {dashboardData?.users?.active || 0} active users
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Card>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                    <EventSeat color="secondary" sx={{ mr: 1 }} />
                    <Typography variant="h6">Seats</Typography>
                  </Box>
                  <Typography variant="h4">{dashboardData?.seats?.total || 0}</Typography>
                  <Typography variant="body2" color="text.secondary">
                    {dashboardData?.seats?.bookings || 0} total bookings
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Card>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                    <MenuBook color="success" sx={{ mr: 1 }} />
                    <Typography variant="h6">Books</Typography>
                  </Box>
                  <Typography variant="h4">{dashboardData?.books?.total || 0}</Typography>
                  <Typography variant="body2" color="text.secondary">
                    {dashboardData?.books?.reservations || 0} total reservations
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Card>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                    <Event color="warning" sx={{ mr: 1 }} />
                    <Typography variant="h6">Events</Typography>
                  </Box>
                  <Typography variant="h4">{dashboardData?.events?.total || 0}</Typography>
                  <Typography variant="body2" color="text.secondary">
                    {dashboardData?.events?.registrations || 0} total registrations
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Card>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                    <CreditCard color="info" sx={{ mr: 1 }} />
                    <Typography variant="h6">Subscriptions</Typography>
                  </Box>
                  <Typography variant="h4">{dashboardData?.subscriptions?.total || 0}</Typography>
                  <Typography variant="body2" color="text.secondary">
                    {dashboardData?.subscriptions?.active || 0} active subscriptions
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Card>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                    <LocalLibrary color="error" sx={{ mr: 1 }} />
                    <Typography variant="h6">Revenue</Typography>
                  </Box>
                  <Typography variant="h4">{formatCurrency(dashboardData?.subscriptions?.revenue || 0)}</Typography>
                  <Typography variant="body2" color="text.secondary">
                    From subscriptions
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        </Box>

        {/* Tabs for different analytics sections */}
        <Paper sx={{ mb: 4 }}>
          <Tabs
            value={tabValue}
            onChange={handleTabChange}
            aria-label="analytics tabs"
            variant="scrollable"
            scrollButtons="auto"
          >
            <Tab icon={<TrendingUp />} label="Trends" iconPosition="start" />
            <Tab icon={<People />} label="Users" iconPosition="start" />
            <Tab icon={<EventSeat />} label="Seats" iconPosition="start" />
            <Tab icon={<MenuBook />} label="Books" iconPosition="start" />
            <Tab icon={<Event />} label="Events" iconPosition="start" />
            <Tab icon={<CreditCard />} label="Subscriptions" iconPosition="start" />
          </Tabs>

          {/* Trends Tab */}
          <TabPanel value={tabValue} index={0}>
            <Grid container spacing={3}>
              <Grid item xs={12}>
                <Typography variant="h6" gutterBottom>
                  User Registrations
                </Typography>
                <Card>
                  <CardContent>
                    <Box sx={{ height: 300 }}>
                      <ResponsiveContainer width="100%" height="100%">
                        <LineChart
                          data={userData?.user_registrations || []}
                          margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
                        >
                          <CartesianGrid strokeDasharray="3 3" />
                          <XAxis dataKey="date" />
                          <YAxis />
                          <Tooltip />
                          <Legend />
                          <Line type="monotone" dataKey="count" name="New Users" stroke="#8884d8" activeDot={{ r: 8 }} />
                        </LineChart>
                      </ResponsiveContainer>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="h6" gutterBottom>
                  Seat Bookings
                </Typography>
                <Card>
                  <CardContent>
                    <Box sx={{ height: 300 }}>
                      <ResponsiveContainer width="100%" height="100%">
                        <AreaChart
                          data={seatData?.bookings_over_time || []}
                          margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
                        >
                          <CartesianGrid strokeDasharray="3 3" />
                          <XAxis dataKey="date" />
                          <YAxis />
                          <Tooltip />
                          <Legend />
                          <Area type="monotone" dataKey="count" name="Bookings" stroke="#82ca9d" fill="#82ca9d" />
                        </AreaChart>
                      </ResponsiveContainer>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="h6" gutterBottom>
                  Book Reservations
                </Typography>
                <Card>
                  <CardContent>
                    <Box sx={{ height: 300 }}>
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart
                          data={bookData?.reservations_over_time || []}
                          margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
                        >
                          <CartesianGrid strokeDasharray="3 3" />
                          <XAxis dataKey="date" />
                          <YAxis />
                          <Tooltip />
                          <Legend />
                          <Bar dataKey="count" name="Reservations" fill="#8884d8" />
                        </BarChart>
                      </ResponsiveContainer>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="h6" gutterBottom>
                  Event Registrations
                </Typography>
                <Card>
                  <CardContent>
                    <Box sx={{ height: 300 }}>
                      <ResponsiveContainer width="100%" height="100%">
                        <LineChart
                          data={eventData?.registrations_over_time || []}
                          margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
                        >
                          <CartesianGrid strokeDasharray="3 3" />
                          <XAxis dataKey="date" />
                          <YAxis />
                          <Tooltip />
                          <Legend />
                          <Line type="monotone" dataKey="count" name="Registrations" stroke="#ff7300" />
                        </LineChart>
                      </ResponsiveContainer>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="h6" gutterBottom>
                  Subscription Revenue
                </Typography>
                <Card>
                  <CardContent>
                    <Box sx={{ height: 300 }}>
                      <ResponsiveContainer width="100%" height="100%">
                        <AreaChart
                          data={subscriptionData?.revenue_over_time || []}
                          margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
                        >
                          <CartesianGrid strokeDasharray="3 3" />
                          <XAxis dataKey="date" />
                          <YAxis />
                          <Tooltip formatter={(value) => formatCurrency(value as number)} />
                          <Legend />
                          <Area type="monotone" dataKey="revenue" name="Revenue" stroke="#8884d8" fill="#8884d8" />
                        </AreaChart>
                      </ResponsiveContainer>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          </TabPanel>

          {/* Users Tab */}
          <TabPanel value={tabValue} index={1}>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Typography variant="h6" gutterBottom>
                  User Roles Distribution
                </Typography>
                <Card>
                  <CardContent>
                    <Box sx={{ height: 300 }}>
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={userData?.users_by_role || []}
                            cx="50%"
                            cy="50%"
                            labelLine={false}
                            outerRadius={100}
                            fill="#8884d8"
                            dataKey="count"
                            nameKey="role"
                            label={({ role, percent }) => `${role} ${(percent * 100).toFixed(0)}%`}
                          >
                            {(userData?.users_by_role || []).map((entry: any, index: number) => (
                              <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                            ))}
                          </Pie>
                          <Tooltip />
                          <Legend />
                        </PieChart>
                      </ResponsiveContainer>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="h6" gutterBottom>
                  New User Registrations
                </Typography>
                <Card>
                  <CardContent>
                    <Box sx={{ height: 300 }}>
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart
                          data={userData?.user_registrations || []}
                          margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
                        >
                          <CartesianGrid strokeDasharray="3 3" />
                          <XAxis dataKey="date" />
                          <YAxis />
                          <Tooltip />
                          <Legend />
                          <Bar dataKey="count" name="New Users" fill="#8884d8" />
                        </BarChart>
                      </ResponsiveContainer>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12}>
                <Typography variant="h6" gutterBottom>
                  User Statistics
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} sm={6} md={3}>
                    <Card>
                      <CardContent>
                        <Typography variant="h6">Total Users</Typography>
                        <Typography variant="h4">{userData?.total_users || 0}</Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                  <Grid item xs={12} sm={6} md={3}>
                    <Card>
                      <CardContent>
                        <Typography variant="h6">Active Users</Typography>
                        <Typography variant="h4">{userData?.active_users || 0}</Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                  <Grid item xs={12} sm={6} md={3}>
                    <Card>
                      <CardContent>
                        <Typography variant="h6">Approval Rate</Typography>
                        <Typography variant="h4">{(userData?.approval_rate || 0).toFixed(1)}%</Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                </Grid>
              </Grid>
            </Grid>
          </TabPanel>

          {/* Seats Tab */}
          <TabPanel value={tabValue} index={2}>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Typography variant="h6" gutterBottom>
                  Seat Usage by Type
                </Typography>
                <Card>
                  <CardContent>
                    <Box sx={{ height: 300 }}>
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={seatData?.seat_types || []}
                            cx="50%"
                            cy="50%"
                            labelLine={false}
                            outerRadius={100}
                            fill="#8884d8"
                            dataKey="count"
                            nameKey="seat_type"
                            label={({ seat_type, percent }) => `${seat_type} ${(percent * 100).toFixed(0)}%`}
                          >
                            {(seatData?.seat_types || []).map((entry: any, index: number) => (
                              <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                            ))}
                          </Pie>
                          <Tooltip />
                          <Legend />
                        </PieChart>
                      </ResponsiveContainer>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="h6" gutterBottom>
                  Booking Status Distribution
                </Typography>
                <Card>
                  <CardContent>
                    <Box sx={{ height: 300 }}>
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={seatData?.bookings_by_status || []}
                            cx="50%"
                            cy="50%"
                            labelLine={false}
                            outerRadius={100}
                            fill="#8884d8"
                            dataKey="count"
                            nameKey="status"
                            label={({ status, percent }) => `${status} ${(percent * 100).toFixed(0)}%`}
                          >
                            {(seatData?.bookings_by_status || []).map((entry: any, index: number) => (
                              <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                            ))}
                          </Pie>
                          <Tooltip />
                          <Legend />
                        </PieChart>
                      </ResponsiveContainer>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12}>
                <Typography variant="h6" gutterBottom>
                  Most Booked Seats
                </Typography>
                <Card>
                  <CardContent>
                    <Box sx={{ height: 300 }}>
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart
                          data={seatData?.most_booked_seats || []}
                          margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
                          layout="vertical"
                        >
                          <CartesianGrid strokeDasharray="3 3" />
                          <XAxis type="number" />
                          <YAxis type="category" dataKey="seat_number" />
                          <Tooltip />
                          <Legend />
                          <Bar dataKey="booking_count" name="Bookings" fill="#82ca9d" />
                        </BarChart>
                      </ResponsiveContainer>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          </TabPanel>

          {/* Books Tab */}
          <TabPanel value={tabValue} index={3}>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Typography variant="h6" gutterBottom>
                  Book Types Distribution
                </Typography>
                <Card>
                  <CardContent>
                    <Box sx={{ height: 300 }}>
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={bookData?.book_types || []}
                            cx="50%"
                            cy="50%"
                            labelLine={false}
                            outerRadius={100}
                            fill="#8884d8"
                            dataKey="count"
                            nameKey="book_type"
                            label={({ book_type, percent }) => `${book_type} ${(percent * 100).toFixed(0)}%`}
                          >
                            {(bookData?.book_types || []).map((entry: any, index: number) => (
                              <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                            ))}
                          </Pie>
                          <Tooltip />
                          <Legend />
                        </PieChart>
                      </ResponsiveContainer>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="h6" gutterBottom>
                  Reservation Status Distribution
                </Typography>
                <Card>
                  <CardContent>
                    <Box sx={{ height: 300 }}>
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={bookData?.reservations_by_status || []}
                            cx="50%"
                            cy="50%"
                            labelLine={false}
                            outerRadius={100}
                            fill="#8884d8"
                            dataKey="count"
                            nameKey="status"
                            label={({ status, percent }) => `${status} ${(percent * 100).toFixed(0)}%`}
                          >
                            {(bookData?.reservations_by_status || []).map((entry: any, index: number) => (
                              <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                            ))}
                          </Pie>
                          <Tooltip />
                          <Legend />
                        </PieChart>
                      </ResponsiveContainer>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12}>
                <Typography variant="h6" gutterBottom>
                  Most Reserved Books
                </Typography>
                <Card>
                  <CardContent>
                    <Box sx={{ height: 300 }}>
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart
                          data={bookData?.most_reserved_books || []}
                          margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
                          layout="vertical"
                        >
                          <CartesianGrid strokeDasharray="3 3" />
                          <XAxis type="number" />
                          <YAxis type="category" dataKey="title" width={250} />
                          <Tooltip />
                          <Legend />
                          <Bar dataKey="reservation_count" name="Reservations" fill="#8884d8" />
                        </BarChart>
                      </ResponsiveContainer>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          </TabPanel>

          {/* Events Tab */}
          <TabPanel value={tabValue} index={4}>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Typography variant="h6" gutterBottom>
                  Event Types Distribution
                </Typography>
                <Card>
                  <CardContent>
                    <Box sx={{ height: 300 }}>
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={eventData?.event_types || []}
                            cx="50%"
                            cy="50%"
                            labelLine={false}
                            outerRadius={100}
                            fill="#8884d8"
                            dataKey="count"
                            nameKey="event_type"
                            label={({ event_type, percent }) => `${event_type} ${(percent * 100).toFixed(0)}%`}
                          >
                            {(eventData?.event_types || []).map((entry: any, index: number) => (
                              <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                            ))}
                          </Pie>
                          <Tooltip />
                          <Legend />
                        </PieChart>
                      </ResponsiveContainer>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="h6" gutterBottom>
                  Registration Status Distribution
                </Typography>
                <Card>
                  <CardContent>
                    <Box sx={{ height: 300 }}>
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={eventData?.registrations_by_status || []}
                            cx="50%"
                            cy="50%"
                            labelLine={false}
                            outerRadius={100}
                            fill="#8884d8"
                            dataKey="count"
                            nameKey="status"
                            label={({ status, percent }) => `${status} ${(percent * 100).toFixed(0)}%`}
                          >
                            {(eventData?.registrations_by_status || []).map((entry: any, index: number) => (
                              <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                            ))}
                          </Pie>
                          <Tooltip />
                          <Legend />
                        </PieChart>
                      </ResponsiveContainer>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12}>
                <Typography variant="h6" gutterBottom>
                  Most Popular Events
                </Typography>
                <Card>
                  <CardContent>
                    <Box sx={{ height: 300 }}>
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart
                          data={eventData?.most_popular_events || []}
                          margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
                          layout="vertical"
                        >
                          <CartesianGrid strokeDasharray="3 3" />
                          <XAxis type="number" />
                          <YAxis type="category" dataKey="title" width={250} />
                          <Tooltip />
                          <Legend />
                          <Bar dataKey="registration_count" name="Registrations" fill="#ff7300" />
                        </BarChart>
                      </ResponsiveContainer>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          </TabPanel>

          {/* Subscriptions Tab */}
          <TabPanel value={tabValue} index={5}>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Typography variant="h6" gutterBottom>
                  Subscriptions by Plan
                </Typography>
                <Card>
                  <CardContent>
                    <Box sx={{ height: 300 }}>
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={subscriptionData?.subscriptions_by_plan || []}
                            cx="50%"
                            cy="50%"
                            labelLine={false}
                            outerRadius={100}
                            fill="#8884d8"
                            dataKey="count"
                            nameKey="plan__name"
                            label={({ plan__name, percent }) => `${plan__name} ${(percent * 100).toFixed(0)}%`}
                          >
                            {(subscriptionData?.subscriptions_by_plan || []).map((entry: any, index: number) => (
                              <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                            ))}
                          </Pie>
                          <Tooltip />
                          <Legend />
                        </PieChart>
                      </ResponsiveContainer>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="h6" gutterBottom>
                  Subscriptions by Status
                </Typography>
                <Card>
                  <CardContent>
                    <Box sx={{ height: 300 }}>
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={subscriptionData?.subscriptions_by_status || []}
                            cx="50%"
                            cy="50%"
                            labelLine={false}
                            outerRadius={100}
                            fill="#8884d8"
                            dataKey="count"
                            nameKey="status"
                            label={({ status, percent }) => `${status} ${(percent * 100).toFixed(0)}%`}
                          >
                            {(subscriptionData?.subscriptions_by_status || []).map((entry: any, index: number) => (
                              <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                            ))}
                          </Pie>
                          <Tooltip />
                          <Legend />
                        </PieChart>
                      </ResponsiveContainer>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12}>
                <Typography variant="h6" gutterBottom>
                  Subscription Revenue Over Time
                </Typography>
                <Card>
                  <CardContent>
                    <Box sx={{ height: 300 }}>
                      <ResponsiveContainer width="100%" height="100%">
                        <AreaChart
                          data={subscriptionData?.revenue_over_time || []}
                          margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
                        >
                          <CartesianGrid strokeDasharray="3 3" />
                          <XAxis dataKey="date" />
                          <YAxis />
                          <Tooltip formatter={(value) => formatCurrency(value as number)} />
                          <Legend />
                          <Area type="monotone" dataKey="revenue" name="Revenue" stroke="#8884d8" fill="#8884d8" />
                        </AreaChart>
                      </ResponsiveContainer>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12}>
                <Typography variant="h6" gutterBottom>
                  Subscription Statistics
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} sm={6} md={3}>
                    <Card>
                      <CardContent>
                        <Typography variant="h6">Total Subscriptions</Typography>
                        <Typography variant="h4">{subscriptionData?.total_subscriptions || 0}</Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                  <Grid item xs={12} sm={6} md={3}>
                    <Card>
                      <CardContent>
                        <Typography variant="h6">Active Subscriptions</Typography>
                        <Typography variant="h4">{subscriptionData?.active_subscriptions || 0}</Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                  <Grid item xs={12} sm={6} md={3}>
                    <Card>
                      <CardContent>
                        <Typography variant="h6">Total Revenue</Typography>
                        <Typography variant="h4">{formatCurrency(subscriptionData?.total_revenue || 0)}</Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                  <Grid item xs={12} sm={6} md={3}>
                    <Card>
                      <CardContent>
                        <Typography variant="h6">Auto-Renewal Rate</Typography>
                        <Typography variant="h4">{(subscriptionData?.auto_renew_rate || 0).toFixed(1)}%</Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                </Grid>
              </Grid>
            </Grid>
          </TabPanel>
        </Paper>

        {/* Export Options */}
        <Box sx={{ display: 'flex', justifyContent: 'flex-end', gap: 2 }}>
          <Button
            variant="outlined"
            startIcon={<BarChartIcon />}
            onClick={() => {
              // This would trigger a report export in a real app
              alert('Export functionality would be implemented here')
            }}
          >
            Export Report
          </Button>
          <Button
            variant="outlined"
            startIcon={<PieChartIcon />}
            onClick={() => {
              // This would trigger a data export in a real app
              alert('Export functionality would be implemented here')
            }}
          >
            Export Data
          </Button>
        </Box>
      </motion.div>
    </Box>
  )
}