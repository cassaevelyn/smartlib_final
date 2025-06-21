import { useState, useEffect } from 'react'
import {
  Box,
  Typography,
  Grid,
  Card,
  CardContent,
  Button,
  TextField,
  Avatar,
  Divider,
  Chip,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Alert,
  CircularProgress,
  Tab,
  Tabs,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  MenuItem,
} from '@mui/material'
import {
  Person,
  Email,
  Phone,
  Home,
  LocationCity,
  School,
  Badge,
  Cake,
  Edit,
  Save,
  Cancel,
  EmojiEvents,
  MenuBook,
  EventSeat,
  Event,
  History,
  CalendarToday,
} from '@mui/icons-material'
import { motion } from 'framer-motion'
import { useForm, Controller } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { useAuthStore } from '../../stores/authStore'
import { authService } from '../../services/authService'
import { User, UserProfile } from '../../types'
import { LoadingSpinner } from '../../components/ui/loading-spinner'
import { useToast } from '../../hooks/use-toast'
import { formatDate } from '../../lib/utils'

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
      id={`profile-tabpanel-${index}`}
      aria-labelledby={`profile-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </div>
  )
}

// Schema for profile update
const profileSchema = z.object({
  first_name: z.string().min(1, 'First name is required'),
  last_name: z.string().min(1, 'Last name is required'),
  phone_number: z.string().optional(),
  date_of_birth: z.string().optional(),
  gender: z.enum(['M', 'F', 'O']).optional(),
  address: z.string().optional(),
  city: z.string().optional(),
  bio: z.string().optional(),
})

type ProfileForm = z.infer<typeof profileSchema>

export function ProfilePage() {
  const { user, updateUser } = useAuthStore()
  const { toast } = useToast()
  
  const [tabValue, setTabValue] = useState(0)
  const [isEditing, setIsEditing] = useState(false)
  const [isLoading, setIsLoading] = useState(true)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [userProfile, setUserProfile] = useState<UserProfile | null>(null)
  const [activities, setActivities] = useState<any[]>([])

  const {
    control,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<ProfileForm>({
    resolver: zodResolver(profileSchema),
    defaultValues: {
      first_name: user?.first_name || '',
      last_name: user?.last_name || '',
      phone_number: user?.phone_number || '',
      date_of_birth: user?.date_of_birth || '',
      gender: user?.gender as any || 'M',
      address: user?.address || '',
      city: user?.city || '',
      bio: user?.bio || '',
    },
  })

  useEffect(() => {
    fetchUserProfile()
    fetchUserActivities()
  }, [])

  useEffect(() => {
    if (user) {
      reset({
        first_name: user.first_name || '',
        last_name: user.last_name || '',
        phone_number: user.phone_number || '',
        date_of_birth: user.date_of_birth || '',
        gender: user.gender as any || 'M',
        address: user.address || '',
        city: user.city || '',
        bio: user.bio || '',
      })
    }
  }, [user, reset])

  const fetchUserProfile = async () => {
    try {
      setIsLoading(true)
      setError(null)
      
      const profile = await authService.getUserProfile()
      setUserProfile(profile)
    } catch (error: any) {
      setError(error.message || 'Failed to fetch user profile')
    } finally {
      setIsLoading(false)
    }
  }

  const fetchUserActivities = async () => {
    try {
      const activitiesData = await authService.getUserActivities()
      setActivities(activitiesData)
    } catch (error: any) {
      console.error('Failed to fetch user activities:', error)
    }
  }

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue)
  }

  const onSubmit = async (data: ProfileForm) => {
    try {
      setIsSubmitting(true)
      setError(null)
      
      // Update user profile
      const updatedUser = await authService.updateProfile(data)
      
      // Update user in store
      updateUser(updatedUser)
      
      toast({
        title: "Profile Updated",
        description: "Your profile has been updated successfully.",
        variant: "default",
      })
      
      setIsEditing(false)
    } catch (error: any) {
      setError(error.message || 'Failed to update profile')
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleCancelEdit = () => {
    reset({
      first_name: user?.first_name || '',
      last_name: user?.last_name || '',
      phone_number: user?.phone_number || '',
      date_of_birth: user?.date_of_birth || '',
      gender: user?.gender as any || 'M',
      address: user?.address || '',
      city: user?.city || '',
      bio: user?.bio || '',
    })
    setIsEditing(false)
  }

  const getActivityIcon = (type: string) => {
    switch (type) {
      case 'SEAT_BOOKING':
        return <EventSeat color="primary" />
      case 'BOOK_RESERVATION':
      case 'BOOK_RETURN':
        return <MenuBook color="secondary" />
      case 'EVENT_REGISTRATION':
      case 'EVENT_ATTENDANCE':
        return <Event color="success" />
      default:
        return <History color="action" />
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
            My Profile
          </Typography>
          <Typography variant="body1" color="text.secondary">
            View and manage your personal information and account details.
          </Typography>
        </Box>

        {error && (
          <Alert severity="error" sx={{ mb: 3 }}>
            {error}
          </Alert>
        )}

        <Grid container spacing={3}>
          {/* Profile Summary Card */}
          <Grid item xs={12} md={4}>
            <Card sx={{ mb: 3 }}>
              <CardContent sx={{ textAlign: 'center' }}>
                <Avatar
                  src={user?.avatar}
                  sx={{ width: 120, height: 120, mx: 'auto', mb: 2 }}
                >
                  {user?.first_name?.[0]}{user?.last_name?.[0]}
                </Avatar>
                <Typography variant="h5" gutterBottom>
                  {user?.full_name}
                </Typography>
                <Typography variant="body1" color="text.secondary" gutterBottom>
                  {user?.email}
                </Typography>
                <Chip
                  label={user?.role?.replace('_', ' ')}
                  color={user?.role === 'SUPER_ADMIN' ? 'error' : user?.role === 'ADMIN' ? 'warning' : 'primary'}
                  sx={{ mt: 1 }}
                />
                <Box sx={{ mt: 2 }}>
                  <Typography variant="body2" color="text.secondary">
                    Student ID: {user?.student_id}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    CRN: {user?.crn}
                  </Typography>
                </Box>
                <Divider sx={{ my: 2 }} />
                <Grid container spacing={2}>
                  <Grid item xs={4}>
                    <Typography variant="h6">{userProfile?.loyalty_points}</Typography>
                    <Typography variant="body2" color="text.secondary">Points</Typography>
                  </Grid>
                  <Grid item xs={4}>
                    <Typography variant="h6">{userProfile?.books_read}</Typography>
                    <Typography variant="body2" color="text.secondary">Books</Typography>
                  </Grid>
                  <Grid item xs={4}>
                    <Typography variant="h6">{userProfile?.events_attended}</Typography>
                    <Typography variant="body2" color="text.secondary">Events</Typography>
                  </Grid>
                </Grid>
              </CardContent>
            </Card>

            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Academic Information
                </Typography>
                <List dense>
                  <ListItem>
                    <ListItemIcon>
                      <School />
                    </ListItemIcon>
                    <ListItemText
                      primary="Education Level"
                      secondary={userProfile?.education_level || 'Not specified'}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <CalendarToday />
                    </ListItemIcon>
                    <ListItemText
                      primary="Enrollment Year"
                      secondary={userProfile?.enrollment_year || 'Not specified'}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <School />
                    </ListItemIcon>
                    <ListItemText
                      primary="Expected Completion"
                      secondary={userProfile?.expected_completion_year || 'Not specified'}
                    />
                  </ListItem>
                </List>
                <Typography variant="subtitle1" sx={{ mt: 2, mb: 1 }}>
                  Study Subjects
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                  {userProfile?.study_subjects?.map((subject, index) => (
                    <Chip key={index} label={subject} size="small" />
                  ))}
                </Box>
              </CardContent>
            </Card>
          </Grid>

          {/* Main Content */}
          <Grid item xs={12} md={8}>
            <Card>
              <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
                <Tabs
                  value={tabValue}
                  onChange={handleTabChange}
                  aria-label="profile tabs"
                  variant="scrollable"
                  scrollButtons="auto"
                >
                  <Tab label="Personal Information" />
                  <Tab label="Activity History" />
                  <Tab label="Statistics" />
                </Tabs>
              </Box>

              {/* Personal Information Tab */}
              <TabPanel value={tabValue} index={0}>
                <Box sx={{ display: 'flex', justifyContent: 'flex-end', mb: 2 }}>
                  {isEditing ? (
                    <Box sx={{ display: 'flex', gap: 1 }}>
                      <Button
                        variant="outlined"
                        startIcon={<Cancel />}
                        onClick={handleCancelEdit}
                        disabled={isSubmitting}
                      >
                        Cancel
                      </Button>
                      <Button
                        variant="contained"
                        startIcon={isSubmitting ? <LoadingSpinner size="sm" /> : <Save />}
                        onClick={handleSubmit(onSubmit)}
                        disabled={isSubmitting}
                      >
                        Save Changes
                      </Button>
                    </Box>
                  ) : (
                    <Button
                      variant="outlined"
                      startIcon={<Edit />}
                      onClick={() => setIsEditing(true)}
                    >
                      Edit Profile
                    </Button>
                  )}
                </Box>

                {isEditing ? (
                  <Box component="form" noValidate>
                    <Grid container spacing={2}>
                      <Grid item xs={12} sm={6}>
                        <Controller
                          name="first_name"
                          control={control}
                          render={({ field }) => (
                            <TextField
                              {...field}
                              label="First Name"
                              fullWidth
                              error={!!errors.first_name}
                              helperText={errors.first_name?.message}
                            />
                          )}
                        />
                      </Grid>
                      <Grid item xs={12} sm={6}>
                        <Controller
                          name="last_name"
                          control={control}
                          render={({ field }) => (
                            <TextField
                              {...field}
                              label="Last Name"
                              fullWidth
                              error={!!errors.last_name}
                              helperText={errors.last_name?.message}
                            />
                          )}
                        />
                      </Grid>
                      <Grid item xs={12} sm={6}>
                        <Controller
                          name="phone_number"
                          control={control}
                          render={({ field }) => (
                            <TextField
                              {...field}
                              label="Phone Number"
                              fullWidth
                              error={!!errors.phone_number}
                              helperText={errors.phone_number?.message}
                            />
                          )}
                        />
                      </Grid>
                      <Grid item xs={12} sm={6}>
                        <Controller
                          name="date_of_birth"
                          control={control}
                          render={({ field }) => (
                            <TextField
                              {...field}
                              label="Date of Birth"
                              type="date"
                              fullWidth
                              InputLabelProps={{ shrink: true }}
                              error={!!errors.date_of_birth}
                              helperText={errors.date_of_birth?.message}
                            />
                          )}
                        />
                      </Grid>
                      <Grid item xs={12} sm={6}>
                        <Controller
                          name="gender"
                          control={control}
                          render={({ field }) => (
                            <TextField
                              {...field}
                              select
                              label="Gender"
                              fullWidth
                              error={!!errors.gender}
                              helperText={errors.gender?.message}
                            >
                              <MenuItem value="M">Male</MenuItem>
                              <MenuItem value="F">Female</MenuItem>
                              <MenuItem value="O">Other</MenuItem>
                            </TextField>
                          )}
                        />
                      </Grid>
                      <Grid item xs={12} sm={6}>
                        <Controller
                          name="city"
                          control={control}
                          render={({ field }) => (
                            <TextField
                              {...field}
                              label="City"
                              fullWidth
                              error={!!errors.city}
                              helperText={errors.city?.message}
                            />
                          )}
                        />
                      </Grid>
                      <Grid item xs={12}>
                        <Controller
                          name="address"
                          control={control}
                          render={({ field }) => (
                            <TextField
                              {...field}
                              label="Address"
                              fullWidth
                              multiline
                              rows={2}
                              error={!!errors.address}
                              helperText={errors.address?.message}
                            />
                          )}
                        />
                      </Grid>
                      <Grid item xs={12}>
                        <Controller
                          name="bio"
                          control={control}
                          render={({ field }) => (
                            <TextField
                              {...field}
                              label="Bio"
                              fullWidth
                              multiline
                              rows={3}
                              error={!!errors.bio}
                              helperText={errors.bio?.message}
                            />
                          )}
                        />
                      </Grid>
                    </Grid>
                  </Box>
                ) : (
                  <List>
                    <ListItem>
                      <ListItemIcon>
                        <Person />
                      </ListItemIcon>
                      <ListItemText
                        primary="Full Name"
                        secondary={user?.full_name}
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon>
                        <Email />
                      </ListItemIcon>
                      <ListItemText
                        primary="Email"
                        secondary={user?.email}
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon>
                        <Phone />
                      </ListItemIcon>
                      <ListItemText
                        primary="Phone Number"
                        secondary={user?.phone_number || 'Not specified'}
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon>
                        <Cake />
                      </ListItemIcon>
                      <ListItemText
                        primary="Date of Birth"
                        secondary={user?.date_of_birth ? formatDate(user.date_of_birth) : 'Not specified'}
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon>
                        <Person />
                      </ListItemIcon>
                      <ListItemText
                        primary="Gender"
                        secondary={
                          user?.gender === 'M' ? 'Male' :
                          user?.gender === 'F' ? 'Female' :
                          user?.gender === 'O' ? 'Other' :
                          'Not specified'
                        }
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon>
                        <LocationCity />
                      </ListItemIcon>
                      <ListItemText
                        primary="City"
                        secondary={user?.city || 'Not specified'}
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon>
                        <Home />
                      </ListItemIcon>
                      <ListItemText
                        primary="Address"
                        secondary={user?.address || 'Not specified'}
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon>
                        <Badge />
                      </ListItemIcon>
                      <ListItemText
                        primary="CRN"
                        secondary={user?.crn}
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon>
                        <School />
                      </ListItemIcon>
                      <ListItemText
                        primary="Student ID"
                        secondary={user?.student_id}
                      />
                    </ListItem>
                    {user?.bio && (
                      <ListItem>
                        <ListItemIcon>
                          <Person />
                        </ListItemIcon>
                        <ListItemText
                          primary="Bio"
                          secondary={user.bio}
                        />
                      </ListItem>
                    )}
                  </List>
                )}
              </TabPanel>

              {/* Activity History Tab */}
              <TabPanel value={tabValue} index={1}>
                <Typography variant="h6" gutterBottom>
                  Recent Activity
                </Typography>
                <List>
                  {activities.map((activity) => (
                    <ListItem key={activity.id} sx={{ mb: 1, bgcolor: 'background.paper', borderRadius: 1 }}>
                      <ListItemIcon>
                        {getActivityIcon(activity.type)}
                      </ListItemIcon>
                      <ListItemText
                        primary={activity.title}
                        secondary={
                          <>
                            <Typography variant="body2" component="span">
                              {activity.description}
                            </Typography>
                            <Typography variant="caption" component="div" color="text.secondary">
                              {formatDate(activity.timestamp)}
                            </Typography>
                          </>
                        }
                      />
                    </ListItem>
                  ))}
                </List>
              </TabPanel>

              {/* Statistics Tab */}
              <TabPanel value={tabValue} index={2}>
                <Typography variant="h6" gutterBottom>
                  Usage Statistics
                </Typography>
                <Grid container spacing={3}>
                  <Grid item xs={12} sm={6} md={4}>
                    <Card variant="outlined">
                      <CardContent>
                        <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                          <EventSeat color="primary" sx={{ mr: 1 }} />
                          <Typography variant="h6">Study Hours</Typography>
                        </Box>
                        <Typography variant="h4">{userProfile?.total_study_hours}</Typography>
                        <Typography variant="body2" color="text.secondary">
                          Total hours spent studying
                        </Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                  <Grid item xs={12} sm={6} md={4}>
                    <Card variant="outlined">
                      <CardContent>
                        <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                          <MenuBook color="secondary" sx={{ mr: 1 }} />
                          <Typography variant="h6">Books Read</Typography>
                        </Box>
                        <Typography variant="h4">{userProfile?.books_read}</Typography>
                        <Typography variant="body2" color="text.secondary">
                          Total books completed
                        </Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                  <Grid item xs={12} sm={6} md={4}>
                    <Card variant="outlined">
                      <CardContent>
                        <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                          <Event color="success" sx={{ mr: 1 }} />
                          <Typography variant="h6">Events</Typography>
                        </Box>
                        <Typography variant="h4">{userProfile?.events_attended}</Typography>
                        <Typography variant="body2" color="text.secondary">
                          Total events attended
                        </Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                  <Grid item xs={12}>
                    <Card variant="outlined">
                      <CardContent>
                        <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                          <EmojiEvents color="warning" sx={{ mr: 1 }} />
                          <Typography variant="h6">Loyalty Program</Typography>
                        </Box>
                        <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                          <Typography variant="h4" sx={{ mr: 2 }}>{userProfile?.loyalty_points}</Typography>
                          <Typography variant="body1">Points Earned</Typography>
                        </Box>
                        <Typography variant="body2" color="text.secondary">
                          Earn points by booking seats, borrowing books, and attending events.
                          Redeem points for extended borrowing periods, premium seats, and more.
                        </Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                </Grid>
              </TabPanel>
            </Card>
          </Grid>
        </Grid>
      </motion.div>
    </Box>
  )
}