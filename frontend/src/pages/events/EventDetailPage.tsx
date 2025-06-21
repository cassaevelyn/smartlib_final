import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  Box,
  Typography,
  Grid,
  Card,
  CardContent,
  CardMedia,
  Button,
  Chip,
  Divider,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Paper,
  Tabs,
  Tab,
  Rating,
  Avatar,
  TextField,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Alert,
  Breadcrumbs,
  Link as MuiLink,
} from '@mui/material'
import {
  Event,
  Person,
  LocationOn,
  AccessTime,
  CalendarToday,
  LocalLibrary,
  Category,
  Description,
  Star,
  NavigateNext,
  ArrowBack,
  Add,
  Public,
  AttachMoney,
  People,
  School,
  EmojiEvents,
  CreditCard,
} from '@mui/icons-material'
import { motion } from 'framer-motion'
import { useForm, Controller } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { eventService } from '../../services/eventService'
import { recommendationService } from '../../services/recommendationService'
import { EventDetail, EventRegistration, EventFeedback } from '../../types'
import { LoadingSpinner } from '../../components/ui/loading-spinner'
import { useToast } from '../../hooks/use-toast'
import { formatDate, formatTime } from '../../lib/utils'
import { EventCard } from '../../components/events/EventCard'
import { useAuthStore } from '../../stores/authStore'

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
      id={`event-tabpanel-${index}`}
      aria-labelledby={`event-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </div>
  )
}

// Schema for the registration form
const registrationSchema = z.object({
  dietary_requirements: z.string().optional(),
  special_needs: z.string().optional(),
  emergency_contact: z.string().optional(),
  how_did_you_hear: z.string().optional(),
  expectations: z.string().optional(),
})

type RegistrationForm = z.infer<typeof registrationSchema>

// Schema for the feedback form
const feedbackSchema = z.object({
  overall_rating: z.number().min(1, 'Rating is required'),
  content_rating: z.number().optional(),
  speaker_rating: z.number().optional(),
  organization_rating: z.number().optional(),
  venue_rating: z.number().optional(),
  what_you_liked: z.string().min(10, 'Please provide at least 10 characters'),
  what_could_improve: z.string().optional(),
  additional_comments: z.string().optional(),
  would_recommend: z.boolean().default(true),
  would_attend_similar: z.boolean().default(true),
  future_topics: z.string().optional(),
  preferred_format: z.string().optional(),
  preferred_duration: z.string().optional(),
})

type FeedbackForm = z.infer<typeof feedbackSchema>

export function EventDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { toast } = useToast()
  const { user } = useAuthStore()
  
  const [event, setEvent] = useState<EventDetail | null>(null)
  const [similarEvents, setSimilarEvents] = useState<EventDetail['similar_events']>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [tabValue, setTabValue] = useState(0)
  
  // Dialog states
  const [registerDialogOpen, setRegisterDialogOpen] = useState(false)
  const [feedbackDialogOpen, setFeedbackDialogOpen] = useState(false)
  const [subscriptionDialogOpen, setSubscriptionDialogOpen] = useState(false)
  const [isSubmitting, setIsSubmitting] = useState(false)

  // Registration form
  const {
    control: registerControl,
    handleSubmit: handleRegisterSubmit,
    formState: { errors: registerErrors },
    reset: resetRegisterForm,
  } = useForm<RegistrationForm>({
    resolver: zodResolver(registrationSchema),
    defaultValues: {
      dietary_requirements: '',
      special_needs: '',
      emergency_contact: '',
      how_did_you_hear: '',
      expectations: '',
    },
  })

  // Feedback form
  const {
    control: feedbackControl,
    handleSubmit: handleFeedbackSubmit,
    formState: { errors: feedbackErrors },
    reset: resetFeedbackForm,
  } = useForm<FeedbackForm>({
    resolver: zodResolver(feedbackSchema),
    defaultValues: {
      overall_rating: 0,
      content_rating: 0,
      speaker_rating: 0,
      organization_rating: 0,
      venue_rating: 0,
      what_you_liked: '',
      what_could_improve: '',
      additional_comments: '',
      would_recommend: true,
      would_attend_similar: true,
      future_topics: '',
      preferred_format: '',
      preferred_duration: '',
    },
  })

  useEffect(() => {
    if (!id) return
    fetchEventDetails(id)
    fetchSimilarEvents(id)
  }, [id])

  const fetchEventDetails = async (eventId: string) => {
    try {
      setIsLoading(true)
      setError(null)
      
      const eventData = await eventService.getEvent(eventId)
      setEvent(eventData)
    } catch (error: any) {
      setError(error.message || 'Failed to fetch event details')
    } finally {
      setIsLoading(false)
    }
  }

  const fetchSimilarEvents = async (eventId: string) => {
    try {
      // Try to get recommendations from the recommendation service
      const recommendations = await recommendationService.getEventsRecommendations()
      
      // Use category-based recommendations as similar events
      if (recommendations.category_based && recommendations.category_based.length > 0) {
        setSimilarEvents(recommendations.category_based)
      }
    } catch (error) {
      // If recommendation service fails, we'll use the similar_events from the event details
      console.error('Failed to fetch recommendations:', error)
    }
  }

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue)
  }

  const handleRegisterClick = () => {
    // Check if premium event and user doesn't have subscription
    if (event?.required_subscription && !user?.has_active_subscription) {
      setSubscriptionDialogOpen(true)
    } else {
      setRegisterDialogOpen(true)
    }
  }

  const onSubmitRegistration = async (data: RegistrationForm) => {
    if (!id) return
    
    try {
      setIsSubmitting(true)
      
      const registrationData = {
        ...data,
        event: id,
      }
      
      await eventService.createRegistration(registrationData)
      
      toast({
        title: "Registration Successful",
        description: "You have successfully registered for this event.",
        variant: "default",
      })
      
      setRegisterDialogOpen(false)
      resetRegisterForm()
      
      // Refresh event details to update registration status
      fetchEventDetails(id)
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || 'Failed to register for event',
        variant: "destructive",
      })
    } finally {
      setIsSubmitting(false)
    }
  }

  const onSubmitFeedback = async (data: FeedbackForm) => {
    if (!id) return
    
    try {
      setIsSubmitting(true)
      
      await eventService.submitEventFeedback(id, data)
      
      toast({
        title: "Feedback Submitted",
        description: "Your feedback has been submitted successfully.",
        variant: "default",
      })
      
      setFeedbackDialogOpen(false)
      resetFeedbackForm()
      
      // Refresh event details
      fetchEventDetails(id)
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || 'Failed to submit feedback',
        variant: "destructive",
      })
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleJoinWaitlist = async () => {
    if (!id) return
    
    try {
      await eventService.joinWaitlist(id)
      
      toast({
        title: "Joined Waitlist",
        description: "You have been added to the waitlist for this event.",
        variant: "default",
      })
      
      // Refresh event details
      fetchEventDetails(id)
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || 'Failed to join waitlist',
        variant: "destructive",
      })
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
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
        <Button
          variant="outlined"
          startIcon={<ArrowBack />}
          onClick={() => navigate('/events')}
        >
          Back to Events
        </Button>
      </Box>
    )
  }

  if (!event) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="warning" sx={{ mb: 3 }}>
          Event not found
        </Alert>
        <Button
          variant="outlined"
          startIcon={<ArrowBack />}
          onClick={() => navigate('/events')}
        >
          Back to Events
        </Button>
      </Box>
    )
  }

  // Check if user can access premium event
  const canAccessPremium = user?.has_active_subscription || !event.required_subscription

  return (
    <Box sx={{ p: 3 }}>
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
      >
        {/* Breadcrumbs */}
        <Breadcrumbs separator={<NavigateNext fontSize="small" />} sx={{ mb: 2 }}>
          <MuiLink
            component="button"
            variant="body2"
            onClick={() => navigate('/events')}
            underline="hover"
            color="inherit"
          >
            Events
          </MuiLink>
          <Typography color="text.primary">{event.title}</Typography>
        </Breadcrumbs>

        {/* Event Header */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={4}>
            <Card>
              <CardMedia
                component="img"
                image={event.banner_image || 'https://images.pexels.com/photos/7103/writing-notes-idea-conference.jpg'}
                alt={event.title}
                sx={{ height: 'auto', maxHeight: 300, objectFit: 'cover' }}
              />
            </Card>
          </Grid>
          <Grid item xs={12} md={8}>
            <Box>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <Typography variant="h4" component="h1" gutterBottom>
                  {event.title}
                </Typography>
                <Chip
                  label={event.event_type_display}
                  size="small"
                  color="primary"
                  sx={{ ml: 2 }}
                />
                {event.required_subscription && (
                  <Chip
                    label="Premium"
                    size="small"
                    color="warning"
                    sx={{ ml: 1 }}
                  />
                )}
              </Box>
              
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <Rating value={event.average_rating} precision={0.1} readOnly />
                <Typography variant="body2" color="text.secondary" sx={{ ml: 1 }}>
                  {event.average_rating.toFixed(1)} ({event.total_feedback} reviews)
                </Typography>
              </Box>
              
              <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mb: 3 }}>
                <Chip
                  icon={<Event />}
                  label={event.status_display}
                  variant="outlined"
                  color={event.is_registration_open ? 'success' : 'default'}
                />
                <Chip
                  icon={<Category />}
                  label={event.category_name}
                  variant="outlined"
                />
                <Chip
                  icon={event.is_online ? <Public /> : <LocalLibrary />}
                  label={event.is_online ? 'Online Event' : 'In-Person'}
                  variant="outlined"
                />
                <Chip
                  icon={<AttachMoney />}
                  label={event.registration_fee > 0 ? `${event.registration_fee} PKR` : 'Free'}
                  variant="outlined"
                  color={event.registration_fee > 0 ? 'default' : 'success'}
                />
                {event.has_certificate && (
                  <Chip
                    icon={<EmojiEvents />}
                    label="Certificate"
                    color="primary"
                  />
                )}
              </Box>
              
              <Grid container spacing={2} sx={{ mb: 3 }}>
                <Grid item xs={12} md={6}>
                  <List dense>
                    <ListItem>
                      <ListItemIcon>
                        <CalendarToday />
                      </ListItemIcon>
                      <ListItemText
                        primary="Date"
                        secondary={`${formatDate(event.start_date)}${event.end_date !== event.start_date ? ` to ${formatDate(event.end_date)}` : ''}`}
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon>
                        <AccessTime />
                      </ListItemIcon>
                      <ListItemText
                        primary="Time"
                        secondary={`${event.start_time} - ${event.end_time} (${event.duration_hours} hours)`}
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon>
                        <LocationOn />
                      </ListItemIcon>
                      <ListItemText
                        primary="Location"
                        secondary={event.is_online ? 'Online Event' : `${event.library_name}${event.venue_details ? `, ${event.venue_details}` : ''}`}
                      />
                    </ListItem>
                  </List>
                </Grid>
                <Grid item xs={12} md={6}>
                  <List dense>
                    <ListItem>
                      <ListItemIcon>
                        <Person />
                      </ListItemIcon>
                      <ListItemText
                        primary="Organizer"
                        secondary={event.organizer_name}
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon>
                        <People />
                      </ListItemIcon>
                      <ListItemText
                        primary="Registration"
                        secondary={`${event.total_registrations} / ${event.max_participants} participants`}
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon>
                        <CalendarToday />
                      </ListItemIcon>
                      <ListItemText
                        primary="Registration Deadline"
                        secondary={formatDate(event.registration_deadline)}
                      />
                    </ListItem>
                  </List>
                </Grid>
              </Grid>
              
              <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
                <Button
                  variant="contained"
                  disabled={!event.user_can_register || event.user_registration_status === 'CONFIRMED'}
                  onClick={handleRegisterClick}
                >
                  {event.user_registration_status === 'CONFIRMED' 
                    ? 'Already Registered' 
                    : event.is_full 
                    ? 'Event Full' 
                    : 'Register Now'}
                </Button>
                
                {event.is_full && !event.user_registration_status && (
                  <Button
                    variant="outlined"
                    onClick={handleJoinWaitlist}
                  >
                    Join Waitlist
                  </Button>
                )}
                
                {event.user_registration_status === 'CONFIRMED' && (
                  <Button
                    variant="outlined"
                    onClick={() => navigate('/my-events')}
                  >
                    View My Registration
                  </Button>
                )}
                
                {event.status === 'COMPLETED' && (
                  <Button
                    variant="outlined"
                    onClick={() => setFeedbackDialogOpen(true)}
                  >
                    Submit Feedback
                  </Button>
                )}
              </Box>
              
              {!event.is_registration_open && event.status !== 'COMPLETED' && (
                <Alert severity="info" sx={{ mt: 2 }}>
                  Registration is currently {event.status_display.toLowerCase()}.
                </Alert>
              )}
              
              {event.is_full && (
                <Alert severity="warning" sx={{ mt: 2 }}>
                  This event is full. You can join the waitlist to be notified if spots become available.
                </Alert>
              )}
              
              {event.required_subscription && !user?.has_active_subscription && (
                <Alert severity="warning" sx={{ mt: 2 }}>
                  This is a premium event. Subscribe to a plan to access premium events.
                  <Button 
                    color="warning" 
                    size="small" 
                    sx={{ ml: 2 }}
                    onClick={() => navigate('/subscriptions')}
                  >
                    View Plans
                  </Button>
                </Alert>
              )}
            </Box>
          </Grid>
        </Grid>

        {/* Tabs for different sections */}
        <Box sx={{ width: '100%', mb: 4 }}>
          <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
            <Tabs
              value={tabValue}
              onChange={handleTabChange}
              aria-label="event details tabs"
              variant="scrollable"
              scrollButtons="auto"
            >
              <Tab label="Description" />
              <Tab label="Speakers" />
              <Tab label="Agenda" />
              <Tab label="Similar Events" />
            </Tabs>
          </Box>

          {/* Description Tab */}
          <TabPanel value={tabValue} index={0}>
            {!canAccessPremium ? (
              <Box sx={{ textAlign: 'center', py: 4 }}>
                <Typography variant="h6" gutterBottom>
                  Premium Content
                </Typography>
                <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
                  Subscribe to a plan to access premium events
                </Typography>
                <Button
                  variant="contained"
                  color="warning"
                  startIcon={<CreditCard />}
                  onClick={() => navigate('/subscriptions')}
                >
                  View Subscription Plans
                </Button>
              </Box>
            ) : (
              <>
                <Typography variant="h6" gutterBottom>
                  Description
                </Typography>
                <Typography variant="body1" paragraph>
                  {event.description}
                </Typography>
                
                {event.learning_objectives && event.learning_objectives.length > 0 && (
                  <>
                    <Typography variant="h6" gutterBottom sx={{ mt: 3 }}>
                      Learning Objectives
                    </Typography>
                    <List>
                      {event.learning_objectives.map((objective, index) => (
                        <ListItem key={index}>
                          <ListItemText primary={objective} />
                        </ListItem>
                      ))}
                    </List>
                  </>
                )}
                
                {event.prerequisites && (
                  <>
                    <Typography variant="h6" gutterBottom sx={{ mt: 3 }}>
                      Prerequisites
                    </Typography>
                    <Typography variant="body1" paragraph>
                      {event.prerequisites}
                    </Typography>
                  </>
                )}
                
                {event.materials_provided && event.materials_provided.length > 0 && (
                  <>
                    <Typography variant="h6" gutterBottom sx={{ mt: 3 }}>
                      Materials Provided
                    </Typography>
                    <List>
                      {event.materials_provided.map((material, index) => (
                        <ListItem key={index}>
                          <ListItemText primary={material} />
                        </ListItem>
                      ))}
                    </List>
                  </>
                )}
              </>
            )}
          </TabPanel>

          {/* Speakers Tab */}
          <TabPanel value={tabValue} index={1}>
            <Typography variant="h6" gutterBottom>
              Speakers
            </Typography>
            
            {event.speakers && event.speakers.length > 0 ? (
              <Grid container spacing={3}>
                {event.speakers.map((speaker) => (
                  <Grid item xs={12} md={6} key={speaker.id}>
                    <Card>
                      <CardContent>
                        <Box sx={{ display: 'flex', alignItems: 'flex-start' }}>
                          <Avatar
                            src={speaker.photo}
                            sx={{ width: 80, height: 80, mr: 2 }}
                          >
                            {speaker.first_name[0]}{speaker.last_name[0]}
                          </Avatar>
                          <Box>
                            <Typography variant="h6">
                              {speaker.title ? `${speaker.title} ` : ''}{speaker.full_name}
                            </Typography>
                            {speaker.organization && (
                              <Typography variant="subtitle1" color="text.secondary">
                                {speaker.organization}
                              </Typography>
                            )}
                            <Box sx={{ display: 'flex', alignItems: 'center', mt: 1 }}>
                              <Rating value={speaker.average_rating} precision={0.1} size="small" readOnly />
                              <Typography variant="body2" color="text.secondary" sx={{ ml: 1 }}>
                                ({speaker.total_events} events)
                              </Typography>
                            </Box>
                          </Box>
                        </Box>
                        
                        {speaker.bio && (
                          <Typography variant="body2" sx={{ mt: 2 }}>
                            {speaker.bio}
                          </Typography>
                        )}
                        
                        {speaker.expertise && speaker.expertise.length > 0 && (
                          <Box sx={{ mt: 2 }}>
                            <Typography variant="body2" color="text.secondary" gutterBottom>
                              Expertise:
                            </Typography>
                            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                              {speaker.expertise.map((exp, index) => (
                                <Chip key={index} label={exp} size="small" variant="outlined" />
                              ))}
                            </Box>
                          </Box>
                        )}
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            ) : (
              <Typography variant="body1" color="text.secondary">
                No speaker information available for this event.
              </Typography>
            )}
          </TabPanel>

          {/* Agenda Tab */}
          <TabPanel value={tabValue} index={2}>
            <Typography variant="h6" gutterBottom>
              Agenda
            </Typography>
            
            {event.agenda ? (
              <Typography variant="body1" component="div" sx={{ whiteSpace: 'pre-line' }}>
                {event.agenda}
              </Typography>
            ) : (
              <Typography variant="body1" color="text.secondary">
                No detailed agenda available for this event.
              </Typography>
            )}
          </TabPanel>

          {/* Similar Events Tab */}
          <TabPanel value={tabValue} index={3}>
            <Typography variant="h6" gutterBottom>
              Similar Events
            </Typography>
            
            {similarEvents && similarEvents.length > 0 ? (
              <Grid container spacing={3}>
                {similarEvents.map((similarEvent) => (
                  <Grid item xs={12} sm={6} md={4} key={similarEvent.id}>
                    <EventCard event={similarEvent} />
                  </Grid>
                ))}
              </Grid>
            ) : event.similar_events && event.similar_events.length > 0 ? (
              <Grid container spacing={3}>
                {event.similar_events.map((similarEvent) => (
                  <Grid item xs={12} sm={6} md={4} key={similarEvent.id}>
                    <EventCard event={similarEvent} />
                  </Grid>
                ))}
              </Grid>
            ) : (
              <Typography variant="body1" color="text.secondary">
                No similar events found.
              </Typography>
            )}
          </TabPanel>
        </Box>

        {/* Register Dialog */}
        <Dialog
          open={registerDialogOpen}
          onClose={() => !isSubmitting && setRegisterDialogOpen(false)}
          maxWidth="md"
          fullWidth
        >
          <DialogTitle>Register for Event</DialogTitle>
          <DialogContent>
            <Box sx={{ mb: 3 }}>
              <Typography variant="h6">{event.title}</Typography>
              <Typography variant="body2" color="text.secondary">
                {formatDate(event.start_date)} • {event.start_time} - {event.end_time}
              </Typography>
            </Box>
            
            {event.registration_fee > 0 && (
              <Alert severity="info" sx={{ mb: 3 }}>
                This event requires a registration fee of {event.user_registration_fee} PKR.
                {event.early_bird_deadline && new Date(event.early_bird_deadline) > new Date() && (
                  <> Early bird discount of {event.early_bird_discount}% applied.</>
                )}
              </Alert>
            )}
            
            <Box component="form" sx={{ mt: 2 }}>
              <Grid container spacing={3}>
                <Grid item xs={12}>
                  <Controller
                    name="dietary_requirements"
                    control={registerControl}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="Dietary Requirements"
                        fullWidth
                        placeholder="Any dietary restrictions or preferences"
                        error={!!registerErrors.dietary_requirements}
                        helperText={registerErrors.dietary_requirements?.message}
                      />
                    )}
                  />
                </Grid>
                
                <Grid item xs={12}>
                  <Controller
                    name="special_needs"
                    control={registerControl}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="Special Needs"
                        fullWidth
                        placeholder="Any special accommodations required"
                        error={!!registerErrors.special_needs}
                        helperText={registerErrors.special_needs?.message}
                      />
                    )}
                  />
                </Grid>
                
                <Grid item xs={12}>
                  <Controller
                    name="emergency_contact"
                    control={registerControl}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="Emergency Contact"
                        fullWidth
                        placeholder="Name and phone number"
                        error={!!registerErrors.emergency_contact}
                        helperText={registerErrors.emergency_contact?.message}
                      />
                    )}
                  />
                </Grid>
                
                <Grid item xs={12}>
                  <Controller
                    name="how_did_you_hear"
                    control={registerControl}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="How did you hear about this event?"
                        fullWidth
                        error={!!registerErrors.how_did_you_hear}
                        helperText={registerErrors.how_did_you_hear?.message}
                      />
                    )}
                  />
                </Grid>
                
                <Grid item xs={12}>
                  <Controller
                    name="expectations"
                    control={registerControl}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="What do you hope to learn from this event?"
                        fullWidth
                        multiline
                        rows={3}
                        error={!!registerErrors.expectations}
                        helperText={registerErrors.expectations?.message}
                      />
                    )}
                  />
                </Grid>
              </Grid>
            </Box>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setRegisterDialogOpen(false)} disabled={isSubmitting}>
              Cancel
            </Button>
            <Button
              variant="contained"
              onClick={handleRegisterSubmit(onSubmitRegistration)}
              disabled={isSubmitting}
            >
              {isSubmitting ? <LoadingSpinner size="sm" /> : 'Register'}
            </Button>
          </DialogActions>
        </Dialog>

        {/* Feedback Dialog */}
        <Dialog
          open={feedbackDialogOpen}
          onClose={() => !isSubmitting && setFeedbackDialogOpen(false)}
          maxWidth="md"
          fullWidth
        >
          <DialogTitle>Submit Feedback</DialogTitle>
          <DialogContent>
            <Box sx={{ mb: 3 }}>
              <Typography variant="h6">{event.title}</Typography>
              <Typography variant="body2" color="text.secondary">
                {formatDate(event.start_date)} • {event.start_time} - {event.end_time}
              </Typography>
            </Box>
            
            <Box component="form" sx={{ mt: 2 }}>
              <Grid container spacing={3}>
                <Grid item xs={12}>
                  <Typography variant="subtitle1" gutterBottom>
                    Overall Rating
                  </Typography>
                  <Controller
                    name="overall_rating"
                    control={feedbackControl}
                    render={({ field }) => (
                      <Rating
                        {...field}
                        onChange={(_, value) => field.onChange(value)}
                        size="large"
                      />
                    )}
                  />
                  {feedbackErrors.overall_rating && (
                    <Typography color="error" variant="caption">
                      {feedbackErrors.overall_rating.message}
                    </Typography>
                  )}
                </Grid>
                
                <Grid item xs={12} sm={4}>
                  <Typography variant="subtitle2" gutterBottom>
                    Content Rating
                  </Typography>
                  <Controller
                    name="content_rating"
                    control={feedbackControl}
                    render={({ field }) => (
                      <Rating
                        {...field}
                        onChange={(_, value) => field.onChange(value)}
                        size="small"
                      />
                    )}
                  />
                </Grid>
                
                <Grid item xs={12} sm={4}>
                  <Typography variant="subtitle2" gutterBottom>
                    Speaker Rating
                  </Typography>
                  <Controller
                    name="speaker_rating"
                    control={feedbackControl}
                    render={({ field }) => (
                      <Rating
                        {...field}
                        onChange={(_, value) => field.onChange(value)}
                        size="small"
                      />
                    )}
                  />
                </Grid>
                
                <Grid item xs={12} sm={4}>
                  <Typography variant="subtitle2" gutterBottom>
                    Organization Rating
                  </Typography>
                  <Controller
                    name="organization_rating"
                    control={feedbackControl}
                    render={({ field }) => (
                      <Rating
                        {...field}
                        onChange={(_, value) => field.onChange(value)}
                        size="small"
                      />
                    )}
                  />
                </Grid>
                
                <Grid item xs={12}>
                  <Controller
                    name="what_you_liked"
                    control={feedbackControl}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="What did you like about this event?"
                        fullWidth
                        multiline
                        rows={3}
                        error={!!feedbackErrors.what_you_liked}
                        helperText={feedbackErrors.what_you_liked?.message}
                      />
                    )}
                  />
                </Grid>
                
                <Grid item xs={12}>
                  <Controller
                    name="what_could_improve"
                    control={feedbackControl}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="What could be improved?"
                        fullWidth
                        multiline
                        rows={3}
                        error={!!feedbackErrors.what_could_improve}
                        helperText={feedbackErrors.what_could_improve?.message}
                      />
                    )}
                  />
                </Grid>
                
                <Grid item xs={12}>
                  <Controller
                    name="additional_comments"
                    control={feedbackControl}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="Additional Comments"
                        fullWidth
                        multiline
                        rows={2}
                        error={!!feedbackErrors.additional_comments}
                        helperText={feedbackErrors.additional_comments?.message}
                      />
                    )}
                  />
                </Grid>
                
                <Grid item xs={12}>
                  <Controller
                    name="future_topics"
                    control={feedbackControl}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="What topics would you like to see in future events?"
                        fullWidth
                        error={!!feedbackErrors.future_topics}
                        helperText={feedbackErrors.future_topics?.message}
                      />
                    )}
                  />
                </Grid>
              </Grid>
            </Box>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setFeedbackDialogOpen(false)} disabled={isSubmitting}>
              Cancel
            </Button>
            <Button
              variant="contained"
              onClick={handleFeedbackSubmit(onSubmitFeedback)}
              disabled={isSubmitting}
            >
              {isSubmitting ? <LoadingSpinner size="sm" /> : 'Submit Feedback'}
            </Button>
          </DialogActions>
        </Dialog>

        {/* Subscription Dialog */}
        <Dialog
          open={subscriptionDialogOpen}
          onClose={() => setSubscriptionDialogOpen(false)}
          maxWidth="sm"
          fullWidth
        >
          <DialogTitle>Premium Content</DialogTitle>
          <DialogContent>
            <Typography variant="h6" gutterBottom>
              This is a premium event
            </Typography>
            <Typography variant="body1" paragraph>
              You need an active subscription to access premium events.
            </Typography>
            <Alert severity="info" sx={{ mb: 3 }}>
              Subscribe to a plan to enjoy:
              <ul>
                <li>Access to premium events</li>
                <li>Access to premium books</li>
                <li>Access to premium seats</li>
                <li>Increased reservation limits</li>
                <li>And many more benefits!</li>
              </ul>
            </Alert>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setSubscriptionDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="contained"
              color="warning"
              startIcon={<CreditCard />}
              onClick={() => {
                setSubscriptionDialogOpen(false)
                navigate('/subscriptions')
              }}
            >
              View Subscription Plans
            </Button>
          </DialogActions>
        </Dialog>
      </motion.div>
    </Box>
  )
}