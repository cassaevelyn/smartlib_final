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
  IconButton,
  Alert,
  CircularProgress,
  Breadcrumbs,
  Link as MuiLink,
} from '@mui/material'
import {
  LocationOn,
  AccessTime,
  Wifi,
  LocalParking,
  LocalPrintshop,
  Scanner,
  Restaurant,
  Phone,
  Email,
  Language,
  EventSeat,
  MenuBook,
  Event,
  Info,
  Star,
  ArrowBack,
  NavigateNext,
} from '@mui/icons-material'
import { motion } from 'framer-motion'
import { libraryService } from '../../services/libraryService'
import { Library, LibraryFloor, LibrarySection } from '../../types'
import { LoadingSpinner } from '../../components/ui/loading-spinner'
import { formatDate, formatTime } from '../../lib/utils'

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
      id={`library-tabpanel-${index}`}
      aria-labelledby={`library-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </div>
  )
}

export function LibraryDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [library, setLibrary] = useState<Library | null>(null)
  const [floors, setFloors] = useState<LibraryFloor[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [tabValue, setTabValue] = useState(0)

  useEffect(() => {
    if (!id) return

    const fetchLibraryDetails = async () => {
      try {
        setIsLoading(true)
        setError(null)

        const libraryData = await libraryService.getLibrary(id)
        setLibrary(libraryData)

        const floorsData = await libraryService.getLibraryFloors(id)
        setFloors(floorsData)
      } catch (error: any) {
        setError(error.message || 'Failed to fetch library details')
      } finally {
        setIsLoading(false)
      }
    }

    fetchLibraryDetails()
  }, [id])

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue)
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
          onClick={() => navigate('/libraries')}
        >
          Back to Libraries
        </Button>
      </Box>
    )
  }

  if (!library) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="warning" sx={{ mb: 3 }}>
          Library not found
        </Alert>
        <Button
          variant="outlined"
          startIcon={<ArrowBack />}
          onClick={() => navigate('/libraries')}
        >
          Back to Libraries
        </Button>
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
        {/* Breadcrumbs */}
        <Breadcrumbs separator={<NavigateNext fontSize="small" />} sx={{ mb: 2 }}>
          <MuiLink
            component="button"
            variant="body2"
            onClick={() => navigate('/libraries')}
            underline="hover"
            color="inherit"
          >
            Libraries
          </MuiLink>
          <Typography color="text.primary">{library.name}</Typography>
        </Breadcrumbs>

        {/* Library Header */}
        <Box sx={{ mb: 4 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
            <Typography variant="h4" component="h1" gutterBottom>
              {library.name}
            </Typography>
            <Chip
              label={library.status}
              size="small"
              color={
                library.status === 'ACTIVE'
                  ? 'success'
                  : library.status === 'MAINTENANCE'
                  ? 'warning'
                  : 'error'
              }
              sx={{ ml: 2 }}
            />
          </Box>
          <Typography variant="body1" color="text.secondary">
            {library.description || 'No description available'}
          </Typography>
        </Box>

        {/* Library Image and Quick Info */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Card>
              <CardMedia
                component="img"
                height="300"
                image={library.main_image || 'https://images.pexels.com/photos/590493/pexels-photo-590493.jpeg'}
                alt={library.name}
              />
            </Card>
          </Grid>
          <Grid item xs={12} md={6}>
            <Card sx={{ height: '100%' }}>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Quick Information
                </Typography>
                <List>
                  <ListItem>
                    <ListItemIcon>
                      <LocationOn />
                    </ListItemIcon>
                    <ListItemText
                      primary="Address"
                      secondary={`${library.address}, ${library.city}${library.postal_code ? `, ${library.postal_code}` : ''}`}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <AccessTime />
                    </ListItemIcon>
                    <ListItemText
                      primary="Opening Hours"
                      secondary={
                        library.is_24_hours
                          ? '24 Hours'
                          : `${library.opening_time} - ${library.closing_time}`
                      }
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <Phone />
                    </ListItemIcon>
                    <ListItemText
                      primary="Contact"
                      secondary={library.phone_number || 'Not available'}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <Email />
                    </ListItemIcon>
                    <ListItemText
                      primary="Email"
                      secondary={library.email || 'Not available'}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <EventSeat />
                    </ListItemIcon>
                    <ListItemText
                      primary="Seats"
                      secondary={`${library.available_seats} available out of ${library.total_seats} total seats`}
                    />
                  </ListItem>
                </List>
                <Box sx={{ display: 'flex', gap: 1, mt: 2 }}>
                  <Button
                    variant="contained"
                    onClick={() => navigate(`/seats?library=${library.id}`)}
                    startIcon={<EventSeat />}
                  >
                    View Seats
                  </Button>
                  <Button
                    variant="outlined"
                    onClick={() => navigate(`/seats/book?library=${library.id}`)}
                  >
                    Book a Seat
                  </Button>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        {/* Tabs for different sections */}
        <Box sx={{ width: '100%', mb: 4 }}>
          <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
            <Tabs
              value={tabValue}
              onChange={handleTabChange}
              aria-label="library details tabs"
              variant="scrollable"
              scrollButtons="auto"
            >
              <Tab label="Overview" icon={<Info />} iconPosition="start" />
              <Tab label="Floors & Sections" icon={<EventSeat />} iconPosition="start" />
              <Tab label="Amenities" icon={<Wifi />} iconPosition="start" />
              <Tab label="Reviews" icon={<Star />} iconPosition="start" />
            </Tabs>
          </Box>

          {/* Overview Tab */}
          <TabPanel value={tabValue} index={0}>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Card>
                  <CardContent>
                    <Typography variant="h6" gutterBottom>
                      About {library.name}
                    </Typography>
                    <Typography variant="body1" paragraph>
                      {library.description || 'No detailed description available for this library.'}
                    </Typography>
                    <Divider sx={{ my: 2 }} />
                    <Typography variant="subtitle1" gutterBottom>
                      Features
                    </Typography>
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mb: 2 }}>
                      {library.has_wifi && (
                        <Chip icon={<Wifi />} label="WiFi" variant="outlined" />
                      )}
                      {library.has_printing && (
                        <Chip icon={<LocalPrintshop />} label="Printing" variant="outlined" />
                      )}
                      {library.has_scanning && (
                        <Chip icon={<Scanner />} label="Scanning" variant="outlined" />
                      )}
                      {library.has_parking && (
                        <Chip icon={<LocalParking />} label="Parking" variant="outlined" />
                      )}
                      {library.has_cafeteria && (
                        <Chip icon={<Restaurant />} label="Cafeteria" variant="outlined" />
                      )}
                    </Box>
                    <Divider sx={{ my: 2 }} />
                    <Typography variant="subtitle1" gutterBottom>
                      Capacity
                    </Typography>
                    <Grid container spacing={2}>
                      <Grid item xs={6}>
                        <Typography variant="body2" color="text.secondary">
                          Total Capacity
                        </Typography>
                        <Typography variant="h6">{library.total_capacity}</Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2" color="text.secondary">
                          Total Seats
                        </Typography>
                        <Typography variant="h6">{library.total_seats}</Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2" color="text.secondary">
                          Study Rooms
                        </Typography>
                        <Typography variant="h6">{library.total_study_rooms}</Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2" color="text.secondary">
                          Current Occupancy
                        </Typography>
                        <Typography variant="h6">{library.occupancy_rate.toFixed(1)}%</Typography>
                      </Grid>
                    </Grid>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} md={6}>
                <Card sx={{ mb: 3 }}>
                  <CardContent>
                    <Typography variant="h6" gutterBottom>
                      Operating Hours
                    </Typography>
                    {library.is_24_hours ? (
                      <Typography variant="body1">
                        This library is open 24 hours a day, 7 days a week.
                      </Typography>
                    ) : (
                      <List dense>
                        <ListItem>
                          <ListItemText primary="Monday" secondary={`${library.opening_time} - ${library.closing_time}`} />
                        </ListItem>
                        <ListItem>
                          <ListItemText primary="Tuesday" secondary={`${library.opening_time} - ${library.closing_time}`} />
                        </ListItem>
                        <ListItem>
                          <ListItemText primary="Wednesday" secondary={`${library.opening_time} - ${library.closing_time}`} />
                        </ListItem>
                        <ListItem>
                          <ListItemText primary="Thursday" secondary={`${library.opening_time} - ${library.closing_time}`} />
                        </ListItem>
                        <ListItem>
                          <ListItemText primary="Friday" secondary={`${library.opening_time} - ${library.closing_time}`} />
                        </ListItem>
                        <ListItem>
                          <ListItemText primary="Saturday" secondary={`${library.opening_time} - ${library.closing_time}`} />
                        </ListItem>
                        <ListItem>
                          <ListItemText primary="Sunday" secondary={`${library.opening_time} - ${library.closing_time}`} />
                        </ListItem>
                      </List>
                    )}
                  </CardContent>
                </Card>
                <Card>
                  <CardContent>
                    <Typography variant="h6" gutterBottom>
                      Booking Information
                    </Typography>
                    <List dense>
                      <ListItem>
                        <ListItemText
                          primary="Advance Booking"
                          secondary={`Up to ${library.booking_advance_days} days in advance`}
                        />
                      </ListItem>
                      <ListItem>
                        <ListItemText
                          primary="Maximum Duration"
                          secondary={`${library.max_booking_duration_hours} hours per booking`}
                        />
                      </ListItem>
                      <ListItem>
                        <ListItemText
                          primary="Auto-Cancel Policy"
                          secondary={`Bookings are automatically cancelled after ${library.auto_cancel_minutes} minutes of no-show`}
                        />
                      </ListItem>
                    </List>
                    <Box sx={{ mt: 2 }}>
                      <Button
                        variant="contained"
                        fullWidth
                        onClick={() => navigate(`/seats/book?library=${library.id}`)}
                      >
                        Book a Seat Now
                      </Button>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          </TabPanel>

          {/* Floors & Sections Tab */}
          <TabPanel value={tabValue} index={1}>
            {floors.length === 0 ? (
              <Box sx={{ textAlign: 'center', py: 4 }}>
                <Typography variant="body1" color="text.secondary">
                  No floor information available for this library.
                </Typography>
              </Box>
            ) : (
              <Grid container spacing={3}>
                {floors.map((floor) => (
                  <Grid item xs={12} key={floor.id}>
                    <Card>
                      <CardContent>
                        <Typography variant="h6" gutterBottom>
                          {floor.floor_name} (Floor {floor.floor_number})
                        </Typography>
                        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mb: 2 }}>
                          {floor.has_silent_zone && (
                            <Chip label="Silent Zone" size="small" variant="outlined" />
                          )}
                          {floor.has_group_study && (
                            <Chip label="Group Study" size="small" variant="outlined" />
                          )}
                          {floor.has_computer_lab && (
                            <Chip label="Computer Lab" size="small" variant="outlined" />
                          )}
                          {floor.has_printer && (
                            <Chip label="Printer" size="small" variant="outlined" />
                          )}
                          {floor.has_restroom && (
                            <Chip label="Restroom" size="small" variant="outlined" />
                          )}
                        </Box>
                        <Grid container spacing={2} sx={{ mb: 2 }}>
                          <Grid item xs={6} sm={3}>
                            <Typography variant="body2" color="text.secondary">
                              Total Seats
                            </Typography>
                            <Typography variant="h6">{floor.total_seats}</Typography>
                          </Grid>
                          <Grid item xs={6} sm={3}>
                            <Typography variant="body2" color="text.secondary">
                              Available Seats
                            </Typography>
                            <Typography variant="h6">{floor.available_seats}</Typography>
                          </Grid>
                          <Grid item xs={6} sm={3}>
                            <Typography variant="body2" color="text.secondary">
                              Study Rooms
                            </Typography>
                            <Typography variant="h6">{floor.study_rooms}</Typography>
                          </Grid>
                          <Grid item xs={6} sm={3}>
                            <Typography variant="body2" color="text.secondary">
                              Occupancy Rate
                            </Typography>
                            <Typography variant="h6">{floor.occupancy_rate.toFixed(1)}%</Typography>
                          </Grid>
                        </Grid>
                        <Divider sx={{ my: 2 }} />
                        <Typography variant="subtitle1" gutterBottom>
                          Sections
                        </Typography>
                        {floor.sections && floor.sections.length > 0 ? (
                          <Grid container spacing={2}>
                            {floor.sections.map((section) => (
                              <Grid item xs={12} sm={6} md={4} key={section.id}>
                                <Card variant="outlined">
                                  <CardContent>
                                    <Typography variant="subtitle1">{section.name}</Typography>
                                    <Typography variant="body2" color="text.secondary" gutterBottom>
                                      {section.section_type_display}
                                    </Typography>
                                    <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                                      <Typography variant="body2">
                                        {section.available_seats}/{section.total_seats} seats
                                      </Typography>
                                      <Chip
                                        label={section.is_section_full ? 'Full' : 'Available'}
                                        size="small"
                                        color={section.is_section_full ? 'error' : 'success'}
                                      />
                                    </Box>
                                    <Button
                                      size="small"
                                      variant="outlined"
                                      fullWidth
                                      onClick={() => navigate(`/seats?section=${section.id}`)}
                                    >
                                      View Seats
                                    </Button>
                                  </CardContent>
                                </Card>
                              </Grid>
                            ))}
                          </Grid>
                        ) : (
                          <Typography variant="body2" color="text.secondary">
                            No sections available for this floor.
                          </Typography>
                        )}
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            )}
          </TabPanel>

          {/* Amenities Tab */}
          <TabPanel value={tabValue} index={2}>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Card>
                  <CardContent>
                    <Typography variant="h6" gutterBottom>
                      Facilities
                    </Typography>
                    <List>
                      <ListItem>
                        <ListItemIcon>
                          <Wifi color={library.has_wifi ? 'primary' : 'disabled'} />
                        </ListItemIcon>
                        <ListItemText
                          primary="WiFi"
                          secondary={library.has_wifi ? 'Available' : 'Not available'}
                        />
                      </ListItem>
                      <ListItem>
                        <ListItemIcon>
                          <LocalPrintshop color={library.has_printing ? 'primary' : 'disabled'} />
                        </ListItemIcon>
                        <ListItemText
                          primary="Printing Services"
                          secondary={library.has_printing ? 'Available' : 'Not available'}
                        />
                      </ListItem>
                      <ListItem>
                        <ListItemIcon>
                          <Scanner color={library.has_scanning ? 'primary' : 'disabled'} />
                        </ListItemIcon>
                        <ListItemText
                          primary="Scanning Services"
                          secondary={library.has_scanning ? 'Available' : 'Not available'}
                        />
                      </ListItem>
                      <ListItem>
                        <ListItemIcon>
                          <LocalParking color={library.has_parking ? 'primary' : 'disabled'} />
                        </ListItemIcon>
                        <ListItemText
                          primary="Parking"
                          secondary={library.has_parking ? 'Available' : 'Not available'}
                        />
                      </ListItem>
                      <ListItem>
                        <ListItemIcon>
                          <Restaurant color={library.has_cafeteria ? 'primary' : 'disabled'} />
                        </ListItemIcon>
                        <ListItemText
                          primary="Cafeteria"
                          secondary={library.has_cafeteria ? 'Available' : 'Not available'}
                        />
                      </ListItem>
                    </List>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} md={6}>
                <Card>
                  <CardContent>
                    <Typography variant="h6" gutterBottom>
                      Rules & Policies
                    </Typography>
                    {library.rules && library.rules.length > 0 ? (
                      <List>
                        {library.rules.map((rule, index) => (
                          <ListItem key={index}>
                            <ListItemText primary={rule} />
                          </ListItem>
                        ))}
                      </List>
                    ) : (
                      <Typography variant="body1">
                        No specific rules listed for this library. Please follow general library etiquette and respect other users.
                      </Typography>
                    )}
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          </TabPanel>

          {/* Reviews Tab */}
          <TabPanel value={tabValue} index={3}>
            <Grid container spacing={3}>
              <Grid item xs={12} md={4}>
                <Card>
                  <CardContent>
                    <Typography variant="h6" gutterBottom>
                      Rating Summary
                    </Typography>
                    <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                      <Typography variant="h3" component="div" sx={{ mr: 2 }}>
                        {library.average_rating.toFixed(1)}
                      </Typography>
                      <Box>
                        <Rating value={library.average_rating} precision={0.1} readOnly />
                        <Typography variant="body2" color="text.secondary">
                          Based on {library.total_reviews} reviews
                        </Typography>
                      </Box>
                    </Box>
                    <Button
                      variant="contained"
                      fullWidth
                      onClick={() => {
                        // This would open a review dialog in a real app
                        alert('Review functionality would be implemented here')
                      }}
                    >
                      Write a Review
                    </Button>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} md={8}>
                <Card>
                  <CardContent>
                    <Typography variant="h6" gutterBottom>
                      Recent Reviews
                    </Typography>
                    {library.recent_reviews && library.recent_reviews.length > 0 ? (
                      <List>
                        {library.recent_reviews.map((review) => (
                          <ListItem key={review.id} alignItems="flex-start" sx={{ mb: 2 }}>
                            <Box sx={{ width: '100%' }}>
                              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                                <Avatar src={review.user_avatar} sx={{ mr: 2 }}>
                                  {review.user_display.charAt(0)}
                                </Avatar>
                                <Box>
                                  <Typography variant="subtitle1">{review.user_display}</Typography>
                                  <Typography variant="caption" color="text.secondary">
                                    {formatDate(review.created_at)}
                                  </Typography>
                                </Box>
                                <Box sx={{ ml: 'auto' }}>
                                  <Rating value={review.rating} size="small" readOnly />
                                </Box>
                              </Box>
                              {review.title && (
                                <Typography variant="subtitle2" gutterBottom>
                                  {review.title}
                                </Typography>
                              )}
                              <Typography variant="body2">{review.review_text}</Typography>
                            </Box>
                          </ListItem>
                        ))}
                      </List>
                    ) : (
                      <Typography variant="body1" color="text.secondary" sx={{ py: 2 }}>
                        No reviews available for this library yet. Be the first to leave a review!
                      </Typography>
                    )}
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          </TabPanel>
        </Box>
      </motion.div>
    </Box>
  )
}