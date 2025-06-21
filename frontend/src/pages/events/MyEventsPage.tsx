import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Box,
  Typography,
  Grid,
  Card,
  CardContent,
  CardMedia,
  Button,
  Tabs,
  Tab,
  Chip,
  Divider,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Alert,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
} from '@mui/material'
import {
  Event,
  CalendarToday,
  AccessTime,
  LocationOn,
  Cancel,
  History,
  QrCode,
  Logout,
  Visibility,
  EmojiEvents,
  Star,
} from '@mui/icons-material'
import { motion } from 'framer-motion'
import QRCode from 'qrcode'
import { eventService } from '../../services/eventService'
import { EventRegistration } from '../../types'
import { LoadingSpinner } from '../../components/ui/loading-spinner'
import { useToast } from '../../hooks/use-toast'
import { formatDate, formatTime, getStatusColor } from '../../lib/utils'

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
      id={`events-tabpanel-${index}`}
      aria-labelledby={`events-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </div>
  )
}

export function MyEventsPage() {
  const navigate = useNavigate()
  const { toast } = useToast()
  
  const [tabValue, setTabValue] = useState(0)
  const [registrations, setRegistrations] = useState<EventRegistration[]>([])
  const [filteredRegistrations, setFilteredRegistrations] = useState<EventRegistration[]>([])
  const [selectedRegistration, setSelectedRegistration] = useState<EventRegistration | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  
  // Dialog states
  const [qrDialogOpen, setQrDialogOpen] = useState(false)
  const [cancelDialogOpen, setCancelDialogOpen] = useState(false)
  const [feedbackDialogOpen, setFeedbackDialogOpen] = useState(false)
  const [qrCodeUrl, setQrCodeUrl] = useState<string | null>(null)
  const [isProcessing, setIsProcessing] = useState(false)

  useEffect(() => {
    fetchRegistrations()
  }, [])

  useEffect(() => {
    // Filter registrations based on tab
    if (registrations.length > 0) {
      switch (tabValue) {
        case 0: // Upcoming
          setFilteredRegistrations(
            registrations.filter(registration => 
              ['CONFIRMED', 'WAITLISTED'].includes(registration.status) && 
              new Date(registration.event_title) > new Date()
            )
          )
          break
        case 1: // Past
          setFilteredRegistrations(
            registrations.filter(registration => 
              ['ATTENDED', 'NO_SHOW'].includes(registration.status) ||
              new Date(registration.event_title) < new Date()
            )
          )
          break
        case 2: // Cancelled
          setFilteredRegistrations(
            registrations.filter(registration => 
              ['CANCELLED', 'REFUNDED'].includes(registration.status)
            )
          )
          break
        default:
          setFilteredRegistrations(registrations)
      }
    }
  }, [tabValue, registrations])

  const fetchRegistrations = async () => {
    try {
      setIsLoading(true)
      setError(null)
      
      const response = await eventService.getRegistrations()
      setRegistrations(response.results)
    } catch (error: any) {
      setError(error.message || 'Failed to fetch event registrations')
    } finally {
      setIsLoading(false)
    }
  }

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue)
  }

  const handleGenerateQRCode = async (registration: EventRegistration) => {
    try {
      setIsProcessing(true)
      
      const response = await eventService.generateQRCode(registration.id)
      
      // Generate QR code from the data
      const qrData = JSON.stringify(response.qr_data)
      const qrCodeDataUrl = await QRCode.toDataURL(qrData)
      
      setQrCodeUrl(qrCodeDataUrl)
      setQrDialogOpen(true)
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || 'Failed to generate QR code',
        variant: "destructive",
      })
    } finally {
      setIsProcessing(false)
    }
  }

  const handleCheckIn = async () => {
    if (!selectedRegistration) return
    
    try {
      setIsProcessing(true)
      
      await eventService.checkIn({
        registration_id: selectedRegistration.id,
        check_in_method: 'MANUAL',
      })
      
      toast({
        title: "Check-in Successful",
        description: "You have successfully checked in to the event.",
        variant: "default",
      })
      
      setQrDialogOpen(false)
      fetchRegistrations()
    } catch (error: any) {
      toast({
        title: "Check-in Failed",
        description: error.message || 'Failed to check in',
        variant: "destructive",
      })
    } finally {
      setIsProcessing(false)
    }
  }

  const handleCheckOut = async (registration: EventRegistration) => {
    try {
      setIsProcessing(true)
      
      await eventService.checkOut({
        registration_id: registration.id,
        check_out_method: 'MANUAL',
      })
      
      toast({
        title: "Check-out Successful",
        description: "You have successfully checked out from the event.",
        variant: "default",
      })
      
      fetchRegistrations()
    } catch (error: any) {
      toast({
        title: "Check-out Failed",
        description: error.message || 'Failed to check out',
        variant: "destructive",
      })
    } finally {
      setIsProcessing(false)
    }
  }

  const handleCancelRegistration = async () => {
    if (!selectedRegistration) return
    
    try {
      setIsProcessing(true)
      
      await eventService.cancelRegistration(selectedRegistration.id)
      
      toast({
        title: "Registration Cancelled",
        description: "Your event registration has been cancelled successfully.",
        variant: "default",
      })
      
      setCancelDialogOpen(false)
      fetchRegistrations()
    } catch (error: any) {
      toast({
        title: "Cancellation Failed",
        description: error.message || 'Failed to cancel registration',
        variant: "destructive",
      })
    } finally {
      setIsProcessing(false)
    }
  }

  const renderRegistrationCard = (registration: EventRegistration) => {
    return (
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        key={registration.id}
      >
        <Card sx={{ mb: 3, display: 'flex', height: '100%' }}>
          <CardMedia
            component="img"
            sx={{ width: 120 }}
            image={registration.event_banner || 'https://images.pexels.com/photos/7103/writing-notes-idea-conference.jpg'}
            alt={registration.event_title}
          />
          <Box sx={{ display: 'flex', flexDirection: 'column', width: '100%' }}>
            <CardContent sx={{ flex: '1 0 auto' }}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 1 }}>
                <Typography variant="h6" component="div">
                  {registration.event_title}
                </Typography>
                <Chip
                  label={registration.status_display}
                  size="small"
                  className={getStatusColor(registration.status)}
                />
              </Box>
              
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <CalendarToday fontSize="small" color="action" sx={{ mr: 0.5 }} />
                <Typography variant="body2" color="text.secondary">
                  {formatDate(registration.registration_date)}
                </Typography>
              </Box>
              
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <AccessTime fontSize="small" color="action" sx={{ mr: 0.5 }} />
                <Typography variant="body2" color="text.secondary">
                  {registration.check_in_time ? formatTime(registration.check_in_time) : 'Not checked in yet'}
                </Typography>
              </Box>
              
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <LocationOn fontSize="small" color="action" sx={{ mr: 0.5 }} />
                <Typography variant="body2" color="text.secondary">
                  {registration.payment_status_display}
                </Typography>
              </Box>
              
              <Box sx={{ display: 'flex', justifyContent: 'flex-end', gap: 1 }}>
                {registration.can_check_in && (
                  <Button
                    size="small"
                    variant="outlined"
                    startIcon={<QrCode />}
                    onClick={() => {
                      setSelectedRegistration(registration)
                      handleGenerateQRCode(registration)
                    }}
                  >
                    Check In
                  </Button>
                )}
                
                {registration.can_check_out && (
                  <Button
                    size="small"
                    variant="outlined"
                    startIcon={<Logout />}
                    onClick={() => {
                      setSelectedRegistration(registration)
                      handleCheckOut(registration)
                    }}
                  >
                    Check Out
                  </Button>
                )}
                
                {registration.status === 'CONFIRMED' && (
                  <Button
                    size="small"
                    variant="outlined"
                    color="error"
                    startIcon={<Cancel />}
                    onClick={() => {
                      setSelectedRegistration(registration)
                      setCancelDialogOpen(true)
                    }}
                  >
                    Cancel
                  </Button>
                )}
                
                {registration.status === 'ATTENDED' && !registration.feedback_submitted && (
                  <Button
                    size="small"
                    variant="outlined"
                    startIcon={<Star />}
                    onClick={() => navigate(`/events/${registration.event}?feedback=true`)}
                  >
                    Feedback
                  </Button>
                )}
                
                {registration.certificate_issued && (
                  <Button
                    size="small"
                    variant="outlined"
                    startIcon={<EmojiEvents />}
                    onClick={() => window.open(registration.certificate_file, '_blank')}
                  >
                    Certificate
                  </Button>
                )}
                
                <Button
                  size="small"
                  startIcon={<Visibility />}
                  onClick={() => navigate(`/events/${registration.event}`)}
                >
                  View Event
                </Button>
              </Box>
            </CardContent>
          </Box>
        </Card>
      </motion.div>
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
            My Events
          </Typography>
          <Typography variant="body1" color="text.secondary">
            Manage your event registrations and attendance.
          </Typography>
        </Box>

        <Card>
          <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
            <Tabs
              value={tabValue}
              onChange={handleTabChange}
              aria-label="event tabs"
              variant="fullWidth"
            >
              <Tab 
                icon={<Event />} 
                label="Upcoming" 
                iconPosition="start" 
              />
              <Tab 
                icon={<History />} 
                label="Past" 
                iconPosition="start" 
              />
              <Tab 
                icon={<Cancel />} 
                label="Cancelled" 
                iconPosition="start" 
              />
            </Tabs>
          </Box>
          
          <Box sx={{ p: 2 }}>
            {isLoading ? (
              <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
                <LoadingSpinner size="md" />
              </Box>
            ) : error ? (
              <Alert severity="error" sx={{ mb: 2 }}>
                {error}
              </Alert>
            ) : filteredRegistrations.length === 0 ? (
              <Box sx={{ textAlign: 'center', py: 4 }}>
                <Typography variant="body1" color="text.secondary" gutterBottom>
                  No event registrations found
                </Typography>
                <Button
                  variant="contained"
                  onClick={() => navigate('/events')}
                  sx={{ mt: 2 }}
                >
                  Browse Events
                </Button>
              </Box>
            ) : (
              <>
                <TabPanel value={tabValue} index={0}>
                  <Grid container spacing={2}>
                    {filteredRegistrations.map((registration) => (
                      <Grid item xs={12} key={registration.id}>
                        {renderRegistrationCard(registration)}
                      </Grid>
                    ))}
                  </Grid>
                </TabPanel>
                
                <TabPanel value={tabValue} index={1}>
                  <Grid container spacing={2}>
                    {filteredRegistrations.map((registration) => (
                      <Grid item xs={12} key={registration.id}>
                        {renderRegistrationCard(registration)}
                      </Grid>
                    ))}
                  </Grid>
                </TabPanel>
                
                <TabPanel value={tabValue} index={2}>
                  <Grid container spacing={2}>
                    {filteredRegistrations.map((registration) => (
                      <Grid item xs={12} key={registration.id}>
                        {renderRegistrationCard(registration)}
                      </Grid>
                    ))}
                  </Grid>
                </TabPanel>
              </>
            )}
          </Box>
        </Card>

        {/* QR Code Dialog */}
        <Dialog
          open={qrDialogOpen}
          onClose={() => !isProcessing && setQrDialogOpen(false)}
          maxWidth="xs"
          fullWidth
        >
          <DialogTitle>Event Check-In QR Code</DialogTitle>
          <DialogContent>
            <Box sx={{ textAlign: 'center', py: 2 }}>
              {qrCodeUrl ? (
                <img src={qrCodeUrl} alt="Check-in QR Code" style={{ width: '100%', maxWidth: 250 }} />
              ) : (
                <LoadingSpinner size="lg" />
              )}
              <Typography variant="body1" sx={{ mt: 2 }}>
                Scan this QR code at the event to check in.
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                This QR code will expire in 15 minutes.
              </Typography>
            </Box>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setQrDialogOpen(false)} disabled={isProcessing}>
              Close
            </Button>
            <Button
              variant="contained"
              onClick={handleCheckIn}
              disabled={isProcessing}
              startIcon={isProcessing ? <LoadingSpinner size="sm" /> : <Event />}
            >
              Manual Check-In
            </Button>
          </DialogActions>
        </Dialog>

        {/* Cancel Registration Dialog */}
        <Dialog
          open={cancelDialogOpen}
          onClose={() => !isProcessing && setCancelDialogOpen(false)}
          maxWidth="xs"
          fullWidth
        >
          <DialogTitle>Cancel Registration</DialogTitle>
          <DialogContent>
            <Typography variant="body1">
              Are you sure you want to cancel your registration for "{selectedRegistration?.event_title}"?
            </Typography>
            {selectedRegistration && selectedRegistration.payment_status === 'COMPLETED' && (
              <Alert severity="warning" sx={{ mt: 2 }}>
                This is a paid event. Refund policies may apply.
              </Alert>
            )}
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setCancelDialogOpen(false)} disabled={isProcessing}>
              No, Keep It
            </Button>
            <Button
              variant="contained"
              color="error"
              onClick={handleCancelRegistration}
              disabled={isProcessing}
              startIcon={isProcessing ? <LoadingSpinner size="sm" /> : <Cancel />}
            >
              Yes, Cancel Registration
            </Button>
          </DialogActions>
        </Dialog>
      </motion.div>
    </Box>
  )
}