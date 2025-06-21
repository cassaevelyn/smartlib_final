import { useState, useEffect } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import {
  Box,
  Typography,
  Grid,
  Card,
  CardContent,
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
  IconButton,
  Paper,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Tooltip,
} from '@mui/material'
import {
  EventSeat,
  AccessTime,
  LocationOn,
  QrCode,
  Logout,
  Cancel,
  CheckCircle,
  History,
  CalendarToday,
} from '@mui/icons-material'
import { motion } from 'framer-motion'
import QRCode from 'qrcode'
import { seatService } from '../../services/seatService'
import { SeatBooking } from '../../types'
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
      id={`bookings-tabpanel-${index}`}
      aria-labelledby={`bookings-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </div>
  )
}

export function MyBookingsPage() {
  const navigate = useNavigate()
  const location = useLocation()
  const { toast } = useToast()
  const queryParams = new URLSearchParams(location.search)
  
  const [tabValue, setTabValue] = useState(0)
  const [bookings, setBookings] = useState<SeatBooking[]>([])
  const [filteredBookings, setFilteredBookings] = useState<SeatBooking[]>([])
  const [selectedBooking, setSelectedBooking] = useState<SeatBooking | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  
  // Dialog states
  const [qrDialogOpen, setQrDialogOpen] = useState(false)
  const [cancelDialogOpen, setCancelDialogOpen] = useState(false)
  const [qrCodeUrl, setQrCodeUrl] = useState<string | null>(null)
  const [isProcessing, setIsProcessing] = useState(false)

  useEffect(() => {
    fetchBookings()
    
    // Handle query parameters for actions
    const action = queryParams.get('action')
    const id = queryParams.get('id')
    
    if (action && id) {
      handleQueryAction(action, id)
    }
  }, [location.search])

  useEffect(() => {
    // Filter bookings based on tab
    if (bookings.length > 0) {
      switch (tabValue) {
        case 0: // Current
          setFilteredBookings(
            bookings.filter(booking => 
              ['CONFIRMED', 'CHECKED_IN'].includes(booking.status) && 
              new Date(booking.booking_date).toDateString() === new Date().toDateString()
            )
          )
          break
        case 1: // Upcoming
          setFilteredBookings(
            bookings.filter(booking => 
              ['CONFIRMED'].includes(booking.status) && 
              new Date(booking.booking_date) > new Date()
            )
          )
          break
        case 2: // Past
          setFilteredBookings(
            bookings.filter(booking => 
              ['COMPLETED', 'CANCELLED', 'NO_SHOW', 'EXPIRED'].includes(booking.status) ||
              (booking.status === 'CHECKED_IN' && new Date(booking.booking_date) < new Date())
            )
          )
          break
        default:
          setFilteredBookings(bookings)
      }
    }
  }, [tabValue, bookings])

  const fetchBookings = async () => {
    try {
      setIsLoading(true)
      setError(null)
      
      const response = await seatService.getBookings()
      setBookings(response.results)
      
      // If there's an ID in the query params, find and select that booking
      const id = queryParams.get('id')
      if (id) {
        const booking = response.results.find(b => b.id === id)
        if (booking) {
          setSelectedBooking(booking)
        }
      }
    } catch (error: any) {
      setError(error.message || 'Failed to fetch bookings')
    } finally {
      setIsLoading(false)
    }
  }

  const handleQueryAction = async (action: string, id: string) => {
    switch (action) {
      case 'checkin':
        try {
          const booking = await seatService.getBooking(id)
          setSelectedBooking(booking)
          handleGenerateQRCode(booking)
        } catch (error: any) {
          toast({
            title: "Error",
            description: error.message || 'Failed to load booking',
            variant: "destructive",
          })
        }
        break
      case 'checkout':
        try {
          const booking = await seatService.getBooking(id)
          setSelectedBooking(booking)
          handleCheckOut(booking)
        } catch (error: any) {
          toast({
            title: "Error",
            description: error.message || 'Failed to load booking',
            variant: "destructive",
          })
        }
        break
      default:
        break
    }
    
    // Clear the query params
    navigate('/my-bookings', { replace: true })
  }

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue)
  }

  const handleGenerateQRCode = async (booking: SeatBooking) => {
    try {
      setIsProcessing(true)
      
      const response = await seatService.generateQRCode(booking.id)
      
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
    if (!selectedBooking) return
    
    try {
      setIsProcessing(true)
      
      await seatService.checkIn({
        booking_id: selectedBooking.id,
        check_in_method: 'MANUAL',
      })
      
      toast({
        title: "Check-in Successful",
        description: "You have successfully checked in to your seat.",
        variant: "default",
      })
      
      setQrDialogOpen(false)
      fetchBookings()
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

  const handleCheckOut = async (booking: SeatBooking) => {
    try {
      setIsProcessing(true)
      
      await seatService.checkOut({
        booking_id: booking.id,
        check_out_method: 'MANUAL',
      })
      
      toast({
        title: "Check-out Successful",
        description: "You have successfully checked out from your seat.",
        variant: "default",
      })
      
      fetchBookings()
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

  const handleCancelBooking = async () => {
    if (!selectedBooking) return
    
    try {
      setIsProcessing(true)
      
      await seatService.cancelBooking(selectedBooking.id)
      
      toast({
        title: "Booking Cancelled",
        description: "Your booking has been cancelled successfully.",
        variant: "default",
      })
      
      setCancelDialogOpen(false)
      fetchBookings()
    } catch (error: any) {
      toast({
        title: "Cancellation Failed",
        description: error.message || 'Failed to cancel booking',
        variant: "destructive",
      })
    } finally {
      setIsProcessing(false)
    }
  }

  const renderBookingCard = (booking: SeatBooking) => {
    return (
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        key={booking.id}
      >
        <Card sx={{ mb: 2 }}>
          <CardContent>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 1 }}>
              <Typography variant="h6">
                Seat {booking.seat_display}
              </Typography>
              <Chip
                label={booking.status_display}
                size="small"
                className={getStatusColor(booking.status)}
              />
            </Box>
            
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
              <LocationOn fontSize="small" color="action" sx={{ mr: 0.5 }} />
              <Typography variant="body2" color="text.secondary">
                {booking.library_name}
              </Typography>
            </Box>
            
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
              <CalendarToday fontSize="small" color="action" sx={{ mr: 0.5 }} />
              <Typography variant="body2" color="text.secondary">
                {formatDate(booking.booking_date)}
              </Typography>
            </Box>
            
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
              <AccessTime fontSize="small" color="action" sx={{ mr: 0.5 }} />
              <Typography variant="body2" color="text.secondary">
                {booking.start_time} - {booking.end_time} ({booking.duration_hours} hours)
              </Typography>
            </Box>
            
            <Box sx={{ display: 'flex', justifyContent: 'flex-end', gap: 1 }}>
              {booking.can_check_in && (
                <Button
                  size="small"
                  variant="outlined"
                  startIcon={<QrCode />}
                  onClick={() => {
                    setSelectedBooking(booking)
                    handleGenerateQRCode(booking)
                  }}
                >
                  Check In
                </Button>
              )}
              
              {booking.can_check_out && (
                <Button
                  size="small"
                  variant="outlined"
                  startIcon={<Logout />}
                  onClick={() => {
                    setSelectedBooking(booking)
                    handleCheckOut(booking)
                  }}
                >
                  Check Out
                </Button>
              )}
              
              {booking.status === 'CONFIRMED' && (
                <Button
                  size="small"
                  variant="outlined"
                  color="error"
                  startIcon={<Cancel />}
                  onClick={() => {
                    setSelectedBooking(booking)
                    setCancelDialogOpen(true)
                  }}
                >
                  Cancel
                </Button>
              )}
              
              <Button
                size="small"
                onClick={() => setSelectedBooking(booking)}
              >
                Details
              </Button>
            </Box>
          </CardContent>
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
            My Bookings
          </Typography>
          <Typography variant="body1" color="text.secondary">
            Manage your seat bookings and reservations.
          </Typography>
        </Box>

        <Grid container spacing={3}>
          <Grid item xs={12} md={selectedBooking ? 8 : 12}>
            <Card>
              <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
                <Tabs
                  value={tabValue}
                  onChange={handleTabChange}
                  aria-label="booking tabs"
                  variant="fullWidth"
                >
                  <Tab 
                    icon={<EventSeat />} 
                    label="Today" 
                    iconPosition="start" 
                  />
                  <Tab 
                    icon={<CalendarToday />} 
                    label="Upcoming" 
                    iconPosition="start" 
                  />
                  <Tab 
                    icon={<History />} 
                    label="Past" 
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
                ) : filteredBookings.length === 0 ? (
                  <Box sx={{ textAlign: 'center', py: 4 }}>
                    <Typography variant="body1" color="text.secondary" gutterBottom>
                      No bookings found
                    </Typography>
                    <Button
                      variant="contained"
                      onClick={() => navigate('/seats/book')}
                      sx={{ mt: 2 }}
                    >
                      Book a Seat
                    </Button>
                  </Box>
                ) : (
                  <TabPanel value={tabValue} index={0}>
                    {filteredBookings.map(renderBookingCard)}
                  </TabPanel>
                )}
                
                <TabPanel value={tabValue} index={1}>
                  {filteredBookings.map(renderBookingCard)}
                </TabPanel>
                
                <TabPanel value={tabValue} index={2}>
                  {filteredBookings.map(renderBookingCard)}
                </TabPanel>
              </Box>
            </Card>
          </Grid>
          
          {selectedBooking && (
            <Grid item xs={12} md={4}>
              <motion.div
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.3 }}
              >
                <Card>
                  <CardContent>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
                      <Typography variant="h6">
                        Booking Details
                      </Typography>
                      <IconButton size="small" onClick={() => setSelectedBooking(null)}>
                        <Cancel fontSize="small" />
                      </IconButton>
                    </Box>
                    
                    <Divider sx={{ mb: 2 }} />
                    
                    <List>
                      <ListItem>
                        <ListItemIcon>
                          <EventSeat />
                        </ListItemIcon>
                        <ListItemText
                          primary="Seat"
                          secondary={selectedBooking.seat_display}
                        />
                      </ListItem>
                      
                      <ListItem>
                        <ListItemIcon>
                          <LocationOn />
                        </ListItemIcon>
                        <ListItemText
                          primary="Location"
                          secondary={selectedBooking.library_name}
                        />
                      </ListItem>
                      
                      <ListItem>
                        <ListItemIcon>
                          <CalendarToday />
                        </ListItemIcon>
                        <ListItemText
                          primary="Date"
                          secondary={formatDate(selectedBooking.booking_date)}
                        />
                      </ListItem>
                      
                      <ListItem>
                        <ListItemIcon>
                          <AccessTime />
                        </ListItemIcon>
                        <ListItemText
                          primary="Time"
                          secondary={`${selectedBooking.start_time} - ${selectedBooking.end_time}`}
                        />
                      </ListItem>
                      
                      <ListItem>
                        <ListItemText
                          primary="Status"
                          secondary={
                            <Chip
                              label={selectedBooking.status_display}
                              size="small"
                              className={getStatusColor(selectedBooking.status)}
                              sx={{ mt: 0.5 }}
                            />
                          }
                        />
                      </ListItem>
                      
                      <ListItem>
                        <ListItemText
                          primary="Booking Code"
                          secondary={selectedBooking.booking_code}
                        />
                      </ListItem>
                      
                      {selectedBooking.purpose && (
                        <ListItem>
                          <ListItemText
                            primary="Purpose"
                            secondary={selectedBooking.purpose}
                          />
                        </ListItem>
                      )}
                      
                      {selectedBooking.special_requirements && (
                        <ListItem>
                          <ListItemText
                            primary="Special Requirements"
                            secondary={selectedBooking.special_requirements}
                          />
                        </ListItem>
                      )}
                      
                      {selectedBooking.notes && (
                        <ListItem>
                          <ListItemText
                            primary="Notes"
                            secondary={selectedBooking.notes}
                          />
                        </ListItem>
                      )}
                    </List>
                    
                    <Box sx={{ display: 'flex', justifyContent: 'center', gap: 2, mt: 2 }}>
                      {selectedBooking.can_check_in && (
                        <Button
                          variant="contained"
                          startIcon={<QrCode />}
                          onClick={() => handleGenerateQRCode(selectedBooking)}
                          disabled={isProcessing}
                        >
                          Check In
                        </Button>
                      )}
                      
                      {selectedBooking.can_check_out && (
                        <Button
                          variant="contained"
                          startIcon={<Logout />}
                          onClick={() => handleCheckOut(selectedBooking)}
                          disabled={isProcessing}
                        >
                          Check Out
                        </Button>
                      )}
                      
                      {selectedBooking.status === 'CONFIRMED' && (
                        <Button
                          variant="outlined"
                          color="error"
                          startIcon={<Cancel />}
                          onClick={() => setCancelDialogOpen(true)}
                          disabled={isProcessing}
                        >
                          Cancel
                        </Button>
                      )}
                    </Box>
                  </CardContent>
                </Card>
              </motion.div>
            </Grid>
          )}
        </Grid>

        {/* QR Code Dialog */}
        <Dialog
          open={qrDialogOpen}
          onClose={() => !isProcessing && setQrDialogOpen(false)}
          maxWidth="xs"
          fullWidth
        >
          <DialogTitle>Check-In QR Code</DialogTitle>
          <DialogContent>
            <Box sx={{ textAlign: 'center', py: 2 }}>
              {qrCodeUrl ? (
                <img src={qrCodeUrl} alt="Check-in QR Code" style={{ width: '100%', maxWidth: 250 }} />
              ) : (
                <LoadingSpinner size="lg" />
              )}
              <Typography variant="body1" sx={{ mt: 2 }}>
                Scan this QR code at the library to check in to your seat.
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
              startIcon={isProcessing ? <LoadingSpinner size="sm" /> : <CheckCircle />}
            >
              Manual Check-In
            </Button>
          </DialogActions>
        </Dialog>

        {/* Cancel Booking Dialog */}
        <Dialog
          open={cancelDialogOpen}
          onClose={() => !isProcessing && setCancelDialogOpen(false)}
          maxWidth="xs"
          fullWidth
        >
          <DialogTitle>Cancel Booking</DialogTitle>
          <DialogContent>
            <Typography variant="body1">
              Are you sure you want to cancel this booking?
            </Typography>
            {selectedBooking && new Date(selectedBooking.booking_date).getTime() - new Date().getTime() < 2 * 60 * 60 * 1000 && (
              <Alert severity="warning" sx={{ mt: 2 }}>
                This is a late cancellation (less than 2 hours before start time). You may incur penalty points.
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
              onClick={handleCancelBooking}
              disabled={isProcessing}
              startIcon={isProcessing ? <LoadingSpinner size="sm" /> : <Cancel />}
            >
              Yes, Cancel Booking
            </Button>
          </DialogActions>
        </Dialog>
      </motion.div>
    </Box>
  )
}