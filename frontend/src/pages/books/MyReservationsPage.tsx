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
  TextField,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
} from '@mui/material'
import {
  MenuBook,
  CalendarToday,
  AccessTime,
  LocalLibrary,
  Cancel,
  Refresh,
  History,
  CheckCircle,
  Visibility,
  Computer,
} from '@mui/icons-material'
import { motion } from 'framer-motion'
import { bookService } from '../../services/bookService'
import { BookReservation } from '../../types'
import { LoadingSpinner } from '../../components/ui/loading-spinner'
import { useToast } from '../../hooks/use-toast'
import { formatDate, formatRelativeTime, getStatusColor } from '../../lib/utils'

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
      id={`reservations-tabpanel-${index}`}
      aria-labelledby={`reservations-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </div>
  )
}

export function MyReservationsPage() {
  const navigate = useNavigate()
  const { toast } = useToast()
  
  const [tabValue, setTabValue] = useState(0)
  const [reservations, setReservations] = useState<BookReservation[]>([])
  const [filteredReservations, setFilteredReservations] = useState<BookReservation[]>([])
  const [selectedReservation, setSelectedReservation] = useState<BookReservation | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  
  // Dialog states
  const [cancelDialogOpen, setCancelDialogOpen] = useState(false)
  const [renewDialogOpen, setRenewDialogOpen] = useState(false)
  const [digitalAccessDialogOpen, setDigitalAccessDialogOpen] = useState(false)
  const [accessPassword, setAccessPassword] = useState('')
  const [isProcessing, setIsProcessing] = useState(false)

  useEffect(() => {
    fetchReservations()
  }, [])

  useEffect(() => {
    // Filter reservations based on tab
    if (reservations.length > 0) {
      switch (tabValue) {
        case 0: // Active
          setFilteredReservations(
            reservations.filter(reservation => 
              ['PENDING', 'CONFIRMED', 'READY_FOR_PICKUP', 'CHECKED_OUT'].includes(reservation.status)
            )
          )
          break
        case 1: // History
          setFilteredReservations(
            reservations.filter(reservation => 
              ['RETURNED', 'CANCELLED', 'EXPIRED'].includes(reservation.status)
            )
          )
          break
        case 2: // Overdue
          setFilteredReservations(
            reservations.filter(reservation => 
              reservation.status === 'OVERDUE' || 
              (reservation.status === 'CHECKED_OUT' && reservation.is_overdue)
            )
          )
          break
        default:
          setFilteredReservations(reservations)
      }
    }
  }, [tabValue, reservations])

  const fetchReservations = async () => {
    try {
      setIsLoading(true)
      setError(null)
      
      const response = await bookService.getReservations()
      setReservations(response.results)
    } catch (error: any) {
      setError(error.message || 'Failed to fetch reservations')
    } finally {
      setIsLoading(false)
    }
  }

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue)
  }

  const handleCancelReservation = async () => {
    if (!selectedReservation) return
    
    try {
      setIsProcessing(true)
      
      await bookService.cancelReservation(selectedReservation.id)
      
      toast({
        title: "Reservation Cancelled",
        description: "Your reservation has been cancelled successfully.",
        variant: "default",
      })
      
      setCancelDialogOpen(false)
      fetchReservations()
    } catch (error: any) {
      toast({
        title: "Cancellation Failed",
        description: error.message || 'Failed to cancel reservation',
        variant: "destructive",
      })
    } finally {
      setIsProcessing(false)
    }
  }

  const handleRenewReservation = async () => {
    if (!selectedReservation) return
    
    try {
      setIsProcessing(true)
      
      await bookService.renewReservation(selectedReservation.id)
      
      toast({
        title: "Reservation Renewed",
        description: "Your reservation has been renewed successfully.",
        variant: "default",
      })
      
      setRenewDialogOpen(false)
      fetchReservations()
    } catch (error: any) {
      toast({
        title: "Renewal Failed",
        description: error.message || 'Failed to renew reservation',
        variant: "destructive",
      })
    } finally {
      setIsProcessing(false)
    }
  }

  const handleDigitalAccess = async () => {
    if (!selectedReservation) return
    
    try {
      setIsProcessing(true)
      
      const response = await bookService.getDigitalAccess(
        selectedReservation.id,
        accessPassword
      )
      
      toast({
        title: "Access Granted",
        description: "Digital access has been granted. You can now view the book.",
        variant: "default",
      })
      
      setDigitalAccessDialogOpen(false)
      
      // In a real app, this would redirect to a digital reader or provide a download link
      window.open(response.book_url, '_blank')
      
      fetchReservations()
    } catch (error: any) {
      toast({
        title: "Access Failed",
        description: error.message || 'Failed to access digital book',
        variant: "destructive",
      })
    } finally {
      setIsProcessing(false)
    }
  }

  const renderReservationCard = (reservation: BookReservation) => {
    return (
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        key={reservation.id}
      >
        <Card sx={{ mb: 3, display: 'flex', height: '100%' }}>
          <CardMedia
            component="img"
            sx={{ width: 120 }}
            image={reservation.book_cover || 'https://images.pexels.com/photos/159866/books-book-pages-read-literature-159866.jpeg'}
            alt={reservation.book_title}
          />
          <Box sx={{ display: 'flex', flexDirection: 'column', width: '100%' }}>
            <CardContent sx={{ flex: '1 0 auto' }}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 1 }}>
                <Typography variant="h6" component="div">
                  {reservation.book_title}
                </Typography>
                <Chip
                  label={reservation.status_display}
                  size="small"
                  className={getStatusColor(reservation.status)}
                />
              </Box>
              
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <MenuBook fontSize="small" color="action" sx={{ mr: 0.5 }} />
                <Typography variant="body2" color="text.secondary">
                  {reservation.reservation_type_display}
                </Typography>
              </Box>
              
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <LocalLibrary fontSize="small" color="action" sx={{ mr: 0.5 }} />
                <Typography variant="body2" color="text.secondary">
                  {reservation.library_name || 'Digital Access'}
                </Typography>
              </Box>
              
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <CalendarToday fontSize="small" color="action" sx={{ mr: 0.5 }} />
                <Typography variant="body2" color="text.secondary">
                  {reservation.reservation_date ? formatDate(reservation.reservation_date) : 'N/A'}
                </Typography>
              </Box>
              
              {reservation.due_date && (
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                  <AccessTime fontSize="small" color="action" sx={{ mr: 0.5 }} />
                  <Typography 
                    variant="body2" 
                    color={reservation.is_overdue ? 'error.main' : 'text.secondary'}
                  >
                    Due: {formatDate(reservation.due_date)}
                    {reservation.days_until_due !== undefined && reservation.days_until_due > 0 && (
                      ` (${reservation.days_until_due} days left)`
                    )}
                    {reservation.is_overdue && ' - OVERDUE'}
                  </Typography>
                </Box>
              )}
              
              <Box sx={{ display: 'flex', justifyContent: 'flex-end', gap: 1, mt: 2 }}>
                {reservation.status === 'CHECKED_OUT' && reservation.can_renew && (
                  <Button
                    size="small"
                    variant="outlined"
                    startIcon={<Refresh />}
                    onClick={() => {
                      setSelectedReservation(reservation)
                      setRenewDialogOpen(true)
                    }}
                  >
                    Renew
                  </Button>
                )}
                
                {reservation.status === 'CHECKED_OUT' && reservation.reservation_type === 'DIGITAL' && (
                  <Button
                    size="small"
                    variant="outlined"
                    startIcon={<Computer />}
                    onClick={() => {
                      setSelectedReservation(reservation)
                      setDigitalAccessDialogOpen(true)
                    }}
                  >
                    Access
                  </Button>
                )}
                
                {['PENDING', 'CONFIRMED', 'READY_FOR_PICKUP'].includes(reservation.status) && (
                  <Button
                    size="small"
                    variant="outlined"
                    color="error"
                    startIcon={<Cancel />}
                    onClick={() => {
                      setSelectedReservation(reservation)
                      setCancelDialogOpen(true)
                    }}
                  >
                    Cancel
                  </Button>
                )}
                
                <Button
                  size="small"
                  startIcon={<Visibility />}
                  onClick={() => navigate(`/books/${reservation.book}`)}
                >
                  View Book
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
            My Reservations
          </Typography>
          <Typography variant="body1" color="text.secondary">
            Manage your book reservations and loans.
          </Typography>
        </Box>

        <Card>
          <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
            <Tabs
              value={tabValue}
              onChange={handleTabChange}
              aria-label="reservation tabs"
              variant="fullWidth"
            >
              <Tab 
                icon={<MenuBook />} 
                label="Active" 
                iconPosition="start" 
              />
              <Tab 
                icon={<History />} 
                label="History" 
                iconPosition="start" 
              />
              <Tab 
                icon={<AccessTime />} 
                label="Overdue" 
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
            ) : filteredReservations.length === 0 ? (
              <Box sx={{ textAlign: 'center', py: 4 }}>
                <Typography variant="body1" color="text.secondary" gutterBottom>
                  No reservations found
                </Typography>
                <Button
                  variant="contained"
                  onClick={() => navigate('/books')}
                  sx={{ mt: 2 }}
                >
                  Browse Books
                </Button>
              </Box>
            ) : (
              <>
                <TabPanel value={tabValue} index={0}>
                  <Grid container spacing={2}>
                    {filteredReservations.map((reservation) => (
                      <Grid item xs={12} key={reservation.id}>
                        {renderReservationCard(reservation)}
                      </Grid>
                    ))}
                  </Grid>
                </TabPanel>
                
                <TabPanel value={tabValue} index={1}>
                  <Grid container spacing={2}>
                    {filteredReservations.map((reservation) => (
                      <Grid item xs={12} key={reservation.id}>
                        {renderReservationCard(reservation)}
                      </Grid>
                    ))}
                  </Grid>
                </TabPanel>
                
                <TabPanel value={tabValue} index={2}>
                  <Grid container spacing={2}>
                    {filteredReservations.length > 0 ? (
                      filteredReservations.map((reservation) => (
                        <Grid item xs={12} key={reservation.id}>
                          {renderReservationCard(reservation)}
                        </Grid>
                      ))
                    ) : (
                      <Grid item xs={12}>
                        <Alert severity="success">
                          You have no overdue books. Great job!
                        </Alert>
                      </Grid>
                    )}
                  </Grid>
                </TabPanel>
              </>
            )}
          </Box>
        </Card>

        {/* Cancel Dialog */}
        <Dialog
          open={cancelDialogOpen}
          onClose={() => !isProcessing && setCancelDialogOpen(false)}
          maxWidth="xs"
          fullWidth
        >
          <DialogTitle>Cancel Reservation</DialogTitle>
          <DialogContent>
            <Typography variant="body1">
              Are you sure you want to cancel your reservation for "{selectedReservation?.book_title}"?
            </Typography>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setCancelDialogOpen(false)} disabled={isProcessing}>
              No, Keep It
            </Button>
            <Button
              variant="contained"
              color="error"
              onClick={handleCancelReservation}
              disabled={isProcessing}
              startIcon={isProcessing ? <LoadingSpinner size="sm" /> : <Cancel />}
            >
              Yes, Cancel Reservation
            </Button>
          </DialogActions>
        </Dialog>

        {/* Renew Dialog */}
        <Dialog
          open={renewDialogOpen}
          onClose={() => !isProcessing && setRenewDialogOpen(false)}
          maxWidth="xs"
          fullWidth
        >
          <DialogTitle>Renew Reservation</DialogTitle>
          <DialogContent>
            <Typography variant="body1">
              Are you sure you want to renew your reservation for "{selectedReservation?.book_title}"?
            </Typography>
            {selectedReservation && (
              <Box sx={{ mt: 2 }}>
                <Typography variant="body2">
                  Current due date: {formatDate(selectedReservation.due_date || '')}
                </Typography>
                <Typography variant="body2">
                  Renewals used: {selectedReservation.renewal_count} of {selectedReservation.max_renewals}
                </Typography>
              </Box>
            )}
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setRenewDialogOpen(false)} disabled={isProcessing}>
              Cancel
            </Button>
            <Button
              variant="contained"
              onClick={handleRenewReservation}
              disabled={isProcessing}
              startIcon={isProcessing ? <LoadingSpinner size="sm" /> : <Refresh />}
            >
              Renew Reservation
            </Button>
          </DialogActions>
        </Dialog>

        {/* Digital Access Dialog */}
        <Dialog
          open={digitalAccessDialogOpen}
          onClose={() => !isProcessing && setDigitalAccessDialogOpen(false)}
          maxWidth="sm"
          fullWidth
        >
          <DialogTitle>Digital Book Access</DialogTitle>
          <DialogContent>
            <Typography variant="body1" paragraph>
              Enter your access password to view "{selectedReservation?.book_title}".
            </Typography>
            <TextField
              label="Access Password"
              type="password"
              fullWidth
              value={accessPassword}
              onChange={(e) => setAccessPassword(e.target.value)}
              margin="normal"
            />
            {selectedReservation && (
              <Alert severity="info" sx={{ mt: 2 }}>
                Your digital access will expire on {formatDate(selectedReservation.digital_access_expires_at || '')}. 
                You have used {selectedReservation.access_count} of {selectedReservation.max_access_count} allowed accesses.
              </Alert>
            )}
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setDigitalAccessDialogOpen(false)} disabled={isProcessing}>
              Cancel
            </Button>
            <Button
              variant="contained"
              onClick={handleDigitalAccess}
              disabled={isProcessing || !accessPassword}
              startIcon={isProcessing ? <LoadingSpinner size="sm" /> : <Computer />}
            >
              Access Digital Book
            </Button>
          </DialogActions>
        </Dialog>
      </motion.div>
    </Box>
  )
}