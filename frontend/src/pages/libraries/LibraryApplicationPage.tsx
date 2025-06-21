import { useState, useEffect } from 'react'
import {
  Box,
  Typography,
  Grid,
  Card,
  CardContent,
  CardMedia,
  Button,
  TextField,
  Divider,
  Chip,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Alert,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Paper,
} from '@mui/material'
import {
  Person,
  LocationOn,
  AccessTime,
  Wifi,
  LocalParking,
  Restaurant,
  Check,
  Info,
  Refresh,
  School,
} from '@mui/icons-material'
import { motion } from 'framer-motion'
import { libraryService } from '../../services/libraryService'
import { authService } from '../../services/authService'
import { useAuthStore } from '../../stores/authStore'
import { Library, UserLibraryAccess } from '../../types'
import { LoadingSpinner } from '../../components/ui/loading-spinner'
import { useToast } from '../../hooks/use-toast'
import { SimplePageHeader } from '../../components/layout/SimplePageHeader'

export function LibraryApplicationPage() {
  const { toast } = useToast()
  const { user, updateUser } = useAuthStore()
  
  const [libraries, setLibraries] = useState<Library[]>([])
  const [userApplications, setUserApplications] = useState<UserLibraryAccess[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [refreshing, setRefreshing] = useState(false)
  
  // Dialog state
  const [selectedLibrary, setSelectedLibrary] = useState<Library | null>(null)
  const [applicationDialogOpen, setApplicationDialogOpen] = useState(false)
  const [applicationNotes, setApplicationNotes] = useState('')

  useEffect(() => {
    fetchData()
  }, [])

  const fetchData = async () => {
    try {
      setIsLoading(true)
      setError(null)
      
      // Fetch libraries and user applications in parallel
      const [librariesResponse, applicationsResponse] = await Promise.all([
        libraryService.getLibraries(),
        authService.getUserLibraryAccess()
      ])
      
      console.log('Libraries response:', librariesResponse)
      console.log('Applications response:', applicationsResponse)
      
      setLibraries(librariesResponse.results)
      setUserApplications(applicationsResponse.results)
    } catch (error: any) {
      console.error('Error fetching data:', error)
      setError(error.message || 'Failed to fetch data')
    } finally {
      setIsLoading(false)
    }
  }

  const handleApply = (library: Library) => {
    setSelectedLibrary(library)
    setApplicationNotes('')
    setApplicationDialogOpen(true)
  }

  const handleSubmitApplication = async () => {
    if (!selectedLibrary) return
    
    try {
      setIsSubmitting(true)
      
      await authService.applyForLibraryAccess(selectedLibrary.id, applicationNotes)
      
      toast({
        title: "Application Submitted",
        description: `Your application to ${selectedLibrary.name} has been submitted successfully.`,
        variant: "default",
      })
      
      setApplicationDialogOpen(false)
      
      // Refresh data
      fetchData()
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || 'Failed to submit application',
        variant: "destructive",
      })
    } finally {
      setIsSubmitting(false)
    }
  }

  const refreshUserStatus = async () => {
    try {
      setRefreshing(true)
      
      // Fetch updated user profile
      const updatedUser = await authService.getProfile()
      
      // Update user in store
      updateUser(updatedUser)
      
      toast({
        title: "Status Updated",
        description: updatedUser.is_approved 
          ? "Your account has been approved! You now have access to the system." 
          : "Your application is still pending approval.",
        variant: updatedUser.is_approved ? "default" : "default",
      })
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || 'Failed to refresh status',
        variant: "destructive",
      })
    } finally {
      setRefreshing(false)
    }
  }

  const getApplicationStatus = (libraryId: string) => {
    const application = userApplications.find(app => app.library === libraryId)
    if (!application) return null
    
    return {
      status: application.is_active ? 'APPROVED' : 'PENDING',
      date: application.created_at,
      id: application.id
    }
  }

  if (isLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
        <LoadingSpinner size="lg" />
      </Box>
    )
  }

  return (
    <Box sx={{ 
      minHeight: '100vh', 
      display: 'flex', 
      flexDirection: 'column',
      background: 'linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%)',
    }}>
      {/* Header */}
      <SimplePageHeader />
      
      {/* Main Content */}
      <Box sx={{ 
        flexGrow: 1, 
        display: 'flex', 
        flexDirection: 'column',
        alignItems: 'center', 
        justifyContent: 'center',
        p: 3,
        mt: 8, // Add top margin to account for the fixed header
      }}>
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          style={{ width: '100%', maxWidth: 1200 }}
        >
          <Paper elevation={3} sx={{ p: 4, borderRadius: 2, mb: 4 }}>
            <Box sx={{ textAlign: 'center', mb: 4 }}>
              <Typography
                variant="h3"
                component="h1"
                sx={{
                  fontWeight: 700,
                  background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                  backgroundClip: 'text',
                  WebkitBackgroundClip: 'text',
                  WebkitTextFillColor: 'transparent',
                  mb: 2,
                }}
              >
                Welcome to Smart Lib
              </Typography>
              
              <Typography variant="h5" gutterBottom>
                {user?.is_approved 
                  ? "Apply for Additional Libraries" 
                  : "Complete Your Registration"}
              </Typography>
              
              <Typography variant="body1" color="text.secondary" sx={{ maxWidth: 800, mx: 'auto' }}>
                {user?.is_approved 
                  ? "You already have access to the platform. You can apply for access to additional libraries below."
                  : "Your account has been created successfully, but you need to apply for access to a library to use the system. Please select a library from the list below to submit your application."}
              </Typography>
              
              {/* Only show the Check Approval Status button if the user has at least one application */}
              {userApplications.length > 0 && (
                <Box sx={{ mt: 3, display: 'flex', justifyContent: 'center' }}>
                  <Button
                    variant="outlined"
                    startIcon={<Refresh />}
                    onClick={refreshUserStatus}
                    disabled={refreshing}
                  >
                    {refreshing ? <LoadingSpinner size="sm" /> : 'Check Approval Status'}
                  </Button>
                </Box>
              )}
            </Box>
            
            {error && (
              <Alert severity="error" sx={{ mb: 3 }}>
                {error}
              </Alert>
            )}
            
            <Box sx={{ mb: 4 }}>
              <Typography variant="h6" gutterBottom>
                Your Applications
              </Typography>
              
              {userApplications.length === 0 ? (
                <Alert severity="info">
                  You haven't applied to any libraries yet. Select a library below to apply.
                </Alert>
              ) : (
                <List>
                  {userApplications.map((application) => (
                    <ListItem key={application.id} sx={{ bgcolor: 'background.paper', mb: 1, borderRadius: 1 }}>
                      <ListItemIcon>
                        <School />
                      </ListItemIcon>
                      <ListItemText
                        primary={application.library_display}
                        secondary={`Applied on: ${new Date(application.created_at).toLocaleDateString()}`}
                      />
                      <Chip
                        label={application.is_active ? 'Approved' : 'Pending'}
                        color={application.is_active ? 'success' : 'warning'}
                      />
                    </ListItem>
                  ))}
                </List>
              )}
            </Box>
            
            <Divider sx={{ mb: 4 }} />
            
            <Typography variant="h6" gutterBottom>
              Available Libraries
            </Typography>
            
            {libraries.length === 0 ? (
              <Alert severity="warning" sx={{ mb: 3 }}>
                No libraries are currently available. Please check back later.
              </Alert>
            ) : (
              <Grid container spacing={3}>
                {libraries.map((library) => {
                  const applicationStatus = getApplicationStatus(library.id)
                  
                  return (
                    <Grid item xs={12} md={6} lg={4} key={library.id}>
                      <motion.div
                        whileHover={{ y: -5, transition: { duration: 0.2 } }}
                      >
                        <Card sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
                          <CardMedia
                            component="img"
                            height="160"
                            image={library.main_image || 'https://images.pexels.com/photos/590493/pexels-photo-590493.jpeg'}
                            alt={library.name}
                          />
                          <CardContent sx={{ flexGrow: 1 }}>
                            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 1 }}>
                              <Typography variant="h6" component="div">
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
                              />
                            </Box>

                            <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                              <LocationOn fontSize="small" color="action" sx={{ mr: 0.5 }} />
                              <Typography variant="body2" color="text.secondary">
                                {library.city}, {library.address}
                              </Typography>
                            </Box>

                            <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                              <AccessTime fontSize="small" color="action" sx={{ mr: 0.5 }} />
                              <Typography variant="body2" color="text.secondary">
                                {library.is_24_hours
                                  ? '24 Hours'
                                  : `${library.opening_time} - ${library.closing_time}`}
                              </Typography>
                            </Box>

                            <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', mb: 2 }}>
                              <Chip
                                label={library.library_type.replace('_', ' ')}
                                size="small"
                                variant="outlined"
                              />
                              {library.has_wifi && (
                                <Chip
                                  icon={<Wifi fontSize="small" />}
                                  label="WiFi"
                                  size="small"
                                  variant="outlined"
                                />
                              )}
                              {library.has_parking && (
                                <Chip
                                  icon={<LocalParking fontSize="small" />}
                                  label="Parking"
                                  size="small"
                                  variant="outlined"
                                />
                              )}
                              {library.has_cafeteria && (
                                <Chip
                                  icon={<Restaurant fontSize="small" />}
                                  label="Cafeteria"
                                  size="small"
                                  variant="outlined"
                                />
                              )}
                            </Box>

                            {applicationStatus ? (
                              <Box sx={{ mt: 2 }}>
                                <Chip
                                  icon={applicationStatus.status === 'APPROVED' ? <Check /> : <Info />}
                                  label={applicationStatus.status === 'APPROVED' ? 'Approved' : 'Application Pending'}
                                  color={applicationStatus.status === 'APPROVED' ? 'success' : 'warning'}
                                  sx={{ width: '100%' }}
                                />
                              </Box>
                            ) : (
                              <Button
                                variant="contained"
                                fullWidth
                                onClick={() => handleApply(library)}
                                disabled={library.status !== 'ACTIVE'}
                              >
                                Apply for Access
                              </Button>
                            )}
                          </CardContent>
                        </Card>
                      </motion.div>
                    </Grid>
                  )
                })}
              </Grid>
            )}
            
            {user?.is_approved && (
              <Box sx={{ mt: 4, display: 'flex', justifyContent: 'center' }}>
                <Button 
                  variant="contained" 
                  color="primary"
                  onClick={() => window.location.href = '/'}
                >
                  Return to Dashboard
                </Button>
              </Box>
            )}
          </Paper>
        </motion.div>
      </Box>

      {/* Application Dialog */}
      <Dialog
        open={applicationDialogOpen}
        onClose={() => !isSubmitting && setApplicationDialogOpen(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>Apply for Library Access</DialogTitle>
        <DialogContent>
          {selectedLibrary && (
            <>
              <Typography variant="h6" gutterBottom>
                {selectedLibrary.name}
              </Typography>
              <Typography variant="body2" color="text.secondary" paragraph>
                {selectedLibrary.description || 'No description available.'}
              </Typography>
              <Typography variant="body2" paragraph>
                Please provide any additional information that might be relevant for your application.
              </Typography>
              <TextField
                label="Application Notes (Optional)"
                multiline
                rows={4}
                fullWidth
                value={applicationNotes}
                onChange={(e) => setApplicationNotes(e.target.value)}
                placeholder="Explain why you need access to this library, your study goals, etc."
                margin="normal"
              />
              <Alert severity="info" sx={{ mt: 2 }}>
                Your application will be reviewed by the library administrators. You will be notified once your application is approved.
              </Alert>
            </>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setApplicationDialogOpen(false)} disabled={isSubmitting}>
            Cancel
          </Button>
          <Button
            variant="contained"
            onClick={handleSubmitApplication}
            disabled={isSubmitting}
          >
            {isSubmitting ? <LoadingSpinner size="sm" /> : 'Submit Application'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  )
}