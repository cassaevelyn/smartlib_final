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
  Chip,
  Alert,
  Rating,
  Divider,
} from '@mui/material'
import {
  LocationOn,
  AccessTime,
  Wifi,
  LocalParking,
  Restaurant,
  ChevronRight,
  Check,
} from '@mui/icons-material'
import { motion } from 'framer-motion'
import { authService } from '../../services/authService'
import { libraryService } from '../../services/libraryService'
import { Library, UserLibraryAccess } from '../../types'
import { LoadingSpinner } from '../../components/ui/loading-spinner'
import { formatDate } from '../../lib/utils'

export function MyLibrariesPage() {
  const navigate = useNavigate()
  const [userLibraries, setUserLibraries] = useState<UserLibraryAccess[]>([])
  const [libraryDetails, setLibraryDetails] = useState<Record<string, Library>>({})
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetchUserLibraries()
  }, [])

  const fetchUserLibraries = async () => {
    try {
      setIsLoading(true)
      setError(null)
      
      // Get user's library access
      const response = await authService.getUserLibraryAccess()
      
      // Filter for active (approved) libraries only
      const approvedLibraries = response.results.filter(access => access.is_active)
      setUserLibraries(approvedLibraries)
      
      // Fetch details for each library
      const libraryIds = approvedLibraries.map(access => access.library)
      const libraryDetailsMap: Record<string, Library> = {}
      
      // Fetch details for each library (in a real app, we might have a batch endpoint)
      for (const libraryId of libraryIds) {
        try {
          const libraryDetail = await libraryService.getLibrary(libraryId)
          libraryDetailsMap[libraryId] = libraryDetail
        } catch (error) {
          console.error(`Failed to fetch details for library ${libraryId}:`, error)
        }
      }
      
      setLibraryDetails(libraryDetailsMap)
    } catch (error: any) {
      console.error('Failed to fetch user libraries:', error)
      setError(error.message || 'Failed to fetch your libraries')
    } finally {
      setIsLoading(false)
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
            My Libraries
          </Typography>
          <Typography variant="body1" color="text.secondary">
            Libraries you have access to.
          </Typography>
        </Box>

        {error && (
          <Alert severity="error" sx={{ mb: 3 }}>
            {error}
          </Alert>
        )}

        {userLibraries.length === 0 ? (
          <Box sx={{ textAlign: 'center', py: 8 }}>
            <Typography variant="h6" color="text.secondary" gutterBottom>
              You don't have access to any libraries yet
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              Apply for access to libraries to start using the system
            </Typography>
            <Button
              variant="contained"
              onClick={() => navigate('/libraries')}
            >
              Browse Libraries
            </Button>
          </Box>
        ) : (
          <>
            <Grid container spacing={3}>
              {userLibraries.map((access, index) => {
                const library = libraryDetails[access.library]
                
                // If we don't have library details yet, show a placeholder
                if (!library) {
                  return (
                    <Grid item xs={12} md={6} lg={4} key={access.id}>
                      <Card sx={{ height: '100%' }}>
                        <CardContent>
                          <Typography variant="h6">
                            {access.library_display}
                          </Typography>
                          <Typography variant="body2" color="text.secondary">
                            Loading library details...
                          </Typography>
                          <Box sx={{ mt: 2 }}>
                            <Chip
                              icon={<Check />}
                              label="Access Granted"
                              color="success"
                            />
                          </Box>
                        </CardContent>
                      </Card>
                    </Grid>
                  )
                }
                
                return (
                  <Grid item xs={12} md={6} lg={4} key={access.id}>
                    <motion.div
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ duration: 0.3, delay: index * 0.05 }}
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

                          <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                            <Rating
                              value={library.average_rating}
                              precision={0.5}
                              size="small"
                              readOnly
                            />
                            <Typography variant="body2" color="text.secondary" sx={{ ml: 1 }}>
                              ({library.total_reviews})
                            </Typography>
                          </Box>

                          <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', mb: 2 }}>
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

                          <Divider sx={{ my: 1 }} />
                          
                          <Box sx={{ mt: 1 }}>
                            <Typography variant="body2" color="text.secondary">
                              Access Type: {access.access_type_display}
                            </Typography>
                            <Typography variant="body2" color="text.secondary">
                              Granted: {formatDate(access.granted_at)}
                            </Typography>
                            {access.expires_at && (
                              <Typography variant="body2" color="text.secondary">
                                Expires: {formatDate(access.expires_at)}
                              </Typography>
                            )}
                          </Box>

                          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mt: 2 }}>
                            <Chip
                              icon={<Check />}
                              label="Access Granted"
                              color="success"
                              size="small"
                            />
                            <Button
                              size="small"
                              endIcon={<ChevronRight />}
                              onClick={() => navigate(`/libraries/${library.id}`)}
                            >
                              Details
                            </Button>
                          </Box>
                        </CardContent>
                      </Card>
                    </motion.div>
                  </Grid>
                )
              })}
            </Grid>
            
            <Box sx={{ mt: 4, display: 'flex', justifyContent: 'center' }}>
              <Button
                variant="outlined"
                onClick={() => navigate('/libraries')}
              >
                Browse All Libraries
              </Button>
            </Box>
          </>
        )}
      </motion.div>
    </Box>
  )
}