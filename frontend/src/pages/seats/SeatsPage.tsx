import { useState, useEffect } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import {
  Box,
  Typography,
  Grid,
  Card,
  CardContent,
  Button,
  TextField,
  InputAdornment,
  MenuItem,
  Chip,
  FormControl,
  InputLabel,
  Select,
  Pagination,
  Alert,
  FormControlLabel,
  Checkbox,
  Divider,
  IconButton,
  Paper,
  Tooltip,
} from '@mui/material'
import { DatePicker } from '@mui/x-date-pickers/DatePicker'
import { TimePicker } from '@mui/x-date-pickers/TimePicker'
import {
  Search,
  FilterList,
  EventSeat,
  PowerSettingsNew,
  Wifi,
  Monitor,
  WbSunny,
  Accessible,
  Star,
  Close,
  ChevronRight,
} from '@mui/icons-material'
import { motion } from 'framer-motion'
import { seatService } from '../../services/seatService'
import { libraryService } from '../../services/libraryService'
import { Seat, Library, LibraryFloor, LibrarySection, SeatSearchFilters } from '../../types'
import { LoadingSpinner } from '../../components/ui/loading-spinner'
import { formatDate } from '../../lib/utils'

export function SeatsPage() {
  const navigate = useNavigate()
  const location = useLocation()
  const queryParams = new URLSearchParams(location.search)
  
  const [seats, setSeats] = useState<Seat[]>([])
  const [libraries, setLibraries] = useState<Library[]>([])
  const [floors, setFloors] = useState<LibraryFloor[]>([])
  const [sections, setSections] = useState<LibrarySection[]>([])
  
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [totalPages, setTotalPages] = useState(1)
  const [currentPage, setCurrentPage] = useState(1)
  const [showFilters, setShowFilters] = useState(false)

  // Filter states
  const [filters, setFilters] = useState<SeatSearchFilters>({
    library_id: queryParams.get('library') || '',
    floor_id: queryParams.get('floor') || '',
    section_id: queryParams.get('section') || '',
    seat_type: '',
    date: new Date().toISOString().split('T')[0],
    start_time: '',
    end_time: '',
    has_power_outlet: false,
    has_ethernet: false,
    has_monitor: false,
    is_near_window: false,
    is_accessible: false,
    is_premium: false,
    min_rating: 0,
    sort_by: 'seat_number',
  })

  useEffect(() => {
    fetchLibraries()
    
    if (filters.library_id) {
      fetchFloors(filters.library_id)
    }
    
    if (filters.floor_id) {
      fetchSections(filters.floor_id)
    }
    
    fetchSeats()
  }, [currentPage])

  const fetchLibraries = async () => {
    try {
      const response = await libraryService.getLibraries()
      setLibraries(response.results)
    } catch (error: any) {
      console.error('Failed to fetch libraries:', error)
    }
  }

  const fetchFloors = async (libraryId: string) => {
    try {
      const floorsData = await libraryService.getLibraryFloors(libraryId)
      setFloors(floorsData)
    } catch (error: any) {
      console.error('Failed to fetch floors:', error)
    }
  }

  const fetchSections = async (floorId: string) => {
    try {
      const sectionsData = await libraryService.getFloorSections(floorId)
      setSections(sectionsData)
    } catch (error: any) {
      console.error('Failed to fetch sections:', error)
    }
  }

  const fetchSeats = async () => {
    try {
      setIsLoading(true)
      setError(null)

      // Build query parameters
      const params: any = {
        page: currentPage,
      }

      // Add filters to params
      Object.entries(filters).forEach(([key, value]) => {
        if (value !== '' && value !== false && value !== null && value !== undefined) {
          params[key] = value
        }
      })

      let response
      if (filters.library_id) {
        response = await seatService.getLibrarySeats(filters.library_id, params)
      } else if (filters.floor_id) {
        response = await seatService.getFloorSeats(filters.floor_id, params)
      } else if (filters.section_id) {
        response = await seatService.getSectionSeats(filters.section_id, params)
      } else {
        response = await seatService.getSeats(params)
      }

      setSeats(response.results)
      setTotalPages(Math.ceil(response.count / 20)) // Assuming 20 items per page
    } catch (error: any) {
      setError(error.message || 'Failed to fetch seats')
    } finally {
      setIsLoading(false)
    }
  }

  const handleLibraryChange = (libraryId: string) => {
    setFilters({
      ...filters,
      library_id: libraryId,
      floor_id: '',
      section_id: '',
    })
    
    if (libraryId) {
      fetchFloors(libraryId)
    } else {
      setFloors([])
      setSections([])
    }
  }

  const handleFloorChange = (floorId: string) => {
    setFilters({
      ...filters,
      floor_id: floorId,
      section_id: '',
    })
    
    if (floorId) {
      fetchSections(floorId)
    } else {
      setSections([])
    }
  }

  const handleSearch = () => {
    setCurrentPage(1)
    fetchSeats()
  }

  const handleResetFilters = () => {
    setFilters({
      library_id: '',
      floor_id: '',
      section_id: '',
      seat_type: '',
      date: new Date().toISOString().split('T')[0],
      start_time: '',
      end_time: '',
      has_power_outlet: false,
      has_ethernet: false,
      has_monitor: false,
      is_near_window: false,
      is_accessible: false,
      is_premium: false,
      min_rating: 0,
      sort_by: 'seat_number',
    })
    setFloors([])
    setSections([])
    setCurrentPage(1)
  }

  const handlePageChange = (event: React.ChangeEvent<unknown>, value: number) => {
    setCurrentPage(value)
  }

  const handleCheckboxChange = (name: keyof SeatSearchFilters) => (event: React.ChangeEvent<HTMLInputElement>) => {
    setFilters({
      ...filters,
      [name]: event.target.checked,
    })
  }

  const getSeatTypeLabel = (type: string) => {
    const types: Record<string, string> = {
      'INDIVIDUAL': 'Individual Study',
      'GROUP': 'Group Study',
      'COMPUTER': 'Computer Workstation',
      'SILENT': 'Silent Study',
      'DISCUSSION': 'Discussion Area',
      'PREMIUM': 'Premium Seat',
      'ACCESSIBLE': 'Accessible Seat',
    }
    return types[type] || type
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
            Seats
          </Typography>
          <Typography variant="body1" color="text.secondary">
            Find and book available seats across our libraries.
          </Typography>
        </Box>

        {/* Search and Filters */}
        <Card sx={{ mb: 4 }}>
          <CardContent>
            <Grid container spacing={2} alignItems="center">
              <Grid item xs={12} md={4}>
                <FormControl fullWidth>
                  <InputLabel>Library</InputLabel>
                  <Select
                    value={filters.library_id}
                    label="Library"
                    onChange={(e) => handleLibraryChange(e.target.value)}
                  >
                    <MenuItem value="">All Libraries</MenuItem>
                    {libraries.map((library) => (
                      <MenuItem key={library.id} value={library.id}>
                        {library.name}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12} md={4}>
                <FormControl fullWidth>
                  <InputLabel>Floor</InputLabel>
                  <Select
                    value={filters.floor_id}
                    label="Floor"
                    onChange={(e) => handleFloorChange(e.target.value)}
                    disabled={!filters.library_id || floors.length === 0}
                  >
                    <MenuItem value="">All Floors</MenuItem>
                    {floors.map((floor) => (
                      <MenuItem key={floor.id} value={floor.id}>
                        {floor.floor_name}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12} md={4}>
                <FormControl fullWidth>
                  <InputLabel>Section</InputLabel>
                  <Select
                    value={filters.section_id}
                    label="Section"
                    onChange={(e) => setFilters({ ...filters, section_id: e.target.value })}
                    disabled={!filters.floor_id || sections.length === 0}
                  >
                    <MenuItem value="">All Sections</MenuItem>
                    {sections.map((section) => (
                      <MenuItem key={section.id} value={section.id}>
                        {section.name}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12} md={4}>
                <FormControl fullWidth>
                  <InputLabel>Seat Type</InputLabel>
                  <Select
                    value={filters.seat_type}
                    label="Seat Type"
                    onChange={(e) => setFilters({ ...filters, seat_type: e.target.value })}
                  >
                    <MenuItem value="">All Types</MenuItem>
                    <MenuItem value="INDIVIDUAL">Individual Study</MenuItem>
                    <MenuItem value="GROUP">Group Study</MenuItem>
                    <MenuItem value="COMPUTER">Computer Workstation</MenuItem>
                    <MenuItem value="SILENT">Silent Study</MenuItem>
                    <MenuItem value="DISCUSSION">Discussion Area</MenuItem>
                    <MenuItem value="PREMIUM">Premium Seat</MenuItem>
                    <MenuItem value="ACCESSIBLE">Accessible Seat</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12} md={4}>
                <DatePicker
                  label="Date"
                  value={filters.date ? new Date(filters.date) : null}
                  onChange={(newValue) => {
                    if (newValue) {
                      setFilters({
                        ...filters,
                        date: newValue.toISOString().split('T')[0],
                      })
                    }
                  }}
                  slotProps={{ textField: { fullWidth: true } }}
                />
              </Grid>
              <Grid item xs={12} md={4}>
                <Box sx={{ display: 'flex', gap: 1 }}>
                  <Button
                    variant="outlined"
                    startIcon={<FilterList />}
                    onClick={() => setShowFilters(!showFilters)}
                    sx={{ flexGrow: 1 }}
                  >
                    {showFilters ? 'Hide Filters' : 'Show Filters'}
                  </Button>
                  <Button
                    variant="contained"
                    onClick={handleSearch}
                  >
                    Search
                  </Button>
                </Box>
              </Grid>

              {showFilters && (
                <>
                  <Grid item xs={12}>
                    <Divider sx={{ my: 2 }}>Advanced Filters</Divider>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Grid container spacing={2}>
                      <Grid item xs={6}>
                        <TimePicker
                          label="Start Time"
                          value={filters.start_time ? new Date(`2023-01-01T${filters.start_time}`) : null}
                          onChange={(newValue) => {
                            if (newValue) {
                              const timeString = newValue.toTimeString().split(' ')[0].substring(0, 5)
                              setFilters({
                                ...filters,
                                start_time: timeString,
                              })
                            }
                          }}
                          slotProps={{ textField: { fullWidth: true } }}
                        />
                      </Grid>
                      <Grid item xs={6}>
                        <TimePicker
                          label="End Time"
                          value={filters.end_time ? new Date(`2023-01-01T${filters.end_time}`) : null}
                          onChange={(newValue) => {
                            if (newValue) {
                              const timeString = newValue.toTimeString().split(' ')[0].substring(0, 5)
                              setFilters({
                                ...filters,
                                end_time: timeString,
                              })
                            }
                          }}
                          slotProps={{ textField: { fullWidth: true } }}
                        />
                      </Grid>
                    </Grid>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <FormControl fullWidth>
                      <InputLabel>Sort By</InputLabel>
                      <Select
                        value={filters.sort_by}
                        label="Sort By"
                        onChange={(e) => setFilters({ ...filters, sort_by: e.target.value as any })}
                      >
                        <MenuItem value="seat_number">Seat Number</MenuItem>
                        <MenuItem value="rating">Rating</MenuItem>
                        <MenuItem value="availability">Availability</MenuItem>
                        <MenuItem value="features">Features</MenuItem>
                      </Select>
                    </FormControl>
                  </Grid>
                  <Grid item xs={12}>
                    <Typography variant="subtitle2" gutterBottom>
                      Features
                    </Typography>
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2 }}>
                      <FormControlLabel
                        control={
                          <Checkbox
                            checked={filters.has_power_outlet}
                            onChange={handleCheckboxChange('has_power_outlet')}
                          />
                        }
                        label="Power Outlet"
                      />
                      <FormControlLabel
                        control={
                          <Checkbox
                            checked={filters.has_ethernet}
                            onChange={handleCheckboxChange('has_ethernet')}
                          />
                        }
                        label="Ethernet"
                      />
                      <FormControlLabel
                        control={
                          <Checkbox
                            checked={filters.has_monitor}
                            onChange={handleCheckboxChange('has_monitor')}
                          />
                        }
                        label="Monitor"
                      />
                      <FormControlLabel
                        control={
                          <Checkbox
                            checked={filters.is_near_window}
                            onChange={handleCheckboxChange('is_near_window')}
                          />
                        }
                        label="Near Window"
                      />
                      <FormControlLabel
                        control={
                          <Checkbox
                            checked={filters.is_accessible}
                            onChange={handleCheckboxChange('is_accessible')}
                          />
                        }
                        label="Accessible"
                      />
                      <FormControlLabel
                        control={
                          <Checkbox
                            checked={filters.is_premium}
                            onChange={handleCheckboxChange('is_premium')}
                          />
                        }
                        label="Premium"
                      />
                    </Box>
                  </Grid>
                  <Grid item xs={12} sx={{ display: 'flex', justifyContent: 'flex-end' }}>
                    <Button
                      variant="outlined"
                      color="secondary"
                      onClick={handleResetFilters}
                      startIcon={<Close />}
                    >
                      Reset Filters
                    </Button>
                  </Grid>
                </>
              )}
            </Grid>
          </CardContent>
        </Card>

        {/* Error Message */}
        {error && (
          <Alert severity="error" sx={{ mb: 3 }}>
            {error}
          </Alert>
        )}

        {/* Loading State */}
        {isLoading ? (
          <Box sx={{ display: 'flex', justifyContent: 'center', py: 8 }}>
            <LoadingSpinner size="lg" />
          </Box>
        ) : (
          <>
            {/* Seats Grid */}
            {seats.length === 0 ? (
              <Box sx={{ textAlign: 'center', py: 8 }}>
                <Typography variant="h6" color="text.secondary" gutterBottom>
                  No seats found
                </Typography>
                <Typography variant="body1" color="text.secondary">
                  Try adjusting your search or filters
                </Typography>
              </Box>
            ) : (
              <Grid container spacing={3}>
                {seats.map((seat, index) => (
                  <Grid item xs={12} sm={6} md={4} lg={3} key={seat.id}>
                    <motion.div
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ duration: 0.3, delay: index * 0.05 }}
                      whileHover={{ y: -5, transition: { duration: 0.2 } }}
                    >
                      <Card sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
                        <CardContent sx={{ flexGrow: 1 }}>
                          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 1 }}>
                            <Typography variant="h6" component="div">
                              Seat {seat.seat_number}
                            </Typography>
                            <Chip
                              label={seat.status_display}
                              size="small"
                              color={
                                seat.status === 'AVAILABLE'
                                  ? 'success'
                                  : seat.status === 'OCCUPIED' || seat.status === 'RESERVED'
                                  ? 'warning'
                                  : 'error'
                              }
                            />
                          </Box>

                          <Typography variant="body2" color="text.secondary" gutterBottom>
                            {seat.library_name} • {seat.floor_name} • {seat.section_name}
                          </Typography>

                          <Chip
                            label={seat.seat_type_display}
                            size="small"
                            variant="outlined"
                            sx={{ mb: 2 }}
                          />

                          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mb: 2 }}>
                            {seat.has_power_outlet && (
                              <Tooltip title="Power Outlet">
                                <Chip
                                  icon={<PowerSettingsNew fontSize="small" />}
                                  label="Power"
                                  size="small"
                                  variant="outlined"
                                />
                              </Tooltip>
                            )}
                            {seat.has_ethernet && (
                              <Tooltip title="Ethernet Connection">
                                <Chip
                                  icon={<Wifi fontSize="small" />}
                                  label="Ethernet"
                                  size="small"
                                  variant="outlined"
                                />
                              </Tooltip>
                            )}
                            {seat.has_monitor && (
                              <Tooltip title="External Monitor">
                                <Chip
                                  icon={<Monitor fontSize="small" />}
                                  label="Monitor"
                                  size="small"
                                  variant="outlined"
                                />
                              </Tooltip>
                            )}
                            {seat.is_near_window && (
                              <Tooltip title="Near Window">
                                <Chip
                                  icon={<WbSunny fontSize="small" />}
                                  label="Window"
                                  size="small"
                                  variant="outlined"
                                />
                              </Tooltip>
                            )}
                            {seat.is_accessible && (
                              <Tooltip title="Accessible">
                                <Chip
                                  icon={<Accessible fontSize="small" />}
                                  label="Accessible"
                                  size="small"
                                  variant="outlined"
                                />
                              </Tooltip>
                            )}
                          </Box>

                          <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                            <Star sx={{ color: 'gold', mr: 0.5 }} fontSize="small" />
                            <Typography variant="body2">
                              {seat.average_rating.toFixed(1)} ({seat.total_bookings} bookings)
                            </Typography>
                          </Box>

                          {seat.current_booking && (
                            <Alert severity="info" sx={{ mb: 2 }}>
                              Currently booked until {seat.current_booking.end_time}
                            </Alert>
                          )}
                        </CardContent>

                        <Box sx={{ p: 2, pt: 0 }}>
                          <Button
                            variant="contained"
                            fullWidth
                            disabled={!seat.is_available}
                            onClick={() => navigate(`/seats/book?seat=${seat.id}&date=${filters.date}`)}
                          >
                            {seat.is_available ? 'Book Now' : 'Unavailable'}
                          </Button>
                        </Box>
                      </Card>
                    </motion.div>
                  </Grid>
                ))}
              </Grid>
            )}

            {/* Pagination */}
            {totalPages > 1 && (
              <Box sx={{ display: 'flex', justifyContent: 'center', mt: 4 }}>
                <Pagination
                  count={totalPages}
                  page={currentPage}
                  onChange={handlePageChange}
                  color="primary"
                />
              </Box>
            )}
          </>
        )}
      </motion.div>
    </Box>
  )
}