import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
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
  Divider,
  IconButton,
} from '@mui/material'
import { DatePicker } from '@mui/x-date-pickers/DatePicker'
import {
  Search,
  FilterList,
  Close,
} from '@mui/icons-material'
import { motion } from 'framer-motion'
import { eventService } from '../../services/eventService'
import { libraryService } from '../../services/libraryService'
import { Event, EventSearchFilters, PaginatedResponse } from '../../types'
import { EventCard } from '../../components/events/EventCard'
import { LoadingSpinner } from '../../components/ui/loading-spinner'

export function EventsPage() {
  const navigate = useNavigate()
  const [events, setEvents] = useState<Event[]>([])
  const [categories, setCategories] = useState<any[]>([])
  const [libraries, setLibraries] = useState<any[]>([])
  
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [totalPages, setTotalPages] = useState(1)
  const [currentPage, setCurrentPage] = useState(1)
  const [showFilters, setShowFilters] = useState(false)

  // Filter states
  const [filters, setFilters] = useState<EventSearchFilters>({
    query: '',
    category_id: '',
    event_type: '',
    library_id: '',
    start_date_from: '',
    start_date_to: '',
    is_online: undefined,
    is_free: undefined,
    has_certificate: undefined,
    registration_open: undefined,
    sort_by: 'start_date',
  })

  useEffect(() => {
    fetchEvents()
    fetchCategories()
    fetchLibraries()
  }, [currentPage])

  const fetchEvents = async () => {
    try {
      setIsLoading(true)
      setError(null)

      // Build query parameters
      const params: any = {
        page: currentPage,
      }

      // Add filters to params
      Object.entries(filters).forEach(([key, value]) => {
        if (value !== '' && value !== undefined) {
          params[key] = value
        }
      })

      let response: PaginatedResponse<Event>
      
      if (Object.keys(params).length > 1) {
        // If we have filters beyond just the page, use search endpoint
        response = await eventService.searchEvents(filters)
      } else {
        // Otherwise use the regular endpoint
        response = await eventService.getEvents(params)
      }

      setEvents(response.results)
      setTotalPages(Math.ceil(response.count / 20)) // Assuming 20 items per page
    } catch (error: any) {
      setError(error.message || 'Failed to fetch events')
    } finally {
      setIsLoading(false)
    }
  }

  const fetchCategories = async () => {
    try {
      const response = await eventService.getCategories()
      setCategories(response.results)
    } catch (error: any) {
      console.error('Failed to fetch categories:', error)
    }
  }

  const fetchLibraries = async () => {
    try {
      const response = await libraryService.getLibraries()
      setLibraries(response.results)
    } catch (error: any) {
      console.error('Failed to fetch libraries:', error)
    }
  }

  const handleSearch = () => {
    setCurrentPage(1)
    fetchEvents()
  }

  const handleResetFilters = () => {
    setFilters({
      query: '',
      category_id: '',
      event_type: '',
      library_id: '',
      start_date_from: '',
      start_date_to: '',
      is_online: undefined,
      is_free: undefined,
      has_certificate: undefined,
      registration_open: undefined,
      sort_by: 'start_date',
    })
    setCurrentPage(1)
  }

  const handlePageChange = (event: React.ChangeEvent<unknown>, value: number) => {
    setCurrentPage(value)
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
            Events
          </Typography>
          <Typography variant="body1" color="text.secondary">
            Discover and register for upcoming events.
          </Typography>
        </Box>

        {/* Search and Filters */}
        <Card sx={{ mb: 4 }}>
          <CardContent>
            <Grid container spacing={2} alignItems="center">
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Search Events"
                  value={filters.query}
                  onChange={(e) => setFilters({ ...filters, query: e.target.value })}
                  onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
                  InputProps={{
                    startAdornment: (
                      <InputAdornment position="start">
                        <Search />
                      </InputAdornment>
                    ),
                  }}
                />
              </Grid>
              <Grid item xs={12} md={3}>
                <FormControl fullWidth>
                  <InputLabel>Category</InputLabel>
                  <Select
                    value={filters.category_id}
                    label="Category"
                    onChange={(e) => setFilters({ ...filters, category_id: e.target.value })}
                  >
                    <MenuItem value="">All Categories</MenuItem>
                    {categories.map((category) => (
                      <MenuItem key={category.id} value={category.id}>
                        {category.name}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12} md={3}>
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
                  <Grid item xs={12} md={3}>
                    <FormControl fullWidth>
                      <InputLabel>Event Type</InputLabel>
                      <Select
                        value={filters.event_type}
                        label="Event Type"
                        onChange={(e) => setFilters({ ...filters, event_type: e.target.value })}
                      >
                        <MenuItem value="">All Types</MenuItem>
                        <MenuItem value="WORKSHOP">Workshop</MenuItem>
                        <MenuItem value="SEMINAR">Seminar</MenuItem>
                        <MenuItem value="LECTURE">Lecture</MenuItem>
                        <MenuItem value="CONFERENCE">Conference</MenuItem>
                        <MenuItem value="TRAINING">Training Session</MenuItem>
                        <MenuItem value="BOOK_CLUB">Book Club</MenuItem>
                        <MenuItem value="STUDY_GROUP">Study Group</MenuItem>
                        <MenuItem value="EXAM_PREP">Exam Preparation</MenuItem>
                        <MenuItem value="NETWORKING">Networking Event</MenuItem>
                        <MenuItem value="CULTURAL">Cultural Event</MenuItem>
                        <MenuItem value="COMPETITION">Competition</MenuItem>
                        <MenuItem value="ORIENTATION">Orientation</MenuItem>
                      </Select>
                    </FormControl>
                  </Grid>
                  <Grid item xs={12} md={3}>
                    <FormControl fullWidth>
                      <InputLabel>Library</InputLabel>
                      <Select
                        value={filters.library_id}
                        label="Library"
                        onChange={(e) => setFilters({ ...filters, library_id: e.target.value })}
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
                  <Grid item xs={12} md={3}>
                    <DatePicker
                      label="Start Date From"
                      value={filters.start_date_from ? new Date(filters.start_date_from) : null}
                      onChange={(newValue) => {
                        if (newValue) {
                          setFilters({
                            ...filters,
                            start_date_from: newValue.toISOString().split('T')[0],
                          })
                        }
                      }}
                      slotProps={{ textField: { fullWidth: true } }}
                    />
                  </Grid>
                  <Grid item xs={12} md={3}>
                    <DatePicker
                      label="Start Date To"
                      value={filters.start_date_to ? new Date(filters.start_date_to) : null}
                      onChange={(newValue) => {
                        if (newValue) {
                          setFilters({
                            ...filters,
                            start_date_to: newValue.toISOString().split('T')[0],
                          })
                        }
                      }}
                      slotProps={{ textField: { fullWidth: true } }}
                    />
                  </Grid>
                  <Grid item xs={12} md={3}>
                    <FormControl fullWidth>
                      <InputLabel>Online Events</InputLabel>
                      <Select
                        value={filters.is_online === undefined ? '' : filters.is_online.toString()}
                        label="Online Events"
                        onChange={(e) => {
                          const value = e.target.value
                          setFilters({ 
                            ...filters, 
                            is_online: value === '' ? undefined : value === 'true'
                          })
                        }}
                      >
                        <MenuItem value="">All Events</MenuItem>
                        <MenuItem value="true">Online Only</MenuItem>
                        <MenuItem value="false">In-Person Only</MenuItem>
                      </Select>
                    </FormControl>
                  </Grid>
                  <Grid item xs={12} md={3}>
                    <FormControl fullWidth>
                      <InputLabel>Free Events</InputLabel>
                      <Select
                        value={filters.is_free === undefined ? '' : filters.is_free.toString()}
                        label="Free Events"
                        onChange={(e) => {
                          const value = e.target.value
                          setFilters({ 
                            ...filters, 
                            is_free: value === '' ? undefined : value === 'true'
                          })
                        }}
                      >
                        <MenuItem value="">All Events</MenuItem>
                        <MenuItem value="true">Free Only</MenuItem>
                        <MenuItem value="false">Paid Only</MenuItem>
                      </Select>
                    </FormControl>
                  </Grid>
                  <Grid item xs={12} md={3}>
                    <FormControl fullWidth>
                      <InputLabel>Has Certificate</InputLabel>
                      <Select
                        value={filters.has_certificate === undefined ? '' : filters.has_certificate.toString()}
                        label="Has Certificate"
                        onChange={(e) => {
                          const value = e.target.value
                          setFilters({ 
                            ...filters, 
                            has_certificate: value === '' ? undefined : value === 'true'
                          })
                        }}
                      >
                        <MenuItem value="">All Events</MenuItem>
                        <MenuItem value="true">With Certificate</MenuItem>
                        <MenuItem value="false">Without Certificate</MenuItem>
                      </Select>
                    </FormControl>
                  </Grid>
                  <Grid item xs={12} md={3}>
                    <FormControl fullWidth>
                      <InputLabel>Registration Status</InputLabel>
                      <Select
                        value={filters.registration_open === undefined ? '' : filters.registration_open.toString()}
                        label="Registration Status"
                        onChange={(e) => {
                          const value = e.target.value
                          setFilters({ 
                            ...filters, 
                            registration_open: value === '' ? undefined : value === 'true'
                          })
                        }}
                      >
                        <MenuItem value="">All Events</MenuItem>
                        <MenuItem value="true">Registration Open</MenuItem>
                        <MenuItem value="false">Registration Closed</MenuItem>
                      </Select>
                    </FormControl>
                  </Grid>
                  <Grid item xs={12} md={3}>
                    <FormControl fullWidth>
                      <InputLabel>Sort By</InputLabel>
                      <Select
                        value={filters.sort_by}
                        label="Sort By"
                        onChange={(e) => setFilters({ ...filters, sort_by: e.target.value as any })}
                      >
                        <MenuItem value="start_date">Start Date</MenuItem>
                        <MenuItem value="title">Title</MenuItem>
                        <MenuItem value="registration_deadline">Registration Deadline</MenuItem>
                        <MenuItem value="popularity">Popularity</MenuItem>
                        <MenuItem value="rating">Rating</MenuItem>
                      </Select>
                    </FormControl>
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
            {/* Events Grid */}
            {events.length === 0 ? (
              <Box sx={{ textAlign: 'center', py: 8 }}>
                <Typography variant="h6" color="text.secondary" gutterBottom>
                  No events found
                </Typography>
                <Typography variant="body1" color="text.secondary">
                  Try adjusting your search or filters
                </Typography>
              </Box>
            ) : (
              <Grid container spacing={3}>
                {events.map((event) => (
                  <Grid item xs={12} sm={6} md={4} key={event.id}>
                    <EventCard event={event} />
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