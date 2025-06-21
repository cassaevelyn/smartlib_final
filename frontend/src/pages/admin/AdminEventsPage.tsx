import { useState, useEffect } from 'react'
import {
  Box,
  Typography,
  Card,
  CardContent,
  Button,
  TextField,
  InputAdornment,
  Chip,
  Divider,
  Alert,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  IconButton,
  Tooltip,
  MenuItem,
  Grid,
} from '@mui/material'
import { DataGrid, GridColDef, GridRenderCellParams, GridToolbar } from '@mui/x-data-grid'
import {
  Search,
  Event,
  Category,
  Person,
  LocationOn,
  CalendarToday,
  AccessTime,
  Public,
  Add,
  Visibility,
  Edit,
  Delete,
  FilterList,
  People,
} from '@mui/icons-material'
import { motion } from 'framer-motion'
import { adminService } from '../../services/adminService'
import { eventService } from '../../services/eventService'
import { libraryService } from '../../services/libraryService'
import { Event as EventType } from '../../types'
import { LoadingSpinner } from '../../components/ui/loading-spinner'
import { useToast } from '../../hooks/use-toast'
import { formatDate, formatTime } from '../../lib/utils'

export function AdminEventsPage() {
  const { toast } = useToast()
  
  const [events, setEvents] = useState<EventType[]>([])
  const [categories, setCategories] = useState<any[]>([])
  const [libraries, setLibraries] = useState<any[]>([])
  const [selectedEvent, setSelectedEvent] = useState<EventType | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  
  // Filter states
  const [categoryFilter, setCategoryFilter] = useState<string>('')
  const [eventTypeFilter, setEventTypeFilter] = useState<string>('')
  const [statusFilter, setStatusFilter] = useState<string>('')
  const [libraryFilter, setLibraryFilter] = useState<string>('')
  const [isOnlineFilter, setIsOnlineFilter] = useState<string>('')
  const [registrationTypeFilter, setRegistrationTypeFilter] = useState<string>('')
  
  // Dialog states
  const [viewDialogOpen, setViewDialogOpen] = useState(false)
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [statusDialogOpen, setStatusDialogOpen] = useState(false)
  const [isProcessing, setIsProcessing] = useState(false)
  const [newStatus, setNewStatus] = useState<string>('')

  useEffect(() => {
    fetchCategories()
    fetchLibraries()
    fetchEvents()
  }, [])

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

  const fetchEvents = async () => {
    try {
      setIsLoading(true)
      setError(null)
      
      // In a real app, this would be an actual API call
      // For now, we'll simulate the data
      
      // Simulated events data
      const eventsData: EventType[] = [
        {
          id: '1',
          title: 'Python Programming Workshop',
          slug: 'python-programming-workshop',
          event_code: 'EV-001',
          category_name: 'Workshop',
          event_type: 'WORKSHOP',
          event_type_display: 'Workshop',
          status: 'REGISTRATION_OPEN',
          status_display: 'Registration Open',
          start_date: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
          end_date: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
          start_time: '10:00',
          end_time: '13:00',
          library_name: 'Main Library',
          organizer_name: 'John Doe',
          speakers_list: 'Dr. Jane Smith',
          registration_type: 'FREE',
          registration_type_display: 'Free Registration',
          registration_fee: 0,
          max_participants: 30,
          total_registrations: 15,
          is_registration_open: true,
          is_full: false,
          available_spots: 15,
          registration_deadline: new Date(Date.now() + 5 * 24 * 60 * 60 * 1000).toISOString(),
          duration_hours: 3,
          is_online: false,
          banner_image: 'https://images.pexels.com/photos/7103/writing-notes-idea-conference.jpg',
          thumbnail: 'https://images.pexels.com/photos/7103/writing-notes-idea-conference.jpg',
          average_rating: 4.5,
          total_feedback: 10,
          created_at: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
          updated_at: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString(),
        },
        {
          id: '2',
          title: 'Book Club: Clean Code',
          slug: 'book-club-clean-code',
          event_code: 'EV-002',
          category_name: 'Book Club',
          event_type: 'BOOK_CLUB',
          event_type_display: 'Book Club',
          status: 'REGISTRATION_OPEN',
          status_display: 'Registration Open',
          start_date: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000).toISOString(),
          end_date: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000).toISOString(),
          start_time: '15:00',
          end_time: '17:00',
          library_name: 'Digital Hub',
          organizer_name: 'Sarah Johnson',
          speakers_list: 'Robert Martin',
          registration_type: 'FREE',
          registration_type_display: 'Free Registration',
          registration_fee: 0,
          max_participants: 20,
          total_registrations: 12,
          is_registration_open: true,
          is_full: false,
          available_spots: 8,
          registration_deadline: new Date(Date.now() + 10 * 24 * 60 * 60 * 1000).toISOString(),
          duration_hours: 2,
          is_online: true,
          banner_image: 'https://images.pexels.com/photos/159866/books-book-pages-read-literature-159866.jpeg',
          thumbnail: 'https://images.pexels.com/photos/159866/books-book-pages-read-literature-159866.jpeg',
          average_rating: 4.8,
          total_feedback: 5,
          created_at: new Date(Date.now() - 45 * 24 * 60 * 60 * 1000).toISOString(),
          updated_at: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString(),
        },
        {
          id: '3',
          title: 'Financial Accounting Seminar',
          slug: 'financial-accounting-seminar',
          event_code: 'EV-003',
          category_name: 'Seminar',
          event_type: 'SEMINAR',
          event_type_display: 'Seminar',
          status: 'COMPLETED',
          status_display: 'Completed',
          start_date: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(),
          end_date: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(),
          start_time: '09:00',
          end_time: '16:00',
          library_name: 'Main Library',
          organizer_name: 'Michael Brown',
          speakers_list: 'Prof. Emily White, Dr. David Green',
          registration_type: 'PAID',
          registration_type_display: 'Paid Registration',
          registration_fee: 1500,
          max_participants: 50,
          total_registrations: 45,
          is_registration_open: false,
          is_full: false,
          available_spots: 5,
          registration_deadline: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString(),
          duration_hours: 7,
          is_online: false,
          banner_image: 'https://images.pexels.com/photos/6694543/pexels-photo-6694543.jpeg',
          thumbnail: 'https://images.pexels.com/photos/6694543/pexels-photo-6694543.jpeg',
          average_rating: 4.6,
          total_feedback: 30,
          created_at: new Date(Date.now() - 60 * 24 * 60 * 60 * 1000).toISOString(),
          updated_at: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(),
        },
        {
          id: '4',
          title: 'Exam Preparation Workshop',
          slug: 'exam-preparation-workshop',
          event_code: 'EV-004',
          category_name: 'Workshop',
          event_type: 'EXAM_PREP',
          event_type_display: 'Exam Preparation',
          status: 'REGISTRATION_CLOSED',
          status_display: 'Registration Closed',
          start_date: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString(),
          end_date: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString(),
          start_time: '14:00',
          end_time: '18:00',
          library_name: 'Main Library',
          organizer_name: 'John Doe',
          speakers_list: 'Prof. Robert Johnson',
          registration_type: 'FIRST_COME_FIRST_SERVE',
          registration_type_display: 'First Come First Serve',
          registration_fee: 0,
          max_participants: 40,
          total_registrations: 40,
          is_registration_open: false,
          is_full: true,
          available_spots: 0,
          registration_deadline: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000).toISOString(),
          duration_hours: 4,
          is_online: false,
          banner_image: 'https://images.pexels.com/photos/6238297/pexels-photo-6238297.jpeg',
          thumbnail: 'https://images.pexels.com/photos/6238297/pexels-photo-6238297.jpeg',
          average_rating: 0,
          total_feedback: 0,
          created_at: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000).toISOString(),
          updated_at: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
        },
        {
          id: '5',
          title: 'Digital Marketing Conference',
          slug: 'digital-marketing-conference',
          event_code: 'EV-005',
          category_name: 'Conference',
          event_type: 'CONFERENCE',
          event_type_display: 'Conference',
          status: 'DRAFT',
          status_display: 'Draft',
          start_date: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
          end_date: new Date(Date.now() + 31 * 24 * 60 * 60 * 1000).toISOString(),
          start_time: '09:00',
          end_time: '17:00',
          library_name: 'Digital Hub',
          organizer_name: 'Sarah Johnson',
          speakers_list: 'Multiple Industry Experts',
          registration_type: 'PAID',
          registration_type_display: 'Paid Registration',
          registration_fee: 5000,
          max_participants: 100,
          total_registrations: 0,
          is_registration_open: false,
          is_full: false,
          available_spots: 100,
          registration_deadline: new Date(Date.now() + 25 * 24 * 60 * 60 * 1000).toISOString(),
          duration_hours: 8,
          is_online: true,
          banner_image: 'https://images.pexels.com/photos/7688336/pexels-photo-7688336.jpeg',
          thumbnail: 'https://images.pexels.com/photos/7688336/pexels-photo-7688336.jpeg',
          average_rating: 0,
          total_feedback: 0,
          created_at: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString(),
          updated_at: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString(),
        },
      ]
      
      setEvents(eventsData)
    } catch (error: any) {
      setError(error.message || 'Failed to fetch events')
    } finally {
      setIsLoading(false)
    }
  }

  const handleCreateEvent = () => {
    toast({
      title: "Feature Not Implemented",
      description: "Event creation functionality would be implemented here.",
      variant: "default",
    })
  }

  const handleEditEvent = (event: EventType) => {
    setSelectedEvent(event)
    toast({
      title: "Feature Not Implemented",
      description: "Event editing functionality would be implemented here.",
      variant: "default",
    })
  }

  const handleDeleteEvent = async () => {
    if (!selectedEvent) return
    
    try {
      setIsProcessing(true)
      
      // In a real app, this would be an actual API call
      // For now, we'll simulate the deletion
      
      // Update local state
      setEvents(prevEvents => prevEvents.filter(event => event.id !== selectedEvent.id))
      
      toast({
        title: "Event Deleted",
        description: `"${selectedEvent.title}" has been deleted successfully.`,
        variant: "default",
      })
      
      setDeleteDialogOpen(false)
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || 'Failed to delete event',
        variant: "destructive",
      })
    } finally {
      setIsProcessing(false)
    }
  }

  const handleChangeEventStatus = async () => {
    if (!selectedEvent || !newStatus) return
    
    try {
      setIsProcessing(true)
      
      // In a real app, this would be an actual API call
      // For now, we'll simulate the update
      
      // Update local state
      setEvents(prevEvents =>
        prevEvents.map(event =>
          event.id === selectedEvent.id ? {
            ...event,
            status: newStatus as EventType['status'],
            status_display: getStatusDisplay(newStatus),
            is_registration_open: newStatus === 'REGISTRATION_OPEN'
          } : event
        )
      )
      
      toast({
        title: "Status Updated",
        description: `"${selectedEvent.title}" status has been updated to ${getStatusDisplay(newStatus)}.`,
        variant: "default",
      })
      
      setStatusDialogOpen(false)
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || 'Failed to update event status',
        variant: "destructive",
      })
    } finally {
      setIsProcessing(false)
    }
  }

  const getStatusDisplay = (status: string): string => {
    switch (status) {
      case 'DRAFT':
        return 'Draft'
      case 'PUBLISHED':
        return 'Published'
      case 'REGISTRATION_OPEN':
        return 'Registration Open'
      case 'REGISTRATION_CLOSED':
        return 'Registration Closed'
      case 'IN_PROGRESS':
        return 'In Progress'
      case 'COMPLETED':
        return 'Completed'
      case 'CANCELLED':
        return 'Cancelled'
      case 'POSTPONED':
        return 'Postponed'
      default:
        return status
    }
  }

  const filteredEvents = events.filter(event => {
    const matchesSearch = searchQuery === '' || 
      event.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      event.organizer_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      event.speakers_list.toLowerCase().includes(searchQuery.toLowerCase()) ||
      event.event_code.toLowerCase().includes(searchQuery.toLowerCase())
    
    const matchesCategory = categoryFilter === '' || event.category_name === categoryFilter
    const matchesEventType = eventTypeFilter === '' || event.event_type === eventTypeFilter
    const matchesStatus = statusFilter === '' || event.status === statusFilter
    const matchesLibrary = libraryFilter === '' || event.library_name === libraryFilter
    
    const matchesIsOnline = isOnlineFilter === '' || 
      (isOnlineFilter === 'true' && event.is_online) ||
      (isOnlineFilter === 'false' && !event.is_online)
    
    const matchesRegistrationType = registrationTypeFilter === '' || event.registration_type === registrationTypeFilter
    
    return matchesSearch && matchesCategory && matchesEventType && matchesStatus && 
           matchesLibrary && matchesIsOnline && matchesRegistrationType
  })

  const columns: GridColDef[] = [
    {
      field: 'title',
      headerName: 'Title',
      flex: 1,
      renderCell: (params: GridRenderCellParams<EventType>) => (
        <Box sx={{ display: 'flex', alignItems: 'center' }}>
          <Event sx={{ mr: 1 }} />
          <Tooltip title={params.row.title}>
            <Typography variant="body2" noWrap>
              {params.row.title.length > 40 ? params.row.title.substring(0, 40) + '...' : params.row.title}
            </Typography>
          </Tooltip>
        </Box>
      ),
    },
    {
      field: 'category_name',
      headerName: 'Category',
      width: 150,
    },
    {
      field: 'event_type_display',
      headerName: 'Type',
      width: 150,
    },
    {
      field: 'library_name',
      headerName: 'Library',
      width: 150,
    },
    {
      field: 'status_display',
      headerName: 'Status',
      width: 180,
      renderCell: (params: GridRenderCellParams<EventType>) => (
        <Chip
          label={params.row.status_display}
          size="small"
          color={
            params.row.status === 'REGISTRATION_OPEN'
              ? 'success'
              : params.row.status === 'PUBLISHED' || params.row.status === 'IN_PROGRESS'
              ? 'primary'
              : params.row.status === 'REGISTRATION_CLOSED' || params.row.status === 'POSTPONED'
              ? 'warning'
              : params.row.status === 'COMPLETED'
              ? 'info'
              : params.row.status === 'CANCELLED'
              ? 'error'
              : 'default'
          }
          variant="outlined"
        />
      ),
    },
    {
      field: 'start_date',
      headerName: 'Date',
      width: 120,
      valueFormatter: (params) => formatDate(params.value as string),
    },
    {
      field: 'time',
      headerName: 'Time',
      width: 120,
      valueGetter: (params) => `${params.row.start_time} - ${params.row.end_time}`,
    },
    {
      field: 'is_online',
      headerName: 'Online',
      width: 100,
      renderCell: (params: GridRenderCellParams<EventType>) => (
        <Chip
          label={params.row.is_online ? 'Yes' : 'No'}
          size="small"
          color={params.row.is_online ? 'info' : 'default'}
          variant="outlined"
        />
      ),
    },
    {
      field: 'registration_type_display',
      headerName: 'Registration',
      width: 150,
    },
    {
      field: 'actions',
      headerName: 'Actions',
      width: 200,
      sortable: false,
      renderCell: (params: GridRenderCellParams<EventType>) => (
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Tooltip title="View Details">
            <IconButton
              size="small"
              onClick={() => {
                setSelectedEvent(params.row)
                setViewDialogOpen(true)
              }}
            >
              <Visibility fontSize="small" />
            </IconButton>
          </Tooltip>
          
          <Tooltip title="Edit Event">
            <IconButton
              size="small"
              color="primary"
              onClick={() => handleEditEvent(params.row)}
            >
              <Edit fontSize="small" />
            </IconButton>
          </Tooltip>
          
          <Tooltip title="Delete Event">
            <IconButton
              size="small"
              color="error"
              onClick={() => {
                setSelectedEvent(params.row)
                setDeleteDialogOpen(true)
              }}
            >
              <Delete fontSize="small" />
            </IconButton>
          </Tooltip>
          
          <Tooltip title="Change Status">
            <IconButton
              size="small"
              color="warning"
              onClick={() => {
                setSelectedEvent(params.row)
                setNewStatus(params.row.status)
                setStatusDialogOpen(true)
              }}
            >
              <FilterList fontSize="small" />
            </IconButton>
          </Tooltip>
        </Box>
      ),
    },
  ]

  return (
    <Box sx={{ p: 3 }}>
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
      >
        <Box sx={{ mb: 4 }}>
          <Typography variant="h4" component="h1" gutterBottom>
            Event Management
          </Typography>
          <Typography variant="body1" color="text.secondary">
            Manage events, their status, and registrations.
          </Typography>
        </Box>

        {error && (
          <Alert severity="error" sx={{ mb: 3 }}>
            {error}
          </Alert>
        )}

        <Card sx={{ mb: 4 }}>
          <CardContent>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
              <Typography variant="h6">
                Events
              </Typography>
              <Button
                variant="contained"
                startIcon={<Add />}
                onClick={handleCreateEvent}
              >
                Create Event
              </Button>
            </Box>
            
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={4}>
                <TextField
                  fullWidth
                  placeholder="Search by title, organizer, speakers, or code"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  InputProps={{
                    startAdornment: (
                      <InputAdornment position="start">
                        <Search />
                      </InputAdornment>
                    ),
                  }}
                />
              </Grid>
              <Grid item xs={12} md={4}>
                <TextField
                  select
                  fullWidth
                  label="Category"
                  value={categoryFilter}
                  onChange={(e) => setCategoryFilter(e.target.value)}
                >
                  <MenuItem value="">All Categories</MenuItem>
                  {categories.map((category) => (
                    <MenuItem key={category.id} value={category.name}>
                      {category.name}
                    </MenuItem>
                  ))}
                </TextField>
              </Grid>
              <Grid item xs={12} md={4}>
                <TextField
                  select
                  fullWidth
                  label="Event Type"
                  value={eventTypeFilter}
                  onChange={(e) => setEventTypeFilter(e.target.value)}
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
                </TextField>
              </Grid>
              <Grid item xs={12} md={3}>
                <TextField
                  select
                  fullWidth
                  label="Status"
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                >
                  <MenuItem value="">All Statuses</MenuItem>
                  <MenuItem value="DRAFT">Draft</MenuItem>
                  <MenuItem value="PUBLISHED">Published</MenuItem>
                  <MenuItem value="REGISTRATION_OPEN">Registration Open</MenuItem>
                  <MenuItem value="REGISTRATION_CLOSED">Registration Closed</MenuItem>
                  <MenuItem value="IN_PROGRESS">In Progress</MenuItem>
                  <MenuItem value="COMPLETED">Completed</MenuItem>
                  <MenuItem value="CANCELLED">Cancelled</MenuItem>
                  <MenuItem value="POSTPONED">Postponed</MenuItem>
                </TextField>
              </Grid>
              <Grid item xs={12} md={3}>
                <TextField
                  select
                  fullWidth
                  label="Library"
                  value={libraryFilter}
                  onChange={(e) => setLibraryFilter(e.target.value)}
                >
                  <MenuItem value="">All Libraries</MenuItem>
                  {libraries.map((library) => (
                    <MenuItem key={library.id} value={library.name}>
                      {library.name}
                    </MenuItem>
                  ))}
                </TextField>
              </Grid>
              <Grid item xs={12} md={3}>
                <TextField
                  select
                  fullWidth
                  label="Online/In-Person"
                  value={isOnlineFilter}
                  onChange={(e) => setIsOnlineFilter(e.target.value)}
                >
                  <MenuItem value="">All</MenuItem>
                  <MenuItem value="true">Online</MenuItem>
                  <MenuItem value="false">In-Person</MenuItem>
                </TextField>
              </Grid>
              <Grid item xs={12} md={3}>
                <TextField
                  select
                  fullWidth
                  label="Registration Type"
                  value={registrationTypeFilter}
                  onChange={(e) => setRegistrationTypeFilter(e.target.value)}
                >
                  <MenuItem value="">All Types</MenuItem>
                  <MenuItem value="FREE">Free</MenuItem>
                  <MenuItem value="PAID">Paid</MenuItem>
                  <MenuItem value="INVITATION_ONLY">Invitation Only</MenuItem>
                  <MenuItem value="FIRST_COME_FIRST_SERVE">First Come First Serve</MenuItem>
                  <MenuItem value="APPROVAL_REQUIRED">Approval Required</MenuItem>
                </TextField>
              </Grid>
            </Grid>
            
            <Box sx={{ height: 600, width: '100%' }}>
              {isLoading ? (
                <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%' }}>
                  <LoadingSpinner size="lg" />
                </Box>
              ) : (
                <DataGrid
                  rows={filteredEvents}
                  columns={columns}
                  initialState={{
                    pagination: {
                      paginationModel: { page: 0, pageSize: 10 },
                    },
                    sorting: {
                      sortModel: [{ field: 'start_date', sort: 'asc' }],
                    },
                  }}
                  pageSizeOptions={[10, 25, 50]}
                  checkboxSelection
                  disableRowSelectionOnClick
                  components={{
                    Toolbar: GridToolbar,
                  }}
                />
              )}
            </Box>
          </CardContent>
        </Card>

        {/* View Event Details Dialog */}
        <Dialog
          open={viewDialogOpen}
          onClose={() => setViewDialogOpen(false)}
          maxWidth="md"
          fullWidth
        >
          <DialogTitle>Event Details</DialogTitle>
          <DialogContent dividers>
            {selectedEvent && (
              <Grid container spacing={2}>
                <Grid item xs={12} md={4}>
                  <Box sx={{ textAlign: 'center', mb: 2 }}>
                    <img
                      src={selectedEvent.banner_image || 'https://via.placeholder.com/300x200?text=No+Image'}
                      alt={selectedEvent.title}
                      style={{ maxWidth: '100%', maxHeight: 200, objectFit: 'contain' }}
                    />
                  </Box>
                </Grid>
                <Grid item xs={12} md={8}>
                  <Typography variant="h6" gutterBottom>
                    {selectedEvent.title}
                  </Typography>
                  
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mb: 2 }}>
                    <Chip
                      icon={<Category />}
                      label={selectedEvent.category_name}
                      variant="outlined"
                    />
                    <Chip
                      icon={<Event />}
                      label={selectedEvent.event_type_display}
                      variant="outlined"
                    />
                    <Chip
                      label={selectedEvent.status_display}
                      color={
                        selectedEvent.status === 'REGISTRATION_OPEN'
                          ? 'success'
                          : selectedEvent.status === 'PUBLISHED' || selectedEvent.status === 'IN_PROGRESS'
                          ? 'primary'
                          : selectedEvent.status === 'REGISTRATION_CLOSED' || selectedEvent.status === 'POSTPONED'
                          ? 'warning'
                          : selectedEvent.status === 'COMPLETED'
                          ? 'info'
                          : selectedEvent.status === 'CANCELLED'
                          ? 'error'
                          : 'default'
                      }
                    />
                    <Chip
                      icon={selectedEvent.is_online ? <Public /> : <LocationOn />}
                      label={selectedEvent.is_online ? 'Online' : 'In-Person'}
                      variant="outlined"
                    />
                  </Box>
                  
                  <Grid container spacing={1}>
                    <Grid item xs={12} sm={6}>
                      <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                        <CalendarToday fontSize="small" sx={{ mr: 1 }} />
                        <Typography variant="body2">
                          {formatDate(selectedEvent.start_date)}
                          {selectedEvent.end_date !== selectedEvent.start_date && 
                            ` - ${formatDate(selectedEvent.end_date)}`}
                        </Typography>
                      </Box>
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                        <AccessTime fontSize="small" sx={{ mr: 1 }} />
                        <Typography variant="body2">
                          {selectedEvent.start_time} - {selectedEvent.end_time} ({selectedEvent.duration_hours} hours)
                        </Typography>
                      </Box>
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                        <LocationOn fontSize="small" sx={{ mr: 1 }} />
                        <Typography variant="body2">
                          {selectedEvent.library_name}
                        </Typography>
                      </Box>
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                        <Person fontSize="small" sx={{ mr: 1 }} />
                        <Typography variant="body2">
                          Organizer: {selectedEvent.organizer_name}
                        </Typography>
                      </Box>
                    </Grid>
                    <Grid item xs={12}>
                      <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                        <People fontSize="small" sx={{ mr: 1 }} />
                        <Typography variant="body2">
                          Speakers: {selectedEvent.speakers_list}
                        </Typography>
                      </Box>
                    </Grid>
                  </Grid>
                  
                  <Divider sx={{ my: 2 }} />
                  
                  <Typography variant="subtitle1" gutterBottom>
                    Registration Information
                  </Typography>
                  <Grid container spacing={1}>
                    <Grid item xs={12} sm={6}>
                      <Typography variant="body2" color="text.secondary">
                        Registration Type
                      </Typography>
                      <Typography variant="body1" gutterBottom>
                        {selectedEvent.registration_type_display}
                      </Typography>
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <Typography variant="body2" color="text.secondary">
                        Registration Fee
                      </Typography>
                      <Typography variant="body1" gutterBottom>
                        {selectedEvent.registration_fee > 0 ? `${selectedEvent.registration_fee} PKR` : 'Free'}
                      </Typography>
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <Typography variant="body2" color="text.secondary">
                        Registration Deadline
                      </Typography>
                      <Typography variant="body1" gutterBottom>
                        {formatDate(selectedEvent.registration_deadline)}
                      </Typography>
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <Typography variant="body2" color="text.secondary">
                        Capacity
                      </Typography>
                      <Typography variant="body1" gutterBottom>
                        {selectedEvent.total_registrations} / {selectedEvent.max_participants} participants
                      </Typography>
                    </Grid>
                  </Grid>
                </Grid>
              </Grid>
            )}
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setViewDialogOpen(false)}>
              Close
            </Button>
            <Button
              variant="outlined"
              color="primary"
              onClick={() => {
                setViewDialogOpen(false)
                handleEditEvent(selectedEvent!)
              }}
            >
              Edit
            </Button>
            <Button
              variant="outlined"
              color="warning"
              onClick={() => {
                setViewDialogOpen(false)
                setNewStatus(selectedEvent!.status)
                setStatusDialogOpen(true)
              }}
            >
              Change Status
            </Button>
          </DialogActions>
        </Dialog>

        {/* Delete Event Dialog */}
        <Dialog
          open={deleteDialogOpen}
          onClose={() => !isProcessing && setDeleteDialogOpen(false)}
          maxWidth="xs"
          fullWidth
        >
          <DialogTitle>Delete Event</DialogTitle>
          <DialogContent>
            <Typography variant="body1">
              Are you sure you want to delete "{selectedEvent?.title}"?
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
              This action cannot be undone.
            </Typography>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setDeleteDialogOpen(false)} disabled={isProcessing}>
              Cancel
            </Button>
            <Button
              variant="contained"
              color="error"
              onClick={handleDeleteEvent}
              disabled={isProcessing}
              startIcon={isProcessing ? <LoadingSpinner size="sm" /> : <Delete />}
            >
              Delete
            </Button>
          </DialogActions>
        </Dialog>

        {/* Change Status Dialog */}
        <Dialog
          open={statusDialogOpen}
          onClose={() => !isProcessing && setStatusDialogOpen(false)}
          maxWidth="xs"
          fullWidth
        >
          <DialogTitle>Change Event Status</DialogTitle>
          <DialogContent>
            <Typography variant="body1" gutterBottom>
              Change status for "{selectedEvent?.title}"
            </Typography>
            <TextField
              select
              fullWidth
              label="New Status"
              value={newStatus}
              onChange={(e) => setNewStatus(e.target.value)}
              margin="normal"
            >
              <MenuItem value="DRAFT">Draft</MenuItem>
              <MenuItem value="PUBLISHED">Published</MenuItem>
              <MenuItem value="REGISTRATION_OPEN">Registration Open</MenuItem>
              <MenuItem value="REGISTRATION_CLOSED">Registration Closed</MenuItem>
              <MenuItem value="IN_PROGRESS">In Progress</MenuItem>
              <MenuItem value="COMPLETED">Completed</MenuItem>
              <MenuItem value="CANCELLED">Cancelled</MenuItem>
              <MenuItem value="POSTPONED">Postponed</MenuItem>
            </TextField>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setStatusDialogOpen(false)} disabled={isProcessing}>
              Cancel
            </Button>
            <Button
              variant="contained"
              color="primary"
              onClick={handleChangeEventStatus}
              disabled={isProcessing || newStatus === selectedEvent?.status}
              startIcon={isProcessing ? <LoadingSpinner size="sm" /> : <FilterList />}
            >
              Update Status
            </Button>
          </DialogActions>
        </Dialog>
      </motion.div>
    </Box>
  )
}