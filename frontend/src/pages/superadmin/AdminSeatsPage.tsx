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
  Alert,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  IconButton,
  Tooltip,
  MenuItem,
  FormControlLabel,
  Checkbox,
  Grid,
} from '@mui/material'
import { DataGrid, GridColDef, GridRenderCellParams, GridToolbar } from '@mui/x-data-grid'
import {
  Search,
  EventSeat,
  PowerSettingsNew,
  Wifi,
  Monitor,
  WbSunny,
  Accessible,
  Add,
  Visibility,
  Edit,
  Delete,
  FilterList,
} from '@mui/icons-material'
import { motion } from 'framer-motion'
import { libraryService } from '../../services/libraryService'
import { Seat, Library, LibraryFloor, LibrarySection } from '../../types'
import { LoadingSpinner } from '../../components/ui/loading-spinner'
import { useToast } from '../../hooks/use-toast'
import { formatDate } from '../../lib/utils'

export function SuperAdminSeatsPage() {
  const { toast } = useToast()
  
  const [seats, setSeats] = useState<Seat[]>([])
  const [libraries, setLibraries] = useState<Library[]>([])
  const [floors, setFloors] = useState<LibraryFloor[]>([])
  const [sections, setSections] = useState<LibrarySection[]>([])
  const [selectedSeat, setSelectedSeat] = useState<Seat | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  
  // Filter states
  const [libraryFilter, setLibraryFilter] = useState<string>('')
  const [floorFilter, setFloorFilter] = useState<string>('')
  const [sectionFilter, setSectionFilter] = useState<string>('')
  const [seatTypeFilter, setSeatTypeFilter] = useState<string>('')
  const [statusFilter, setStatusFilter] = useState<string>('')
  const [hasPowerOutlet, setHasPowerOutlet] = useState<boolean>(false)
  const [hasEthernet, setHasEthernet] = useState<boolean>(false)
  const [hasMonitor, setHasMonitor] = useState<boolean>(false)
  const [isNearWindow, setIsNearWindow] = useState<boolean>(false)
  const [isAccessible, setIsAccessible] = useState<boolean>(false)
  const [isPremium, setIsPremium] = useState<boolean>(false)
  
  // Dialog states
  const [viewDialogOpen, setViewDialogOpen] = useState(false)
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [statusDialogOpen, setStatusDialogOpen] = useState(false)
  const [isProcessing, setIsProcessing] = useState(false)
  const [newStatus, setNewStatus] = useState<string>('')

  useEffect(() => {
    fetchLibraries()
    fetchSeats()
  }, [])

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
      
      // In a real app, this would be an actual API call
      // For now, we'll simulate the data
      
      // Simulated seats data
      const seatsData: Seat[] = [
        {
          id: '1',
          library: 'lib-1',
          library_name: 'Main Library',
          floor: 'floor-1',
          floor_name: 'Ground Floor',
          section: 'section-1',
          section_name: 'Silent Study',
          seat_number: 'S001',
          seat_code: 'LIB-S001',
          seat_type: 'SILENT',
          seat_type_display: 'Silent Study',
          status: 'AVAILABLE',
          status_display: 'Available',
          is_available: true,
          has_power_outlet: true,
          has_ethernet: true,
          has_monitor: false,
          has_whiteboard: false,
          is_near_window: true,
          is_accessible: false,
          x_coordinate: 10,
          y_coordinate: 20,
          rotation: 0,
          is_bookable: true,
          requires_approval: false,
          is_premium: false,
          max_booking_duration_hours: 8,
          total_bookings: 45,
          total_usage_hours: 180.5,
          average_rating: 4.5,
          description: 'Silent study seat with power outlet and ethernet connection',
          features: ['power_outlet', 'ethernet', 'near_window'],
          created_at: new Date(Date.now() - 180 * 24 * 60 * 60 * 1000).toISOString(),
          updated_at: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
        },
        {
          id: '2',
          library: 'lib-1',
          library_name: 'Main Library',
          floor: 'floor-1',
          floor_name: 'Ground Floor',
          section: 'section-2',
          section_name: 'Group Study',
          seat_number: 'G001',
          seat_code: 'LIB-G001',
          seat_type: 'GROUP',
          seat_type_display: 'Group Study',
          status: 'OCCUPIED',
          status_display: 'Occupied',
          is_available: false,
          has_power_outlet: true,
          has_ethernet: true,
          has_monitor: true,
          has_whiteboard: true,
          is_near_window: false,
          is_accessible: true,
          x_coordinate: 30,
          y_coordinate: 40,
          rotation: 0,
          is_bookable: true,
          requires_approval: false,
          is_premium: false,
          max_booking_duration_hours: 4,
          total_bookings: 78,
          total_usage_hours: 312.0,
          average_rating: 4.2,
          description: 'Group study seat with power outlet, ethernet, monitor, and whiteboard',
          features: ['power_outlet', 'ethernet', 'monitor', 'whiteboard', 'accessible'],
          created_at: new Date(Date.now() - 150 * 24 * 60 * 60 * 1000).toISOString(),
          updated_at: new Date(Date.now() - 20 * 24 * 60 * 60 * 1000).toISOString(),
        },
        {
          id: '3',
          library: 'lib-2',
          library_name: 'Digital Hub',
          floor: 'floor-1',
          floor_name: 'First Floor',
          section: 'section-3',
          section_name: 'Computer Lab',
          seat_number: 'C001',
          seat_code: 'DH-C001',
          seat_type: 'COMPUTER',
          seat_type_display: 'Computer Workstation',
          status: 'AVAILABLE',
          status_display: 'Available',
          is_available: true,
          has_power_outlet: true,
          has_ethernet: true,
          has_monitor: true,
          has_whiteboard: false,
          is_near_window: false,
          is_accessible: false,
          x_coordinate: 50,
          y_coordinate: 60,
          rotation: 0,
          is_bookable: true,
          requires_approval: false,
          is_premium: true,
          max_booking_duration_hours: 6,
          total_bookings: 120,
          total_usage_hours: 720.0,
          average_rating: 4.8,
          description: 'Computer workstation with dual monitors and high-speed ethernet',
          features: ['power_outlet', 'ethernet', 'monitor', 'premium'],
          created_at: new Date(Date.now() - 120 * 24 * 60 * 60 * 1000).toISOString(),
          updated_at: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000).toISOString(),
        },
        {
          id: '4',
          library: 'lib-1',
          library_name: 'Main Library',
          floor: 'floor-2',
          floor_name: 'Second Floor',
          section: 'section-4',
          section_name: 'Individual Study',
          seat_number: 'I001',
          seat_code: 'LIB-I001',
          seat_type: 'INDIVIDUAL',
          seat_type_display: 'Individual Study',
          status: 'MAINTENANCE',
          status_display: 'Under Maintenance',
          is_available: false,
          has_power_outlet: true,
          has_ethernet: false,
          has_monitor: false,
          has_whiteboard: false,
          is_near_window: true,
          is_accessible: false,
          x_coordinate: 70,
          y_coordinate: 80,
          rotation: 0,
          is_bookable: false,
          requires_approval: false,
          is_premium: false,
          max_booking_duration_hours: 8,
          total_bookings: 65,
          total_usage_hours: 520.0,
          average_rating: 4.0,
          description: 'Individual study seat near window with power outlet',
          features: ['power_outlet', 'near_window'],
          created_at: new Date(Date.now() - 200 * 24 * 60 * 60 * 1000).toISOString(),
          updated_at: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
        },
        {
          id: '5',
          library: 'lib-2',
          library_name: 'Digital Hub',
          floor: 'floor-2',
          floor_name: 'Second Floor',
          section: 'section-5',
          section_name: 'Premium Zone',
          seat_number: 'P001',
          seat_code: 'DH-P001',
          seat_type: 'PREMIUM',
          seat_type_display: 'Premium Seat',
          status: 'OUT_OF_ORDER',
          status_display: 'Out of Order',
          is_available: false,
          has_power_outlet: true,
          has_ethernet: true,
          has_monitor: true,
          has_whiteboard: false,
          is_near_window: true,
          is_accessible: true,
          x_coordinate: 90,
          y_coordinate: 100,
          rotation: 0,
          is_bookable: false,
          requires_approval: true,
          is_premium: true,
          max_booking_duration_hours: 12,
          total_bookings: 30,
          total_usage_hours: 360.0,
          average_rating: 4.9,
          description: 'Premium seat with all amenities and extended booking hours',
          features: ['power_outlet', 'ethernet', 'monitor', 'near_window', 'accessible', 'premium'],
          created_at: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString(),
          updated_at: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000).toISOString(),
        },
      ]
      
      setSeats(seatsData)
    } catch (error: any) {
      setError(error.message || 'Failed to fetch seats')
    } finally {
      setIsLoading(false)
    }
  }

  const handleLibraryChange = (libraryId: string) => {
    setLibraryFilter(libraryId)
    setFloorFilter('')
    setSectionFilter('')
    
    if (libraryId) {
      fetchFloors(libraryId)
    } else {
      setFloors([])
      setSections([])
    }
  }

  const handleFloorChange = (floorId: string) => {
    setFloorFilter(floorId)
    setSectionFilter('')
    
    if (floorId) {
      fetchSections(floorId)
    } else {
      setSections([])
    }
  }

  const handleCreateSeat = () => {
    toast({
      title: "Feature Not Implemented",
      description: "Seat creation functionality would be implemented here.",
      variant: "default",
    })
  }

  const handleEditSeat = (seat: Seat) => {
    setSelectedSeat(seat)
    toast({
      title: "Feature Not Implemented",
      description: "Seat editing functionality would be implemented here.",
      variant: "default",
    })
  }

  const handleDeleteSeat = async () => {
    if (!selectedSeat) return
    
    try {
      setIsProcessing(true)
      
      // In a real app, this would be an actual API call
      // For now, we'll simulate the deletion
      
      // Update local state
      setSeats(prevSeats => prevSeats.filter(seat => seat.id !== selectedSeat.id))
      
      toast({
        title: "Seat Deleted",
        description: `Seat ${selectedSeat.seat_number} has been deleted successfully.`,
        variant: "default",
      })
      
      setDeleteDialogOpen(false)
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || 'Failed to delete seat',
        variant: "destructive",
      })
    } finally {
      setIsProcessing(false)
    }
  }

  const handleChangeSeatStatus = async () => {
    if (!selectedSeat || !newStatus) return
    
    try {
      setIsProcessing(true)
      
      // In a real app, this would be an actual API call
      // For now, we'll simulate the update
      
      // Update local state
      setSeats(prevSeats =>
        prevSeats.map(seat =>
          seat.id === selectedSeat.id ? {
            ...seat,
            status: newStatus as Seat['status'],
            status_display: getStatusDisplay(newStatus),
            is_available: newStatus === 'AVAILABLE',
            is_bookable: newStatus === 'AVAILABLE' || newStatus === 'RESERVED'
          } : seat
        )
      )
      
      toast({
        title: "Status Updated",
        description: `Seat ${selectedSeat.seat_number} status has been updated to ${getStatusDisplay(newStatus)}.`,
        variant: "default",
      })
      
      setStatusDialogOpen(false)
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || 'Failed to update seat status',
        variant: "destructive",
      })
    } finally {
      setIsProcessing(false)
    }
  }

  const getStatusDisplay = (status: string): string => {
    switch (status) {
      case 'AVAILABLE':
        return 'Available'
      case 'OCCUPIED':
        return 'Occupied'
      case 'RESERVED':
        return 'Reserved'
      case 'MAINTENANCE':
        return 'Under Maintenance'
      case 'OUT_OF_ORDER':
        return 'Out of Order'
      default:
        return status
    }
  }

  const filteredSeats = seats.filter(seat => {
    const matchesSearch = searchQuery === '' || 
      seat.seat_number.toLowerCase().includes(searchQuery.toLowerCase()) ||
      seat.seat_code.toLowerCase().includes(searchQuery.toLowerCase()) ||
      seat.library_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      seat.floor_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      seat.section_name.toLowerCase().includes(searchQuery.toLowerCase())
    
    const matchesLibrary = libraryFilter === '' || seat.library === libraryFilter
    const matchesFloor = floorFilter === '' || seat.floor === floorFilter
    const matchesSection = sectionFilter === '' || seat.section === sectionFilter
    const matchesSeatType = seatTypeFilter === '' || seat.seat_type === seatTypeFilter
    const matchesStatus = statusFilter === '' || seat.status === statusFilter
    
    const matchesFeatures = 
      (!hasPowerOutlet || seat.has_power_outlet) &&
      (!hasEthernet || seat.has_ethernet) &&
      (!hasMonitor || seat.has_monitor) &&
      (!isNearWindow || seat.is_near_window) &&
      (!isAccessible || seat.is_accessible) &&
      (!isPremium || seat.is_premium)
    
    return matchesSearch && matchesLibrary && matchesFloor && matchesSection && 
           matchesSeatType && matchesStatus && matchesFeatures
  })

  const columns: GridColDef[] = [
    {
      field: 'seat_number',
      headerName: 'Seat Number',
      width: 150,
      renderCell: (params: GridRenderCellParams<Seat>) => (
        <Box sx={{ display: 'flex', alignItems: 'center' }}>
          <EventSeat sx={{ mr: 1 }} />
          {params.row.seat_number}
        </Box>
      ),
    },
    {
      field: 'library_name',
      headerName: 'Library',
      width: 180,
    },
    {
      field: 'floor_name',
      headerName: 'Floor',
      width: 150,
    },
    {
      field: 'section_name',
      headerName: 'Section',
      width: 150,
    },
    {
      field: 'seat_type_display',
      headerName: 'Type',
      width: 180,
    },
    {
      field: 'status_display',
      headerName: 'Status',
      width: 150,
      renderCell: (params: GridRenderCellParams<Seat>) => (
        <Chip
          label={params.row.status_display}
          size="small"
          color={
            params.row.status === 'AVAILABLE'
              ? 'success'
              : params.row.status === 'OCCUPIED' || params.row.status === 'RESERVED'
              ? 'warning'
              : 'error'
          }
          variant="outlined"
        />
      ),
    },
    {
      field: 'is_bookable',
      headerName: 'Bookable',
      width: 120,
      renderCell: (params: GridRenderCellParams<Seat>) => (
        <Chip
          label={params.row.is_bookable ? 'Yes' : 'No'}
          size="small"
          color={params.row.is_bookable ? 'success' : 'error'}
          variant="outlined"
        />
      ),
    },
    {
      field: 'is_premium',
      headerName: 'Premium',
      width: 120,
      renderCell: (params: GridRenderCellParams<Seat>) => (
        <Chip
          label={params.row.is_premium ? 'Yes' : 'No'}
          size="small"
          color={params.row.is_premium ? 'primary' : 'default'}
          variant="outlined"
        />
      ),
    },
    {
      field: 'created_at',
      headerName: 'Created',
      width: 150,
      valueFormatter: (params) => formatDate(params.value as string),
    },
    {
      field: 'actions',
      headerName: 'Actions',
      width: 200,
      sortable: false,
      renderCell: (params: GridRenderCellParams<Seat>) => (
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Tooltip title="View Details">
            <IconButton
              size="small"
              onClick={() => {
                setSelectedSeat(params.row)
                setViewDialogOpen(true)
              }}
            >
              <Visibility fontSize="small" />
            </IconButton>
          </Tooltip>
          
          <Tooltip title="Edit Seat">
            <IconButton
              size="small"
              color="primary"
              onClick={() => handleEditSeat(params.row)}
            >
              <Edit fontSize="small" />
            </IconButton>
          </Tooltip>
          
          <Tooltip title="Delete Seat">
            <IconButton
              size="small"
              color="error"
              onClick={() => {
                setSelectedSeat(params.row)
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
                setSelectedSeat(params.row)
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
            Seat Management
          </Typography>
          <Typography variant="body1" color="text.secondary">
            Manage seats, their status, and configurations.
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
                Seats
              </Typography>
              <Button
                variant="contained"
                startIcon={<Add />}
                onClick={handleCreateSeat}
              >
                Add Seat
              </Button>
            </Box>
            
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={4}>
                <TextField
                  fullWidth
                  placeholder="Search by seat number, code, or location"
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
                  label="Library"
                  value={libraryFilter}
                  onChange={(e) => handleLibraryChange(e.target.value)}
                >
                  <MenuItem value="">All Libraries</MenuItem>
                  {libraries.map((library) => (
                    <MenuItem key={library.id} value={library.id}>
                      {library.name}
                    </MenuItem>
                  ))}
                </TextField>
              </Grid>
              <Grid item xs={12} md={4}>
                <TextField
                  select
                  fullWidth
                  label="Floor"
                  value={floorFilter}
                  onChange={(e) => handleFloorChange(e.target.value)}
                  disabled={!libraryFilter || floors.length === 0}
                >
                  <MenuItem value="">All Floors</MenuItem>
                  {floors.map((floor) => (
                    <MenuItem key={floor.id} value={floor.id}>
                      {floor.floor_name}
                    </MenuItem>
                  ))}
                </TextField>
              </Grid>
              <Grid item xs={12} md={4}>
                <TextField
                  select
                  fullWidth
                  label="Section"
                  value={sectionFilter}
                  onChange={(e) => setSectionFilter(e.target.value)}
                  disabled={!floorFilter || sections.length === 0}
                >
                  <MenuItem value="">All Sections</MenuItem>
                  {sections.map((section) => (
                    <MenuItem key={section.id} value={section.id}>
                      {section.name}
                    </MenuItem>
                  ))}
                </TextField>
              </Grid>
              <Grid item xs={12} md={4}>
                <TextField
                  select
                  fullWidth
                  label="Seat Type"
                  value={seatTypeFilter}
                  onChange={(e) => setSeatTypeFilter(e.target.value)}
                >
                  <MenuItem value="">All Types</MenuItem>
                  <MenuItem value="INDIVIDUAL">Individual Study</MenuItem>
                  <MenuItem value="GROUP">Group Study</MenuItem>
                  <MenuItem value="COMPUTER">Computer Workstation</MenuItem>
                  <MenuItem value="SILENT">Silent Study</MenuItem>
                  <MenuItem value="DISCUSSION">Discussion Area</MenuItem>
                  <MenuItem value="PREMIUM">Premium Seat</MenuItem>
                  <MenuItem value="ACCESSIBLE">Accessible Seat</MenuItem>
                </TextField>
              </Grid>
              <Grid item xs={12} md={4}>
                <TextField
                  select
                  fullWidth
                  label="Status"
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                >
                  <MenuItem value="">All Statuses</MenuItem>
                  <MenuItem value="AVAILABLE">Available</MenuItem>
                  <MenuItem value="OCCUPIED">Occupied</MenuItem>
                  <MenuItem value="RESERVED">Reserved</MenuItem>
                  <MenuItem value="MAINTENANCE">Under Maintenance</MenuItem>
                  <MenuItem value="OUT_OF_ORDER">Out of Order</MenuItem>
                </TextField>
              </Grid>
              <Grid item xs={12}>
                <Typography variant="subtitle2" gutterBottom>
                  Features
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2 }}>
                  <FormControlLabel
                    control={
                      <Checkbox
                        checked={hasPowerOutlet}
                        onChange={(e) => setHasPowerOutlet(e.target.checked)}
                      />
                    }
                    label="Power Outlet"
                  />
                  <FormControlLabel
                    control={
                      <Checkbox
                        checked={hasEthernet}
                        onChange={(e) => setHasEthernet(e.target.checked)}
                      />
                    }
                    label="Ethernet"
                  />
                  <FormControlLabel
                    control={
                      <Checkbox
                        checked={hasMonitor}
                        onChange={(e) => setHasMonitor(e.target.checked)}
                      />
                    }
                    label="Monitor"
                  />
                  <FormControlLabel
                    control={
                      <Checkbox
                        checked={isNearWindow}
                        onChange={(e) => setIsNearWindow(e.target.checked)}
                      />
                    }
                    label="Near Window"
                  />
                  <FormControlLabel
                    control={
                      <Checkbox
                        checked={isAccessible}
                        onChange={(e) => setIsAccessible(e.target.checked)}
                      />
                    }
                    label="Accessible"
                  />
                  <FormControlLabel
                    control={
                      <Checkbox
                        checked={isPremium}
                        onChange={(e) => setIsPremium(e.target.checked)}
                      />
                    }
                    label="Premium"
                  />
                </Box>
              </Grid>
            </Grid>
            
            <Box sx={{ height: 600, width: '100%' }}>
              {isLoading ? (
                <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%' }}>
                  <LoadingSpinner size="lg" />
                </Box>
              ) : (
                <DataGrid
                  rows={filteredSeats}
                  columns={columns}
                  initialState={{
                    pagination: {
                      paginationModel: { page: 0, pageSize: 10 },
                    },
                    sorting: {
                      sortModel: [{ field: 'created_at', sort: 'desc' }],
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

        {/* View Seat Details Dialog */}
        <Dialog
          open={viewDialogOpen}
          onClose={() => setViewDialogOpen(false)}
          maxWidth="md"
          fullWidth
        >
          <DialogTitle>Seat Details</DialogTitle>
          <DialogContent dividers>
            {selectedSeat && (
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle1" gutterBottom>
                    Basic Information
                  </Typography>
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="body2" color="text.secondary">
                      Seat Number
                    </Typography>
                    <Typography variant="body1">
                      {selectedSeat.seat_number}
                    </Typography>
                  </Box>
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="body2" color="text.secondary">
                      Seat Code
                    </Typography>
                    <Typography variant="body1">
                      {selectedSeat.seat_code}
                    </Typography>
                  </Box>
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="body2" color="text.secondary">
                      Location
                    </Typography>
                    <Typography variant="body1">
                      {selectedSeat.library_name}, {selectedSeat.floor_name}, {selectedSeat.section_name}
                    </Typography>
                  </Box>
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="body2" color="text.secondary">
                      Seat Type
                    </Typography>
                    <Typography variant="body1">
                      {selectedSeat.seat_type_display}
                    </Typography>
                  </Box>
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="body2" color="text.secondary">
                      Status
                    </Typography>
                    <Chip
                      label={selectedSeat.status_display}
                      size="small"
                      color={
                        selectedSeat.status === 'AVAILABLE'
                          ? 'success'
                          : selectedSeat.status === 'OCCUPIED' || selectedSeat.status === 'RESERVED'
                          ? 'warning'
                          : 'error'
                      }
                    />
                  </Box>
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="body2" color="text.secondary">
                      Description
                    </Typography>
                    <Typography variant="body1">
                      {selectedSeat.description || 'No description available'}
                    </Typography>
                  </Box>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle1" gutterBottom>
                    Features & Settings
                  </Typography>
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="body2" color="text.secondary">
                      Features
                    </Typography>
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 0.5 }}>
                      {selectedSeat.has_power_outlet && (
                        <Chip icon={<PowerSettingsNew />} label="Power Outlet" size="small" />
                      )}
                      {selectedSeat.has_ethernet && (
                        <Chip icon={<Wifi />} label="Ethernet" size="small" />
                      )}
                      {selectedSeat.has_monitor && (
                        <Chip icon={<Monitor />} label="Monitor" size="small" />
                      )}
                      {selectedSeat.is_near_window && (
                        <Chip icon={<WbSunny />} label="Near Window" size="small" />
                      )}
                      {selectedSeat.is_accessible && (
                        <Chip icon={<Accessible />} label="Accessible" size="small" />
                      )}
                      {selectedSeat.is_premium && (
                        <Chip label="Premium" size="small" color="primary" />
                      )}
                    </Box>
                  </Box>
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="body2" color="text.secondary">
                      Booking Settings
                    </Typography>
                    <Typography variant="body1">
                      {selectedSeat.is_bookable ? 'Bookable' : 'Not Bookable'} | 
                      {selectedSeat.requires_approval ? ' Requires Approval' : ' No Approval Required'} | 
                      Max Duration: {selectedSeat.max_booking_duration_hours} hours
                    </Typography>
                  </Box>
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="body2" color="text.secondary">
                      Position
                    </Typography>
                    <Typography variant="body1">
                      X: {selectedSeat.x_coordinate}, Y: {selectedSeat.y_coordinate}, Rotation: {selectedSeat.rotation}°
                    </Typography>
                  </Box>
                  <Typography variant="subtitle1" gutterBottom sx={{ mt: 3 }}>
                    Statistics
                  </Typography>
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="body2" color="text.secondary">
                      Total Bookings
                    </Typography>
                    <Typography variant="body1">
                      {selectedSeat.total_bookings}
                    </Typography>
                  </Box>
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="body2" color="text.secondary">
                      Total Usage Hours
                    </Typography>
                    <Typography variant="body1">
                      {selectedSeat.total_usage_hours}
                    </Typography>
                  </Box>
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="body2" color="text.secondary">
                      Average Rating
                    </Typography>
                    <Typography variant="body1">
                      {selectedSeat.average_rating.toFixed(1)} / 5.0
                    </Typography>
                  </Box>
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="body2" color="text.secondary">
                      Created At
                    </Typography>
                    <Typography variant="body1">
                      {formatDate(selectedSeat.created_at)}
                    </Typography>
                  </Box>
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
                handleEditSeat(selectedSeat!)
              }}
            >
              Edit
            </Button>
            <Button
              variant="outlined"
              color="warning"
              onClick={() => {
                setViewDialogOpen(false)
                setNewStatus(selectedSeat!.status)
                setStatusDialogOpen(true)
              }}
            >
              Change Status
            </Button>
          </DialogActions>
        </Dialog>

        {/* Delete Seat Dialog */}
        <Dialog
          open={deleteDialogOpen}
          onClose={() => !isProcessing && setDeleteDialogOpen(false)}
          maxWidth="xs"
          fullWidth
        >
          <DialogTitle>Delete Seat</DialogTitle>
          <DialogContent>
            <Typography variant="body1">
              Are you sure you want to delete seat {selectedSeat?.seat_number}?
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
              onClick={handleDeleteSeat}
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
          <DialogTitle>Change Seat Status</DialogTitle>
          <DialogContent>
            <Typography variant="body1" gutterBottom>
              Change status for seat {selectedSeat?.seat_number}
            </Typography>
            <TextField
              select
              fullWidth
              label="New Status"
              value={newStatus}
              onChange={(e) => setNewStatus(e.target.value)}
              margin="normal"
            >
              <MenuItem value="AVAILABLE">Available</MenuItem>
              <MenuItem value="OCCUPIED">Occupied</MenuItem>
              <MenuItem value="RESERVED">Reserved</MenuItem>
              <MenuItem value="MAINTENANCE">Under Maintenance</MenuItem>
              <MenuItem value="OUT_OF_ORDER">Out of Order</MenuItem>
            </TextField>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setStatusDialogOpen(false)} disabled={isProcessing}>
              Cancel
            </Button>
            <Button
              variant="contained"
              color="primary"
              onClick={handleChangeSeatStatus}
              disabled={isProcessing || newStatus === selectedSeat?.status}
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