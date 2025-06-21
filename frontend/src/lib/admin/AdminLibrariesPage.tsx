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
  Add,
  Visibility,
  Edit,
  Delete,
  FilterList,
  LocalLibrary,
  LocationOn,
  AccessTime,
  Phone,
  Email,
  Language,
  Wifi,
  LocalPrintshop,
  Scanner,
  LocalParking,
  Restaurant,
  EventSeat,
  Star,
} from '@mui/icons-material'
import { motion } from 'framer-motion'
import { useNavigate } from 'react-router-dom'
import { adminService } from '../../services/adminService'
import { Library } from '../../types'
import { LoadingSpinner } from '../../components/ui/loading-spinner'
import { useToast } from '../../hooks/use-toast'
import { formatDate } from '../utils'
import { useAuthStore } from '../../stores/authStore'

export function SuperAdminLibrariesPage() {
  const navigate = useNavigate()
  const { toast } = useToast()
  const { user } = useAuthStore()
  
  const [libraries, setLibraries] = useState<Library[]>([])
  const [selectedLibrary, setSelectedLibrary] = useState<Library | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [libraryTypeFilter, setLibraryTypeFilter] = useState<string>('')
  const [statusFilter, setStatusFilter] = useState<string>('')
  const [cityFilter, setCityFilter] = useState<string>('')
  
  // Dialog states
  const [viewDialogOpen, setViewDialogOpen] = useState(false)
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [statusDialogOpen, setStatusDialogOpen] = useState(false)
  const [isProcessing, setIsProcessing] = useState(false)
  const [newStatus, setNewStatus] = useState<string>('')

  useEffect(() => {
    fetchLibraries()
  }, [])

  const fetchLibraries = async () => {
    try {
      setIsLoading(true)
      setError(null)
      
      const response = await adminService.getAdminLibraries()
      setLibraries(response.results)
    } catch (error: any) {
      setError(error.message || 'Failed to fetch libraries')
    } finally {
      setIsLoading(false)
    }
  }

  const handleCreateLibrary = () => {
    // Navigate to library creation page
    navigate('/superadmin/libraries/create')
  }

  const handleEditLibrary = (library: Library) => {
    navigate(`/superadmin/libraries/${library.id}`)
  }

  const handleDeleteLibrary = async () => {
    if (!selectedLibrary) return
    
    try {
      setIsProcessing(true)
      
      await adminService.deleteLibrary(selectedLibrary.id)
      
      toast({
        title: "Library Deleted",
        description: `"${selectedLibrary.name}" has been deleted successfully.`,
        variant: "default",
      })
      
      setDeleteDialogOpen(false)
      fetchLibraries()
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || 'Failed to delete library',
        variant: "destructive",
      })
    } finally {
      setIsProcessing(false)
    }
  }

  const handleChangeLibraryStatus = async () => {
    if (!selectedLibrary || !newStatus) return
    
    try {
      setIsProcessing(true)
      
      await adminService.updateLibrary(selectedLibrary.id, { status: newStatus })
      
      toast({
        title: "Status Updated",
        description: `"${selectedLibrary.name}" status has been updated to ${newStatus}.`,
        variant: "default",
      })
      
      setStatusDialogOpen(false)
      fetchLibraries()
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || 'Failed to update library status',
        variant: "destructive",
      })
    } finally {
      setIsProcessing(false)
    }
  }

  const filteredLibraries = libraries.filter(library => {
    const matchesSearch = searchQuery === '' || 
      library.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      library.code.toLowerCase().includes(searchQuery.toLowerCase()) ||
      library.city.toLowerCase().includes(searchQuery.toLowerCase()) ||
      library.address.toLowerCase().includes(searchQuery.toLowerCase())
    
    const matchesLibraryType = libraryTypeFilter === '' || library.library_type === libraryTypeFilter
    const matchesStatus = statusFilter === '' || library.status === statusFilter
    const matchesCity = cityFilter === '' || library.city.toLowerCase().includes(cityFilter.toLowerCase())
    
    return matchesSearch && matchesLibraryType && matchesStatus && matchesCity
  })

  const columns: GridColDef[] = [
    {
      field: 'name',
      headerName: 'Name',
      flex: 1,
      renderCell: (params: GridRenderCellParams<Library>) => (
        <Box sx={{ display: 'flex', alignItems: 'center' }}>
          <LocalLibrary sx={{ mr: 1 }} />
          <Typography variant="body2" noWrap>
            {params.row.name}
          </Typography>
        </Box>
      ),
    },
    {
      field: 'code',
      headerName: 'Code',
      width: 120,
    },
    {
      field: 'library_type',
      headerName: 'Type',
      width: 150,
      valueFormatter: (params) => {
        const types: Record<string, string> = {
          'MAIN': 'Main Library',
          'BRANCH': 'Branch Library',
          'STUDY_CENTER': 'Study Center',
          'DIGITAL_HUB': 'Digital Hub',
        }
        return types[params.value as string] || params.value
      },
    },
    {
      field: 'city',
      headerName: 'City',
      width: 150,
    },
    {
      field: 'status',
      headerName: 'Status',
      width: 150,
      renderCell: (params: GridRenderCellParams<Library>) => (
        <Chip
          label={params.row.status}
          size="small"
          color={
            params.row.status === 'ACTIVE'
              ? 'success'
              : params.row.status === 'MAINTENANCE'
              ? 'warning'
              : 'error'
          }
          variant="outlined"
        />
      ),
    },
    {
      field: 'total_seats',
      headerName: 'Seats',
      width: 120,
      valueFormatter: (params) => params.value.toLocaleString(),
    },
    {
      field: 'occupancy_rate',
      headerName: 'Occupancy',
      width: 120,
      renderCell: (params: GridRenderCellParams<Library>) => (
        <Box sx={{ width: '100%', display: 'flex', alignItems: 'center' }}>
          <Box
            sx={{
              width: '100%',
              height: 8,
              bgcolor: 'background.paper',
              borderRadius: 4,
              position: 'relative',
            }}
          >
            <Box
              sx={{
                height: '100%',
                borderRadius: 4,
                position: 'absolute',
                left: 0,
                width: `${Number(params.row.occupancy_rate || 0)}%`,
                bgcolor:
                  Number(params.row.occupancy_rate || 0) < 70
                    ? 'success.main'
                    : Number(params.row.occupancy_rate || 0) < 90
                    ? 'warning.main'
                    : 'error.main',
              }}
            />
          </Box>
          <Typography variant="body2" sx={{ ml: 1 }}>
            {Number(params.row.occupancy_rate || 0).toFixed(1)}%
          </Typography>
        </Box>
      ),
    },
    {
      field: 'average_rating',
      headerName: 'Rating',
      width: 120,
      renderCell: (params: GridRenderCellParams<Library>) => (
        <Box sx={{ display: 'flex', alignItems: 'center' }}>
          <Star sx={{ color: 'gold', mr: 0.5 }} fontSize="small" />
          <Typography variant="body2">
            {Number(params.row.average_rating || 0).toFixed(1)}
          </Typography>
        </Box>
      ),
    },
    {
      field: 'created_at',
      headerName: 'Created',
      width: 120,
      valueFormatter: (params) => formatDate(params.value as string),
    },
    {
      field: 'actions',
      headerName: 'Actions',
      width: 200,
      sortable: false,
      renderCell: (params: GridRenderCellParams<Library>) => (
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Tooltip title="View Details">
            <IconButton
              size="small"
              onClick={() => {
                setSelectedLibrary(params.row)
                setViewDialogOpen(true)
              }}
            >
              <Visibility fontSize="small" />
            </IconButton>
          </Tooltip>
          
          <Tooltip title="Edit Library">
            <IconButton
              size="small"
              color="primary"
              onClick={() => handleEditLibrary(params.row)}
            >
              <Edit fontSize="small" />
            </IconButton>
          </Tooltip>
          
          <Tooltip title="Delete Library">
            <IconButton
              size="small"
              color="error"
              onClick={() => {
                setSelectedLibrary(params.row)
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
                setSelectedLibrary(params.row)
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
            Library Management
          </Typography>
          <Typography variant="body1" color="text.secondary">
            Manage libraries, their status, and configurations.
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
                Libraries
              </Typography>
              <Button
                variant="contained"
                startIcon={<Add />}
                onClick={handleCreateLibrary}
              >
                Add Library
              </Button>
            </Box>
            
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  placeholder="Search by name, code, city, or address"
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
              <Grid item xs={12} md={2}>
                <TextField
                  select
                  fullWidth
                  label="Library Type"
                  value={libraryTypeFilter}
                  onChange={(e) => setLibraryTypeFilter(e.target.value)}
                >
                  <MenuItem value="">All Types</MenuItem>
                  <MenuItem value="MAIN">Main Library</MenuItem>
                  <MenuItem value="BRANCH">Branch Library</MenuItem>
                  <MenuItem value="STUDY_CENTER">Study Center</MenuItem>
                  <MenuItem value="DIGITAL_HUB">Digital Hub</MenuItem>
                </TextField>
              </Grid>
              <Grid item xs={12} md={2}>
                <TextField
                  select
                  fullWidth
                  label="Status"
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                >
                  <MenuItem value="">All Statuses</MenuItem>
                  <MenuItem value="ACTIVE">Active</MenuItem>
                  <MenuItem value="MAINTENANCE">Under Maintenance</MenuItem>
                  <MenuItem value="CLOSED">Temporarily Closed</MenuItem>
                  <MenuItem value="RENOVATION">Under Renovation</MenuItem>
                </TextField>
              </Grid>
              <Grid item xs={12} md={2}>
                <TextField
                  fullWidth
                  label="City"
                  value={cityFilter}
                  onChange={(e) => setCityFilter(e.target.value)}
                />
              </Grid>
            </Grid>
            
            <Box sx={{ height: 600, width: '100%' }}>
              {isLoading ? (
                <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%' }}>
                  <LoadingSpinner size="lg" />
                </Box>
              ) : (
                <DataGrid
                  rows={filteredLibraries}
                  columns={columns}
                  initialState={{
                    pagination: {
                      paginationModel: { page: 0, pageSize: 10 },
                    },
                    sorting: {
                      sortModel: [{ field: 'name', sort: 'asc' }],
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

        {/* View Library Details Dialog */}
        <Dialog
          open={viewDialogOpen}
          onClose={() => setViewDialogOpen(false)}
          maxWidth="md"
          fullWidth
        >
          <DialogTitle>Library Details</DialogTitle>
          <DialogContent dividers>
            {selectedLibrary && (
              <Grid container spacing={2}>
                <Grid item xs={12} md={4}>
                  <Box sx={{ textAlign: 'center', mb: 2 }}>
                    <img
                      src={selectedLibrary.main_image || 'https://via.placeholder.com/300x200?text=No+Image'}
                      alt={selectedLibrary.name}
                      style={{ maxWidth: '100%', maxHeight: 200, objectFit: 'contain' }}
                    />
                  </Box>
                </Grid>
                <Grid item xs={12} md={8}>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 1 }}>
                    <Typography variant="h6" gutterBottom>
                      {selectedLibrary.name}
                    </Typography>
                    <Chip
                      label={selectedLibrary.status}
                      color={
                        selectedLibrary.status === 'ACTIVE'
                          ? 'success'
                          : selectedLibrary.status === 'MAINTENANCE'
                          ? 'warning'
                          : 'error'
                      }
                    />
                  </Box>
                  
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    {selectedLibrary.code} • {selectedLibrary.library_type.replace('_', ' ')}
                  </Typography>
                  
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                    <LocationOn fontSize="small" color="action" sx={{ mr: 0.5 }} />
                    <Typography variant="body2" color="text.secondary">
                      {selectedLibrary.address}, {selectedLibrary.city}
                      {selectedLibrary.postal_code && `, ${selectedLibrary.postal_code}`}
                    </Typography>
                  </Box>
                  
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                    <AccessTime fontSize="small" color="action" sx={{ mr: 0.5 }} />
                    <Typography variant="body2" color="text.secondary">
                      {selectedLibrary.is_24_hours
                        ? '24 Hours'
                        : `${selectedLibrary.opening_time} - ${selectedLibrary.closing_time}`}
                    </Typography>
                  </Box>
                  
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                    <Phone fontSize="small" color="action" sx={{ mr: 0.5 }} />
                    <Typography variant="body2" color="text.secondary">
                      {selectedLibrary.phone_number || 'Not provided'}
                    </Typography>
                  </Box>
                  
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                    <Email fontSize="small" color="action" sx={{ mr: 0.5 }} />
                    <Typography variant="body2" color="text.secondary">
                      {selectedLibrary.email || 'Not provided'}
                    </Typography>
                  </Box>
                  
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                    <Language fontSize="small" color="action" sx={{ mr: 0.5 }} />
                    <Typography variant="body2" color="text.secondary">
                      {selectedLibrary.website || 'Not provided'}
                    </Typography>
                  </Box>
                  
                  <Divider sx={{ my: 2 }} />
                  
                  <Typography variant="subtitle1" gutterBottom>
                    Features
                  </Typography>
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mb: 2 }}>
                    {selectedLibrary.has_wifi && (
                      <Chip icon={<Wifi />} label="WiFi" variant="outlined" />
                    )}
                    {selectedLibrary.has_printing && (
                      <Chip icon={<LocalPrintshop />} label="Printing" variant="outlined" />
                    )}
                    {selectedLibrary.has_scanning && (
                      <Chip icon={<Scanner />} label="Scanning" variant="outlined" />
                    )}
                    {selectedLibrary.has_parking && (
                      <Chip icon={<LocalParking />} label="Parking" variant="outlined" />
                    )}
                    {selectedLibrary.has_cafeteria && (
                      <Chip icon={<Restaurant />} label="Cafeteria" variant="outlined" />
                    )}
                  </Box>
                  
                  <Typography variant="subtitle1" gutterBottom>
                    Capacity
                  </Typography>
                  <Grid container spacing={2}>
                    <Grid item xs={6}>
                      <Typography variant="body2" color="text.secondary">
                        Total Capacity
                      </Typography>
                      <Typography variant="h6">{selectedLibrary.total_capacity}</Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="body2" color="text.secondary">
                        Total Seats
                      </Typography>
                      <Typography variant="h6">{selectedLibrary.total_seats}</Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="body2" color="text.secondary">
                        Study Rooms
                      </Typography>
                      <Typography variant="h6">{selectedLibrary.total_study_rooms}</Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="body2" color="text.secondary">
                        Current Occupancy
                      </Typography>
                      <Typography variant="h6">{Number(selectedLibrary.occupancy_rate || 0).toFixed(1)}%</Typography>
                    </Grid>
                  </Grid>
                  
                  <Divider sx={{ my: 2 }} />
                  
                  <Typography variant="subtitle1" gutterBottom>
                    Statistics
                  </Typography>
                  <Grid container spacing={2}>
                    <Grid item xs={6}>
                      <Typography variant="body2" color="text.secondary">
                        Total Visits
                      </Typography>
                      <Typography variant="h6">{selectedLibrary.total_visits.toLocaleString()}</Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="body2" color="text.secondary">
                        Average Rating
                      </Typography>
                      <Box sx={{ display: 'flex', alignItems: 'center' }}>
                        <Typography variant="h6" sx={{ mr: 1 }}>{Number(selectedLibrary.average_rating || 0).toFixed(1)}</Typography>
                        <Star sx={{ color: 'gold' }} />
                      </Box>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="body2" color="text.secondary">
                        Total Reviews
                      </Typography>
                      <Typography variant="h6">{selectedLibrary.total_reviews}</Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="body2" color="text.secondary">
                        Created At
                      </Typography>
                      <Typography variant="h6">{formatDate(selectedLibrary.created_at)}</Typography>
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
                if (selectedLibrary) {
                  handleEditLibrary(selectedLibrary)
                }
              }}
            >
              Edit
            </Button>
            <Button
              variant="outlined"
              color="warning"
              onClick={() => {
                setViewDialogOpen(false)
                if (selectedLibrary) {
                  setNewStatus(selectedLibrary.status)
                  setStatusDialogOpen(true)
                }
              }}
            >
              Change Status
            </Button>
          </DialogActions>
        </Dialog>

        {/* Delete Library Dialog */}
        <Dialog
          open={deleteDialogOpen}
          onClose={() => !isProcessing && setDeleteDialogOpen(false)}
          maxWidth="xs"
          fullWidth
        >
          <DialogTitle>Delete Library</DialogTitle>
          <DialogContent>
            <Typography variant="body1">
              Are you sure you want to delete "{selectedLibrary?.name}"?
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
              onClick={handleDeleteLibrary}
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
          <DialogTitle>Change Library Status</DialogTitle>
          <DialogContent>
            <Typography variant="body1" gutterBottom>
              Change status for "{selectedLibrary?.name}"
            </Typography>
            <TextField
              select
              fullWidth
              label="New Status"
              value={newStatus}
              onChange={(e) => setNewStatus(e.target.value)}
              margin="normal"
            >
              <MenuItem value="ACTIVE">Active</MenuItem>
              <MenuItem value="MAINTENANCE">Under Maintenance</MenuItem>
              <MenuItem value="CLOSED">Temporarily Closed</MenuItem>
              <MenuItem value="RENOVATION">Under Renovation</MenuItem>
            </TextField>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setStatusDialogOpen(false)} disabled={isProcessing}>
              Cancel
            </Button>
            <Button
              variant="contained"
              color="primary"
              onClick={handleChangeLibraryStatus}
              disabled={isProcessing || newStatus === selectedLibrary?.status}
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