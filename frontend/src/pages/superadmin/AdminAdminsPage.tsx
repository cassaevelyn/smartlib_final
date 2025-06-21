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
  Grid,
  FormControlLabel,
  Checkbox,
  FormControl,
  InputLabel,
  Select,
  FormHelperText,
} from '@mui/material'
import { DataGrid, GridColDef, GridRenderCellParams, GridToolbar } from '@mui/x-data-grid'
import {
  Search,
  Person,
  LocalLibrary,
  Add,
  Visibility,
  Edit,
  Delete,
  Save,
  Cancel,
} from '@mui/icons-material'
import { motion } from 'framer-motion'
import { useForm, Controller } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { adminService } from '../../services/adminService'
import { libraryService } from '../../services/libraryService'
import { AdminProfile, User, Library } from '../../types'
import { LoadingSpinner } from '../../components/ui/loading-spinner'
import { useToast } from '../../hooks/use-toast'

// Schema for admin profile form
const adminProfileSchema = z.object({
  user: z.string().min(1, 'User is required'),
  managed_library: z.string().optional(),
  can_approve_users: z.boolean().default(false),
  can_manage_events: z.boolean().default(false),
  can_manage_books: z.boolean().default(false),
  can_view_analytics: z.boolean().default(false),
  permissions: z.record(z.any()).optional(),
});

type AdminProfileForm = z.infer<typeof adminProfileSchema>;

export function SuperAdminAdminsPage() {
  const { toast } = useToast()
  
  const [adminProfiles, setAdminProfiles] = useState<AdminProfile[]>([])
  const [eligibleUsers, setEligibleUsers] = useState<User[]>([])
  const [libraries, setLibraries] = useState<Library[]>([])
  const [selectedAdminProfile, setSelectedAdminProfile] = useState<AdminProfile | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  
  // Dialog states
  const [formDialogOpen, setFormDialogOpen] = useState(false)
  const [viewDialogOpen, setViewDialogOpen] = useState(false)
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [isEditMode, setIsEditMode] = useState(false)

  // Form
  const {
    control,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<AdminProfileForm>({
    resolver: zodResolver(adminProfileSchema),
    defaultValues: {
      user: '',
      managed_library: '',
      can_approve_users: false,
      can_manage_events: false,
      can_manage_books: false,
      can_view_analytics: false,
      permissions: {},
    },
  });

  useEffect(() => {
    fetchData()
  }, [])

  const fetchData = async () => {
    try {
      setIsLoading(true)
      setError(null)
      
      // Fetch admin profiles, eligible users, and libraries in parallel
      const [adminProfilesResponse, eligibleUsersResponse, librariesResponse] = await Promise.all([
        adminService.getAdminProfiles(),
        adminService.getUsersForAdminAssignment(),
        libraryService.getLibraries()
      ])
      
      setAdminProfiles(adminProfilesResponse.results)
      setEligibleUsers(eligibleUsersResponse.results)
      setLibraries(librariesResponse.results)
    } catch (error: any) {
      setError(error.message || 'Failed to fetch data')
    } finally {
      setIsLoading(false)
    }
  }

  const handleCreateAdminProfile = () => {
    setIsEditMode(false)
    reset({
      user: '',
      managed_library: '',
      can_approve_users: false,
      can_manage_events: false,
      can_manage_books: false,
      can_view_analytics: false,
      permissions: {},
    })
    setFormDialogOpen(true)
  }

  const handleEditAdminProfile = (adminProfile: AdminProfile) => {
    setIsEditMode(true)
    setSelectedAdminProfile(adminProfile)
    
    reset({
      user: adminProfile.user,
      managed_library: adminProfile.managed_library || '',
      can_approve_users: adminProfile.can_approve_users,
      can_manage_events: adminProfile.can_manage_events,
      can_manage_books: adminProfile.can_manage_books,
      can_view_analytics: adminProfile.can_view_analytics,
      permissions: adminProfile.permissions || {},
    })
    
    setFormDialogOpen(true)
  }

  const handleDeleteAdminProfile = async () => {
    if (!selectedAdminProfile) return
    
    try {
      setIsSubmitting(true)
      
      await adminService.deleteAdminProfile(selectedAdminProfile.id)
      
      toast({
        title: "Admin Profile Deleted",
        description: `Admin profile for ${selectedAdminProfile.user_display} has been deleted successfully.`,
        variant: "default",
      })
      
      setDeleteDialogOpen(false)
      fetchData() // Refresh data
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || 'Failed to delete admin profile',
        variant: "destructive",
      })
    } finally {
      setIsSubmitting(false)
    }
  }

  const onSubmit = async (data: AdminProfileForm) => {
    try {
      setIsSubmitting(true)
      
      if (isEditMode && selectedAdminProfile) {
        // Update existing admin profile
        await adminService.updateAdminProfile(selectedAdminProfile.id, data)
        
        toast({
          title: "Admin Profile Updated",
          description: "The admin profile has been updated successfully.",
          variant: "default",
        })
      } else {
        // Create new admin profile
        await adminService.createAdminProfile(data)
        
        toast({
          title: "Admin Profile Created",
          description: "The admin profile has been created successfully.",
          variant: "default",
        })
      }
      
      setFormDialogOpen(false)
      fetchData() // Refresh data
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || 'Failed to save admin profile',
        variant: "destructive",
      })
    } finally {
      setIsSubmitting(false)
    }
  }

  const filteredAdminProfiles = adminProfiles.filter(profile => {
    return searchQuery === '' || 
      profile.user_display.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (profile.managed_library_display && profile.managed_library_display.toLowerCase().includes(searchQuery.toLowerCase()))
  })

  const columns: GridColDef[] = [
    {
      field: 'user_display',
      headerName: 'Admin',
      flex: 1,
      renderCell: (params: GridRenderCellParams<AdminProfile>) => (
        <Box sx={{ display: 'flex', alignItems: 'center' }}>
          <Person sx={{ mr: 1 }} />
          <Typography variant="body2">
            {params.row.user_display}
          </Typography>
        </Box>
      ),
    },
    {
      field: 'managed_library_display',
      headerName: 'Managed Library',
      flex: 1,
      renderCell: (params: GridRenderCellParams<AdminProfile>) => (
        <Box sx={{ display: 'flex', alignItems: 'center' }}>
          <LocalLibrary sx={{ mr: 1 }} />
          <Typography variant="body2">
            {params.row.managed_library_display || 'None'}
          </Typography>
        </Box>
      ),
    },
    {
      field: 'can_approve_users',
      headerName: 'Approve Users',
      width: 150,
      renderCell: (params: GridRenderCellParams<AdminProfile>) => (
        <Chip
          label={params.row.can_approve_users ? 'Yes' : 'No'}
          size="small"
          color={params.row.can_approve_users ? 'success' : 'default'}
          variant="outlined"
        />
      ),
    },
    {
      field: 'can_manage_events',
      headerName: 'Manage Events',
      width: 150,
      renderCell: (params: GridRenderCellParams<AdminProfile>) => (
        <Chip
          label={params.row.can_manage_events ? 'Yes' : 'No'}
          size="small"
          color={params.row.can_manage_events ? 'success' : 'default'}
          variant="outlined"
        />
      ),
    },
    {
      field: 'can_manage_books',
      headerName: 'Manage Books',
      width: 150,
      renderCell: (params: GridRenderCellParams<AdminProfile>) => (
        <Chip
          label={params.row.can_manage_books ? 'Yes' : 'No'}
          size="small"
          color={params.row.can_manage_books ? 'success' : 'default'}
          variant="outlined"
        />
      ),
    },
    {
      field: 'can_view_analytics',
      headerName: 'View Analytics',
      width: 150,
      renderCell: (params: GridRenderCellParams<AdminProfile>) => (
        <Chip
          label={params.row.can_view_analytics ? 'Yes' : 'No'}
          size="small"
          color={params.row.can_view_analytics ? 'success' : 'default'}
          variant="outlined"
        />
      ),
    },
    {
      field: 'actions',
      headerName: 'Actions',
      width: 150,
      sortable: false,
      renderCell: (params: GridRenderCellParams<AdminProfile>) => (
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Tooltip title="View Details">
            <IconButton
              size="small"
              onClick={() => {
                setSelectedAdminProfile(params.row)
                setViewDialogOpen(true)
              }}
            >
              <Visibility fontSize="small" />
            </IconButton>
          </Tooltip>
          
          <Tooltip title="Edit Admin Profile">
            <IconButton
              size="small"
              color="primary"
              onClick={() => handleEditAdminProfile(params.row)}
            >
              <Edit fontSize="small" />
            </IconButton>
          </Tooltip>
          
          <Tooltip title="Delete Admin Profile">
            <IconButton
              size="small"
              color="error"
              onClick={() => {
                setSelectedAdminProfile(params.row)
                setDeleteDialogOpen(true)
              }}
            >
              <Delete fontSize="small" />
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
            Admin Management
          </Typography>
          <Typography variant="body1" color="text.secondary">
            Manage library administrators and their permissions.
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
                Admin Profiles
              </Typography>
              <Button
                variant="contained"
                startIcon={<Add />}
                onClick={handleCreateAdminProfile}
              >
                Add Admin
              </Button>
            </Box>
            
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  placeholder="Search by admin name or library"
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
            </Grid>
            
            <Box sx={{ height: 600, width: '100%' }}>
              {isLoading ? (
                <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%' }}>
                  <LoadingSpinner size="lg" />
                </Box>
              ) : (
                <DataGrid
                  rows={filteredAdminProfiles}
                  columns={columns}
                  initialState={{
                    pagination: {
                      paginationModel: { page: 0, pageSize: 10 },
                    },
                    sorting: {
                      sortModel: [{ field: 'user_display', sort: 'asc' }],
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

        {/* Admin Profile Form Dialog */}
        <Dialog
          open={formDialogOpen}
          onClose={() => !isSubmitting && setFormDialogOpen(false)}
          maxWidth="md"
          fullWidth
        >
          <DialogTitle>
            {isEditMode ? 'Edit Admin Profile' : 'Create Admin Profile'}
          </DialogTitle>
          <DialogContent>
            <Box component="form" sx={{ mt: 2 }}>
              <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                  <Controller
                    name="user"
                    control={control}
                    render={({ field }) => (
                      <FormControl fullWidth error={!!errors.user} required>
                        <InputLabel>User</InputLabel>
                        <Select
                          {...field}
                          label="User"
                          disabled={isEditMode}
                        >
                          {isEditMode && selectedAdminProfile ? (
                            <MenuItem value={selectedAdminProfile.user}>
                              {selectedAdminProfile.user_display}
                            </MenuItem>
                          ) : (
                            eligibleUsers.map((user) => (
                              <MenuItem key={user.id} value={user.id}>
                                {user.full_name} ({user.email})
                              </MenuItem>
                            ))
                          )}
                        </Select>
                        {errors.user && (
                          <FormHelperText>{errors.user.message}</FormHelperText>
                        )}
                      </FormControl>
                    )}
                  />
                </Grid>
                <Grid item xs={12} md={6}>
                  <Controller
                    name="managed_library"
                    control={control}
                    render={({ field }) => (
                      <FormControl fullWidth>
                        <InputLabel>Managed Library</InputLabel>
                        <Select
                          {...field}
                          label="Managed Library"
                        >
                          <MenuItem value="">None</MenuItem>
                          {libraries.map((library) => (
                            <MenuItem key={library.id} value={library.id}>
                              {library.name}
                            </MenuItem>
                          ))}
                        </Select>
                      </FormControl>
                    )}
                  />
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="subtitle1" gutterBottom>
                    Permissions
                  </Typography>
                  <Grid container spacing={2}>
                    <Grid item xs={12} sm={6}>
                      <Controller
                        name="can_approve_users"
                        control={control}
                        render={({ field }) => (
                          <FormControlLabel
                            control={
                              <Checkbox
                                checked={field.value}
                                onChange={(e) => field.onChange(e.target.checked)}
                              />
                            }
                            label="Can Approve Users"
                          />
                        )}
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <Controller
                        name="can_manage_events"
                        control={control}
                        render={({ field }) => (
                          <FormControlLabel
                            control={
                              <Checkbox
                                checked={field.value}
                                onChange={(e) => field.onChange(e.target.checked)}
                              />
                            }
                            label="Can Manage Events"
                          />
                        )}
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <Controller
                        name="can_manage_books"
                        control={control}
                        render={({ field }) => (
                          <FormControlLabel
                            control={
                              <Checkbox
                                checked={field.value}
                                onChange={(e) => field.onChange(e.target.checked)}
                              />
                            }
                            label="Can Manage Books"
                          />
                        )}
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <Controller
                        name="can_view_analytics"
                        control={control}
                        render={({ field }) => (
                          <FormControlLabel
                            control={
                              <Checkbox
                                checked={field.value}
                                onChange={(e) => field.onChange(e.target.checked)}
                              />
                            }
                            label="Can View Analytics"
                          />
                        )}
                      />
                    </Grid>
                  </Grid>
                </Grid>
              </Grid>
            </Box>
          </DialogContent>
          <DialogActions>
            <Button
              onClick={() => setFormDialogOpen(false)}
              disabled={isSubmitting}
              startIcon={<Cancel />}
            >
              Cancel
            </Button>
            <Button
              variant="contained"
              onClick={handleSubmit(onSubmit)}
              disabled={isSubmitting}
              startIcon={isSubmitting ? <LoadingSpinner size="sm" /> : <Save />}
            >
              {isEditMode ? 'Update' : 'Create'}
            </Button>
          </DialogActions>
        </Dialog>

        {/* View Admin Profile Dialog */}
        <Dialog
          open={viewDialogOpen}
          onClose={() => setViewDialogOpen(false)}
          maxWidth="md"
          fullWidth
        >
          <DialogTitle>Admin Profile Details</DialogTitle>
          <DialogContent dividers>
            {selectedAdminProfile && (
              <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle1" gutterBottom>
                    Admin Information
                  </Typography>
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="body2" color="text.secondary">
                      Admin Name
                    </Typography>
                    <Typography variant="body1">
                      {selectedAdminProfile.user_display}
                    </Typography>
                  </Box>
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="body2" color="text.secondary">
                      Managed Library
                    </Typography>
                    <Typography variant="body1">
                      {selectedAdminProfile.managed_library_display || 'None'}
                    </Typography>
                  </Box>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle1" gutterBottom>
                    Permissions
                  </Typography>
                  <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                    <Box>
                      <Typography variant="body2" color="text.secondary">
                        Can Approve Users
                      </Typography>
                      <Chip
                        label={selectedAdminProfile.can_approve_users ? 'Yes' : 'No'}
                        size="small"
                        color={selectedAdminProfile.can_approve_users ? 'success' : 'default'}
                        variant="outlined"
                      />
                    </Box>
                    <Box>
                      <Typography variant="body2" color="text.secondary">
                        Can Manage Events
                      </Typography>
                      <Chip
                        label={selectedAdminProfile.can_manage_events ? 'Yes' : 'No'}
                        size="small"
                        color={selectedAdminProfile.can_manage_events ? 'success' : 'default'}
                        variant="outlined"
                      />
                    </Box>
                    <Box>
                      <Typography variant="body2" color="text.secondary">
                        Can Manage Books
                      </Typography>
                      <Chip
                        label={selectedAdminProfile.can_manage_books ? 'Yes' : 'No'}
                        size="small"
                        color={selectedAdminProfile.can_manage_books ? 'success' : 'default'}
                        variant="outlined"
                      />
                    </Box>
                    <Box>
                      <Typography variant="body2" color="text.secondary">
                        Can View Analytics
                      </Typography>
                      <Chip
                        label={selectedAdminProfile.can_view_analytics ? 'Yes' : 'No'}
                        size="small"
                        color={selectedAdminProfile.can_view_analytics ? 'success' : 'default'}
                        variant="outlined"
                      />
                    </Box>
                  </Box>
                </Grid>
                {selectedAdminProfile.permissions && Object.keys(selectedAdminProfile.permissions).length > 0 && (
                  <Grid item xs={12}>
                    <Typography variant="subtitle1" gutterBottom>
                      Additional Permissions
                    </Typography>
                    <pre>
                      {JSON.stringify(selectedAdminProfile.permissions, null, 2)}
                    </pre>
                  </Grid>
                )}
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
                if (selectedAdminProfile) {
                  handleEditAdminProfile(selectedAdminProfile)
                }
              }}
            >
              Edit
            </Button>
          </DialogActions>
        </Dialog>

        {/* Delete Admin Profile Dialog */}
        <Dialog
          open={deleteDialogOpen}
          onClose={() => !isSubmitting && setDeleteDialogOpen(false)}
          maxWidth="xs"
          fullWidth
        >
          <DialogTitle>Delete Admin Profile</DialogTitle>
          <DialogContent>
            <Typography variant="body1">
              Are you sure you want to delete the admin profile for "{selectedAdminProfile?.user_display}"?
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
              This action cannot be undone. The user's role will be changed back to STUDENT.
            </Typography>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setDeleteDialogOpen(false)} disabled={isSubmitting}>
              Cancel
            </Button>
            <Button
              variant="contained"
              color="error"
              onClick={handleDeleteAdminProfile}
              disabled={isSubmitting}
              startIcon={isSubmitting ? <LoadingSpinner size="sm" /> : <Delete />}
            >
              Delete
            </Button>
          </DialogActions>
        </Dialog>
      </motion.div>
    </Box>
  )
}