import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  Box,
  Typography,
  Grid,
  Card,
  CardContent,
  Button,
  TextField,
  MenuItem,
  FormControl,
  InputLabel,
  Select,
  Switch,
  FormControlLabel,
  Divider,
  Alert,
  Breadcrumbs,
  Link as MuiLink,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Tabs,
  Tab,
  FormHelperText,
} from '@mui/material'
import {
  Save,
  Delete,
  ArrowBack,
  Edit,
  Cancel,
  NavigateNext,
} from '@mui/icons-material'
import { motion } from 'framer-motion'
import { useForm, Controller } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { adminService } from '../../services/adminService'
import { Library } from '../../types'
import { LoadingSpinner } from '../../components/ui/loading-spinner'
import { useToast } from '../../hooks/use-toast'
import { useAuthStore } from '../../stores/authStore'

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
      id={`library-tabpanel-${index}`}
      aria-labelledby={`library-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </div>
  )
}

// Schema for library form
const librarySchema = z.object({
  name: z.string().min(1, 'Name is required'),
  library_type: z.enum(['MAIN', 'BRANCH', 'STUDY_CENTER', 'DIGITAL_HUB'], {
    errorMap: () => ({ message: 'Library type is required' })
  }),
  status: z.enum(['ACTIVE', 'MAINTENANCE', 'CLOSED', 'RENOVATION'], {
    errorMap: () => ({ message: 'Status is required' })
  }),
  address: z.string().min(1, 'Address is required'),
  city: z.string().min(1, 'City is required'),
  postal_code: z.string().optional(),
  phone_number: z.string().optional(),
  email: z.string().email('Invalid email').optional().or(z.literal('')),
  website: z.string().url('Invalid URL').optional().or(z.literal('')),
  opening_time: z.string().min(1, 'Opening time is required'),
  closing_time: z.string().min(1, 'Closing time is required'),
  is_24_hours: z.boolean().default(false),
  total_capacity: z.number().int().min(0, 'Capacity must be a positive number'),
  total_seats: z.number().int().min(0, 'Seats must be a positive number'),
  total_study_rooms: z.number().int().min(0, 'Study rooms must be a positive number'),
  has_wifi: z.boolean().default(true),
  has_printing: z.boolean().default(true),
  has_scanning: z.boolean().default(true),
  has_cafeteria: z.boolean().default(false),
  has_parking: z.boolean().default(false),
  allow_booking: z.boolean().default(true),
  booking_advance_days: z.number().int().min(1, 'Must be at least 1 day'),
  max_booking_duration_hours: z.number().int().min(1, 'Must be at least 1 hour'),
  auto_cancel_minutes: z.number().int().min(5, 'Must be at least 5 minutes'),
  description: z.string().optional(),
});

type LibraryForm = z.infer<typeof librarySchema>;

export function SuperAdminLibraryDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { toast } = useToast();
  const { user } = useAuthStore();
  
  const [library, setLibrary] = useState<Library | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isEditing, setIsEditing] = useState(false);
  const [tabValue, setTabValue] = useState(0);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  
  // Check if we're in create mode (no id parameter)
  const isCreateMode = !id;
  
  // Check if user is super admin
  const isSuperAdmin = user?.role === 'SUPER_ADMIN';

  const {
    control,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<LibraryForm>({
    resolver: zodResolver(librarySchema),
    defaultValues: {
      name: '',
      library_type: 'BRANCH',
      status: 'ACTIVE',
      address: '',
      city: '',
      postal_code: '',
      phone_number: '',
      email: '',
      website: '',
      opening_time: '08:00',
      closing_time: '20:00',
      is_24_hours: false,
      total_capacity: 100,
      total_seats: 50,
      total_study_rooms: 5,
      has_wifi: true,
      has_printing: true,
      has_scanning: true,
      has_cafeteria: false,
      has_parking: false,
      allow_booking: true,
      booking_advance_days: 7,
      max_booking_duration_hours: 8,
      auto_cancel_minutes: 30,
      description: '',
    },
  });

  useEffect(() => {
    if (isCreateMode) {
      // If we're creating a new library, set editing mode to true and stop loading
      setIsEditing(true);
      setIsLoading(false);
    } else if (id) {
      // If we're editing an existing library, fetch its details
      fetchLibraryDetails(id);
    }
  }, [id, isCreateMode]);

  const fetchLibraryDetails = async (libraryId: string) => {
    try {
      setIsLoading(true);
      setError(null);
      
      const libraryData = await adminService.getLibraryDetails(libraryId);
      setLibrary(libraryData);
      
      // Reset form with library data
      reset({
        name: libraryData.name,
        library_type: libraryData.library_type,
        status: libraryData.status,
        address: libraryData.address,
        city: libraryData.city,
        postal_code: libraryData.postal_code || '',
        phone_number: libraryData.phone_number || '',
        email: libraryData.email || '',
        website: libraryData.website || '',
        opening_time: libraryData.opening_time,
        closing_time: libraryData.closing_time,
        is_24_hours: libraryData.is_24_hours,
        total_capacity: libraryData.total_capacity,
        total_seats: libraryData.total_seats,
        total_study_rooms: libraryData.total_study_rooms,
        has_wifi: libraryData.has_wifi,
        has_printing: libraryData.has_printing,
        has_scanning: libraryData.has_scanning,
        has_cafeteria: libraryData.has_cafeteria,
        has_parking: libraryData.has_parking,
        allow_booking: libraryData.allow_booking,
        booking_advance_days: libraryData.booking_advance_days,
        max_booking_duration_hours: libraryData.max_booking_duration_hours,
        auto_cancel_minutes: libraryData.auto_cancel_minutes,
        description: libraryData.description || '',
      });
      
    } catch (error: any) {
      setError(error.message || 'Failed to fetch library details');
    } finally {
      setIsLoading(false);
    }
  };

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  const onSubmit = async (data: LibraryForm) => {
    try {
      setIsSubmitting(true);
      setError(null);
      
      let updatedLibrary;
      
      if (isCreateMode) {
        // Create a new library
        updatedLibrary = await adminService.createLibrary(data);
        
        toast({
          title: "Library Created",
          description: "The library has been created successfully.",
          variant: "default",
        });
        
        // Navigate to the edit page for the newly created library
        navigate(`/superadmin/libraries/${updatedLibrary.id}`);
      } else if (id) {
        // Update existing library
        updatedLibrary = await adminService.updateLibrary(id, data);
        
        setLibrary(updatedLibrary);
        setIsEditing(false);
        
        toast({
          title: "Library Updated",
          description: "The library has been updated successfully.",
          variant: "default",
        });
      }
      
    } catch (error: any) {
      setError(error.message || 'Failed to save library');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDelete = async () => {
    if (!id) return;
    
    try {
      setIsSubmitting(true);
      
      await adminService.deleteLibrary(id);
      
      toast({
        title: "Library Deleted",
        description: "The library has been deleted successfully.",
        variant: "default",
      });
      
      navigate('/superadmin/libraries');
      
    } catch (error: any) {
      setError(error.message || 'Failed to delete library');
      setIsSubmitting(false);
    }
  };

  const handleCancelEdit = () => {
    if (isCreateMode) {
      // If we're creating a new library, navigate back to the libraries list
      navigate('/superadmin/libraries');
    } else if (library) {
      // If we're editing an existing library, reset form to original values
      reset({
        name: library.name,
        library_type: library.library_type,
        status: library.status,
        address: library.address,
        city: library.city,
        postal_code: library.postal_code || '',
        phone_number: library.phone_number || '',
        email: library.email || '',
        website: library.website || '',
        opening_time: library.opening_time,
        closing_time: library.closing_time,
        is_24_hours: library.is_24_hours,
        total_capacity: library.total_capacity,
        total_seats: library.total_seats,
        total_study_rooms: library.total_study_rooms,
        has_wifi: library.has_wifi,
        has_printing: library.has_printing,
        has_scanning: library.has_scanning,
        has_cafeteria: library.has_cafeteria,
        has_parking: library.has_parking,
        allow_booking: library.allow_booking,
        booking_advance_days: library.booking_advance_days,
        max_booking_duration_hours: library.max_booking_duration_hours,
        auto_cancel_minutes: library.auto_cancel_minutes,
        description: library.description || '',
      });
      setIsEditing(false);
    }
  };

  if (isLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '50vh' }}>
        <LoadingSpinner size="lg" />
      </Box>
    );
  }

  if (error && !library && !isCreateMode) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
        <Button
          variant="outlined"
          startIcon={<ArrowBack />}
          onClick={() => navigate('/superadmin/libraries')}
        >
          Back to Libraries
        </Button>
      </Box>
    );
  }

  if (!library && !isCreateMode) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="warning" sx={{ mb: 3 }}>
          Library not found
        </Alert>
        <Button
          variant="outlined"
          startIcon={<ArrowBack />}
          onClick={() => navigate('/superadmin/libraries')}
        >
          Back to Libraries
        </Button>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
      >
        {/* Breadcrumbs */}
        <Breadcrumbs separator={<NavigateNext fontSize="small" />} sx={{ mb: 2 }}>
          <MuiLink
            component="button"
            variant="body2"
            onClick={() => navigate('/superadmin')}
            underline="hover"
            color="inherit"
          >
            SuperAdmin
          </MuiLink>
          <MuiLink
            component="button"
            variant="body2"
            onClick={() => navigate('/superadmin/libraries')}
            underline="hover"
            color="inherit"
          >
            Libraries
          </MuiLink>
          <Typography color="text.primary">
            {isCreateMode ? 'Create New Library' : library?.name}
          </Typography>
        </Breadcrumbs>

        <Box sx={{ mb: 4, display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <Box>
            <Typography variant="h4" component="h1" gutterBottom>
              {isCreateMode ? 'Create New Library' : library?.name}
            </Typography>
            {!isCreateMode && (
              <Typography variant="body1" color="text.secondary">
                {library?.code} • {library?.library_type.replace('_', ' ')}
              </Typography>
            )}
          </Box>
          
          <Box sx={{ display: 'flex', gap: 2 }}>
            {!isEditing && !isCreateMode && (
              <Button
                variant="outlined"
                startIcon={<Edit />}
                onClick={() => setIsEditing(true)}
              >
                Edit Library
              </Button>
            )}
            
            {(isEditing || isCreateMode) && (
              <>
                <Button
                  variant="outlined"
                  color="secondary"
                  startIcon={<Cancel />}
                  onClick={handleCancelEdit}
                >
                  Cancel
                </Button>
                <Button
                  variant="contained"
                  color="primary"
                  startIcon={isSubmitting ? <LoadingSpinner size="sm" /> : <Save />}
                  onClick={handleSubmit(onSubmit)}
                  disabled={isSubmitting}
                >
                  {isCreateMode ? 'Create Library' : 'Save Changes'}
                </Button>
              </>
            )}
            
            {isSuperAdmin && !isCreateMode && !isEditing && (
              <Button
                variant="outlined"
                color="error"
                startIcon={<Delete />}
                onClick={() => setDeleteDialogOpen(true)}
              >
                Delete
              </Button>
            )}
            
            <Button
              variant="outlined"
              startIcon={<ArrowBack />}
              onClick={() => navigate('/superadmin/libraries')}
            >
              Back
            </Button>
          </Box>
        </Box>

        {error && (
          <Alert severity="error" sx={{ mb: 3 }}>
            {error}
          </Alert>
        )}

        <Card>
          <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
            <Tabs
              value={tabValue}
              onChange={handleTabChange}
              aria-label="library tabs"
              variant="scrollable"
              scrollButtons="auto"
            >
              <Tab label="Basic Information" />
              <Tab label="Features & Capacity" />
              <Tab label="Booking Settings" />
              {!isCreateMode && <Tab label="Statistics" />}
            </Tabs>
          </Box>

          {/* Basic Information Tab */}
          <TabPanel value={tabValue} index={0}>
            <Box component="form" noValidate>
              <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                  <Controller
                    name="name"
                    control={control}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="Library Name"
                        fullWidth
                        error={!!errors.name}
                        helperText={errors.name?.message}
                        disabled={!isEditing && !isCreateMode}
                        required
                      />
                    )}
                  />
                </Grid>
                <Grid item xs={12} md={6}>
                  <Controller
                    name="library_type"
                    control={control}
                    render={({ field }) => (
                      <FormControl fullWidth error={!!errors.library_type} required>
                        <InputLabel>Library Type</InputLabel>
                        <Select
                          {...field}
                          label="Library Type"
                          disabled={!isEditing && !isCreateMode}
                        >
                          <MenuItem value="MAIN">Main Library</MenuItem>
                          <MenuItem value="BRANCH">Branch Library</MenuItem>
                          <MenuItem value="STUDY_CENTER">Study Center</MenuItem>
                          <MenuItem value="DIGITAL_HUB">Digital Hub</MenuItem>
                        </Select>
                        {errors.library_type && (
                          <FormHelperText>{errors.library_type.message}</FormHelperText>
                        )}
                      </FormControl>
                    )}
                  />
                </Grid>
                <Grid item xs={12} md={6}>
                  <Controller
                    name="status"
                    control={control}
                    render={({ field }) => (
                      <FormControl fullWidth error={!!errors.status} required>
                        <InputLabel>Status</InputLabel>
                        <Select
                          {...field}
                          label="Status"
                          disabled={!isEditing && !isCreateMode}
                        >
                          <MenuItem value="ACTIVE">Active</MenuItem>
                          <MenuItem value="MAINTENANCE">Under Maintenance</MenuItem>
                          <MenuItem value="CLOSED">Temporarily Closed</MenuItem>
                          <MenuItem value="RENOVATION">Under Renovation</MenuItem>
                        </Select>
                        {errors.status && (
                          <FormHelperText>{errors.status.message}</FormHelperText>
                        )}
                      </FormControl>
                    )}
                  />
                </Grid>
                <Grid item xs={12} md={6}>
                  <Controller
                    name="description"
                    control={control}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="Description"
                        fullWidth
                        multiline
                        rows={3}
                        error={!!errors.description}
                        helperText={errors.description?.message}
                        disabled={!isEditing && !isCreateMode}
                      />
                    )}
                  />
                </Grid>
                
                <Grid item xs={12}>
                  <Divider sx={{ my: 2 }}>Location Information</Divider>
                </Grid>
                
                <Grid item xs={12} md={12}>
                  <Controller
                    name="address"
                    control={control}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="Address"
                        fullWidth
                        error={!!errors.address}
                        helperText={errors.address?.message}
                        disabled={!isEditing && !isCreateMode}
                        required
                      />
                    )}
                  />
                </Grid>
                <Grid item xs={12} md={6}>
                  <Controller
                    name="city"
                    control={control}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="City"
                        fullWidth
                        error={!!errors.city}
                        helperText={errors.city?.message}
                        disabled={!isEditing && !isCreateMode}
                        required
                      />
                    )}
                  />
                </Grid>
                <Grid item xs={12} md={6}>
                  <Controller
                    name="postal_code"
                    control={control}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="Postal Code"
                        fullWidth
                        error={!!errors.postal_code}
                        helperText={errors.postal_code?.message}
                        disabled={!isEditing && !isCreateMode}
                      />
                    )}
                  />
                </Grid>
                
                <Grid item xs={12}>
                  <Divider sx={{ my: 2 }}>Contact Information</Divider>
                </Grid>
                
                <Grid item xs={12} md={4}>
                  <Controller
                    name="phone_number"
                    control={control}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="Phone Number"
                        fullWidth
                        error={!!errors.phone_number}
                        helperText={errors.phone_number?.message}
                        disabled={!isEditing && !isCreateMode}
                      />
                    )}
                  />
                </Grid>
                <Grid item xs={12} md={4}>
                  <Controller
                    name="email"
                    control={control}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="Email"
                        fullWidth
                        error={!!errors.email}
                        helperText={errors.email?.message}
                        disabled={!isEditing && !isCreateMode}
                      />
                    )}
                  />
                </Grid>
                <Grid item xs={12} md={4}>
                  <Controller
                    name="website"
                    control={control}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="Website"
                        fullWidth
                        error={!!errors.website}
                        helperText={errors.website?.message}
                        disabled={!isEditing && !isCreateMode}
                      />
                    )}
                  />
                </Grid>
                
                <Grid item xs={12}>
                  <Divider sx={{ my: 2 }}>Operating Hours</Divider>
                </Grid>
                
                <Grid item xs={12} md={4}>
                  <Controller
                    name="opening_time"
                    control={control}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="Opening Time"
                        type="time"
                        fullWidth
                        error={!!errors.opening_time}
                        helperText={errors.opening_time?.message}
                        disabled={(!isEditing && !isCreateMode) || control._formValues.is_24_hours}
                        required
                        InputLabelProps={{ shrink: true }}
                      />
                    )}
                  />
                </Grid>
                <Grid item xs={12} md={4}>
                  <Controller
                    name="closing_time"
                    control={control}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="Closing Time"
                        type="time"
                        fullWidth
                        error={!!errors.closing_time}
                        helperText={errors.closing_time?.message}
                        disabled={(!isEditing && !isCreateMode) || control._formValues.is_24_hours}
                        required
                        InputLabelProps={{ shrink: true }}
                      />
                    )}
                  />
                </Grid>
                <Grid item xs={12} md={4}>
                  <Controller
                    name="is_24_hours"
                    control={control}
                    render={({ field }) => (
                      <FormControlLabel
                        control={
                          <Switch
                            checked={field.value}
                            onChange={(e) => field.onChange(e.target.checked)}
                            disabled={!isEditing && !isCreateMode}
                          />
                        }
                        label="Open 24 Hours"
                      />
                    )}
                  />
                </Grid>
              </Grid>
            </Box>
          </TabPanel>

          {/* Features & Capacity Tab */}
          <TabPanel value={tabValue} index={1}>
            <Box component="form" noValidate>
              <Grid container spacing={3}>
                <Grid item xs={12}>
                  <Divider sx={{ my: 2 }}>Capacity</Divider>
                </Grid>
                
                <Grid item xs={12} md={4}>
                  <Controller
                    name="total_capacity"
                    control={control}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="Total Capacity"
                        type="number"
                        fullWidth
                        error={!!errors.total_capacity}
                        helperText={errors.total_capacity?.message}
                        disabled={!isEditing && !isCreateMode}
                        InputProps={{ inputProps: { min: 0 } }}
                        onChange={(e) => field.onChange(Number(e.target.value))}
                      />
                    )}
                  />
                </Grid>
                <Grid item xs={12} md={4}>
                  <Controller
                    name="total_seats"
                    control={control}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="Total Seats"
                        type="number"
                        fullWidth
                        error={!!errors.total_seats}
                        helperText={errors.total_seats?.message}
                        disabled={!isEditing && !isCreateMode}
                        InputProps={{ inputProps: { min: 0 } }}
                        onChange={(e) => field.onChange(Number(e.target.value))}
                      />
                    )}
                  />
                </Grid>
                <Grid item xs={12} md={4}>
                  <Controller
                    name="total_study_rooms"
                    control={control}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="Total Study Rooms"
                        type="number"
                        fullWidth
                        error={!!errors.total_study_rooms}
                        helperText={errors.total_study_rooms?.message}
                        disabled={!isEditing && !isCreateMode}
                        InputProps={{ inputProps: { min: 0 } }}
                        onChange={(e) => field.onChange(Number(e.target.value))}
                      />
                    )}
                  />
                </Grid>
                
                <Grid item xs={12}>
                  <Divider sx={{ my: 2 }}>Features</Divider>
                </Grid>
                
                <Grid item xs={12} md={4}>
                  <Controller
                    name="has_wifi"
                    control={control}
                    render={({ field }) => (
                      <FormControlLabel
                        control={
                          <Switch
                            checked={field.value}
                            onChange={(e) => field.onChange(e.target.checked)}
                            disabled={!isEditing && !isCreateMode}
                          />
                        }
                        label="WiFi Available"
                      />
                    )}
                  />
                </Grid>
                <Grid item xs={12} md={4}>
                  <Controller
                    name="has_printing"
                    control={control}
                    render={({ field }) => (
                      <FormControlLabel
                        control={
                          <Switch
                            checked={field.value}
                            onChange={(e) => field.onChange(e.target.checked)}
                            disabled={!isEditing && !isCreateMode}
                          />
                        }
                        label="Printing Services"
                      />
                    )}
                  />
                </Grid>
                <Grid item xs={12} md={4}>
                  <Controller
                    name="has_scanning"
                    control={control}
                    render={({ field }) => (
                      <FormControlLabel
                        control={
                          <Switch
                            checked={field.value}
                            onChange={(e) => field.onChange(e.target.checked)}
                            disabled={!isEditing && !isCreateMode}
                          />
                        }
                        label="Scanning Services"
                      />
                    )}
                  />
                </Grid>
                <Grid item xs={12} md={4}>
                  <Controller
                    name="has_cafeteria"
                    control={control}
                    render={({ field }) => (
                      <FormControlLabel
                        control={
                          <Switch
                            checked={field.value}
                            onChange={(e) => field.onChange(e.target.checked)}
                            disabled={!isEditing && !isCreateMode}
                          />
                        }
                        label="Cafeteria"
                      />
                    )}
                  />
                </Grid>
                <Grid item xs={12} md={4}>
                  <Controller
                    name="has_parking"
                    control={control}
                    render={({ field }) => (
                      <FormControlLabel
                        control={
                          <Switch
                            checked={field.value}
                            onChange={(e) => field.onChange(e.target.checked)}
                            disabled={!isEditing && !isCreateMode}
                          />
                        }
                        label="Parking Available"
                      />
                    )}
                  />
                </Grid>
              </Grid>
            </Box>
          </TabPanel>

          {/* Booking Settings Tab */}
          <TabPanel value={tabValue} index={2}>
            <Box component="form" noValidate>
              <Grid container spacing={3}>
                <Grid item xs={12} md={4}>
                  <Controller
                    name="allow_booking"
                    control={control}
                    render={({ field }) => (
                      <FormControlLabel
                        control={
                          <Switch
                            checked={field.value}
                            onChange={(e) => field.onChange(e.target.checked)}
                            disabled={!isEditing && !isCreateMode}
                          />
                        }
                        label="Allow Seat Booking"
                      />
                    )}
                  />
                </Grid>
                <Grid item xs={12} md={4}>
                  <Controller
                    name="booking_advance_days"
                    control={control}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="Advance Booking Days"
                        type="number"
                        fullWidth
                        error={!!errors.booking_advance_days}
                        helperText={errors.booking_advance_days?.message}
                        disabled={(!isEditing && !isCreateMode) || !control._formValues.allow_booking}
                        InputProps={{ inputProps: { min: 1 } }}
                        onChange={(e) => field.onChange(Number(e.target.value))}
                      />
                    )}
                  />
                </Grid>
                <Grid item xs={12} md={4}>
                  <Controller
                    name="max_booking_duration_hours"
                    control={control}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="Max Booking Duration (hours)"
                        type="number"
                        fullWidth
                        error={!!errors.max_booking_duration_hours}
                        helperText={errors.max_booking_duration_hours?.message}
                        disabled={(!isEditing && !isCreateMode) || !control._formValues.allow_booking}
                        InputProps={{ inputProps: { min: 1 } }}
                        onChange={(e) => field.onChange(Number(e.target.value))}
                      />
                    )}
                  />
                </Grid>
                <Grid item xs={12} md={4}>
                  <Controller
                    name="auto_cancel_minutes"
                    control={control}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="Auto-Cancel No-Show (minutes)"
                        type="number"
                        fullWidth
                        error={!!errors.auto_cancel_minutes}
                        helperText={errors.auto_cancel_minutes?.message}
                        disabled={(!isEditing && !isCreateMode) || !control._formValues.allow_booking}
                        InputProps={{ inputProps: { min: 5 } }}
                        onChange={(e) => field.onChange(Number(e.target.value))}
                      />
                    )}
                  />
                </Grid>
              </Grid>
            </Box>
          </TabPanel>

          {/* Statistics Tab - Only show for existing libraries */}
          {!isCreateMode && (
            <TabPanel value={tabValue} index={3}>
              <Grid container spacing={3}>
                <Grid item xs={12} md={4}>
                  <Card variant="outlined">
                    <CardContent>
                      <Typography variant="h6" gutterBottom>
                        Total Visits
                      </Typography>
                      <Typography variant="h3">
                        {library?.total_visits.toLocaleString()}
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Card variant="outlined">
                    <CardContent>
                      <Typography variant="h6" gutterBottom>
                        Average Rating
                      </Typography>
                      <Typography variant="h3">
                        {Number(library?.average_rating || 0).toFixed(1)}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        Based on {library?.total_reviews} reviews
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Card variant="outlined">
                    <CardContent>
                      <Typography variant="h6" gutterBottom>
                        Current Occupancy
                      </Typography>
                      <Typography variant="h3">
                        {Number(library?.occupancy_rate || 0).toFixed(1)}%
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        {library?.occupied_seats} of {library?.total_seats} seats occupied
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
                
                <Grid item xs={12}>
                  <Box sx={{ mt: 3, display: 'flex', justifyContent: 'center' }}>
                    <Button
                      variant="outlined"
                      onClick={() => navigate(`/superadmin/libraries/${id}/statistics`)}
                    >
                      View Detailed Statistics
                    </Button>
                  </Box>
                </Grid>
              </Grid>
            </TabPanel>
          )}
        </Card>

        {/* Delete Confirmation Dialog */}
        <Dialog
          open={deleteDialogOpen}
          onClose={() => !isSubmitting && setDeleteDialogOpen(false)}
          aria-labelledby="delete-dialog-title"
        >
          <DialogTitle id="delete-dialog-title">Delete Library</DialogTitle>
          <DialogContent>
            <Typography variant="body1">
              Are you sure you want to delete the library "{library?.name}"? This action cannot be undone.
            </Typography>
            <Typography variant="body2" color="error" sx={{ mt: 2 }}>
              All associated data including floors, sections, seats, and bookings will also be deleted.
            </Typography>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setDeleteDialogOpen(false)} disabled={isSubmitting}>
              Cancel
            </Button>
            <Button
              onClick={handleDelete}
              color="error"
              disabled={isSubmitting}
              startIcon={isSubmitting ? <LoadingSpinner size="sm" /> : <Delete />}
            >
              Delete Library
            </Button>
          </DialogActions>
        </Dialog>
      </motion.div>
    </Box>
  );
}