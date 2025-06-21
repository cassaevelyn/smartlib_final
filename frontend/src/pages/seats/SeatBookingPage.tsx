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
  MenuItem,
  FormControl,
  InputLabel,
  Select,
  Alert,
  Stepper,
  Step,
  StepLabel,
  Paper,
  Divider,
  Chip,
  FormHelperText,
  Breadcrumbs,
  Link as MuiLink,
} from '@mui/material'
import { DatePicker } from '@mui/x-date-pickers/DatePicker'
import { TimePicker } from '@mui/x-date-pickers/TimePicker'
import {
  EventSeat,
  LocationOn,
  AccessTime,
  Check,
  NavigateNext,
  ArrowBack,
} from '@mui/icons-material'
import { motion } from 'framer-motion'
import { useForm, Controller } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { seatService } from '../../services/seatService'
import { libraryService } from '../../services/libraryService'
import { Seat, Library, LibraryFloor, LibrarySection, SeatBooking } from '../../types'
import { LoadingSpinner } from '../../components/ui/loading-spinner'
import { useToast } from '../../hooks/use-toast'
import { formatDate, formatTime } from '../../lib/utils'

// Schema for the booking form
const bookingSchema = z.object({
  seat: z.string().min(1, 'Seat is required'),
  booking_date: z.string().min(1, 'Date is required'),
  start_time: z.string().min(1, 'Start time is required'),
  end_time: z.string().min(1, 'End time is required'),
  booking_type: z.string().optional(),
  purpose: z.string().optional(),
  special_requirements: z.string().optional(),
  notes: z.string().optional(),
}).refine((data) => {
  if (!data.start_time || !data.end_time) return true
  return data.start_time < data.end_time
}, {
  message: "End time must be after start time",
  path: ["end_time"],
})

type BookingForm = z.infer<typeof bookingSchema>

const steps = ['Select Seat', 'Choose Time', 'Confirm Booking']

export function SeatBookingPage() {
  const navigate = useNavigate()
  const location = useLocation()
  const { toast } = useToast()
  const queryParams = new URLSearchParams(location.search)
  
  const [activeStep, setActiveStep] = useState(0)
  const [libraries, setLibraries] = useState<Library[]>([])
  const [floors, setFloors] = useState<LibraryFloor[]>([])
  const [sections, setSections] = useState<LibrarySection[]>([])
  const [seats, setSeats] = useState<Seat[]>([])
  const [selectedSeat, setSelectedSeat] = useState<Seat | null>(null)
  const [availableTimeSlots, setAvailableTimeSlots] = useState<any[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const {
    control,
    handleSubmit,
    watch,
    setValue,
    formState: { errors, isValid },
  } = useForm<BookingForm>({
    resolver: zodResolver(bookingSchema),
    defaultValues: {
      seat: queryParams.get('seat') || '',
      booking_date: queryParams.get('date') || new Date().toISOString().split('T')[0],
      start_time: '',
      end_time: '',
      booking_type: 'REGULAR',
      purpose: '',
      special_requirements: '',
      notes: '',
    },
  })

  const watchedSeat = watch('seat')
  const watchedDate = watch('booking_date')
  const watchedLibrary = watch('library_id')
  const watchedFloor = watch('floor_id')
  const watchedSection = watch('section_id')

  useEffect(() => {
    fetchLibraries()
    
    if (queryParams.get('seat')) {
      fetchSeatDetails(queryParams.get('seat') as string)
      setActiveStep(1) // Skip to time selection if seat is provided
    } else if (queryParams.get('library')) {
      fetchLibraryDetails(queryParams.get('library') as string)
    } else {
      setIsLoading(false)
    }
  }, [])

  useEffect(() => {
    if (watchedSeat && watchedDate) {
      fetchSeatAvailability(watchedSeat, watchedDate)
    }
  }, [watchedSeat, watchedDate])

  const fetchLibraries = async () => {
    try {
      const response = await libraryService.getLibraries()
      setLibraries(response.results)
    } catch (error: any) {
      console.error('Failed to fetch libraries:', error)
    }
  }

  const fetchLibraryDetails = async (libraryId: string) => {
    try {
      setIsLoading(true)
      
      const library = await libraryService.getLibrary(libraryId)
      const floorsData = await libraryService.getLibraryFloors(libraryId)
      setFloors(floorsData)
      
      if (floorsData.length > 0) {
        const sectionsData = await libraryService.getFloorSections(floorsData[0].id)
        setSections(sectionsData)
        
        if (sectionsData.length > 0) {
          const seatsResponse = await seatService.getSectionSeats(sectionsData[0].id)
          setSeats(seatsResponse.results)
        }
      }
      
      setIsLoading(false)
    } catch (error: any) {
      setError(error.message || 'Failed to fetch library details')
      setIsLoading(false)
    }
  }

  const fetchSeatDetails = async (seatId: string) => {
    try {
      setIsLoading(true)
      
      const seat = await seatService.getSeat(seatId)
      setSelectedSeat(seat)
      
      setIsLoading(false)
    } catch (error: any) {
      setError(error.message || 'Failed to fetch seat details')
      setIsLoading(false)
    }
  }

  const fetchSeatAvailability = async (seatId: string, date: string) => {
    try {
      setIsLoading(true)
      
      const availability = await seatService.checkSeatAvailability(seatId, date)
      
      if (availability.available_slots) {
        setAvailableTimeSlots(availability.available_slots)
      }
      
      setIsLoading(false)
    } catch (error: any) {
      setError(error.message || 'Failed to fetch seat availability')
      setIsLoading(false)
    }
  }

  const handleLibraryChange = async (libraryId: string) => {
    setValue('library_id', libraryId)
    setValue('floor_id', '')
    setValue('section_id', '')
    setValue('seat', '')
    
    setFloors([])
    setSections([])
    setSeats([])
    
    if (libraryId) {
      try {
        setIsLoading(true)
        const floorsData = await libraryService.getLibraryFloors(libraryId)
        setFloors(floorsData)
        setIsLoading(false)
      } catch (error: any) {
        setError(error.message || 'Failed to fetch floors')
        setIsLoading(false)
      }
    }
  }

  const handleFloorChange = async (floorId: string) => {
    setValue('floor_id', floorId)
    setValue('section_id', '')
    setValue('seat', '')
    
    setSections([])
    setSeats([])
    
    if (floorId) {
      try {
        setIsLoading(true)
        const sectionsData = await libraryService.getFloorSections(floorId)
        setSections(sectionsData)
        setIsLoading(false)
      } catch (error: any) {
        setError(error.message || 'Failed to fetch sections')
        setIsLoading(false)
      }
    }
  }

  const handleSectionChange = async (sectionId: string) => {
    setValue('section_id', sectionId)
    setValue('seat', '')
    
    setSeats([])
    
    if (sectionId) {
      try {
        setIsLoading(true)
        const seatsResponse = await seatService.getSectionSeats(sectionId)
        setSeats(seatsResponse.results)
        setIsLoading(false)
      } catch (error: any) {
        setError(error.message || 'Failed to fetch seats')
        setIsLoading(false)
      }
    }
  }

  const handleSeatSelect = (seat: Seat) => {
    setValue('seat', seat.id)
    setSelectedSeat(seat)
    handleNext()
  }

  const handleTimeSlotSelect = (startTime: string, endTime: string) => {
    setValue('start_time', startTime)
    setValue('end_time', endTime)
    handleNext()
  }

  const handleNext = () => {
    setActiveStep((prevStep) => prevStep + 1)
  }

  const handleBack = () => {
    setActiveStep((prevStep) => prevStep - 1)
  }

  const onSubmit = async (data: BookingForm) => {
    try {
      setIsSubmitting(true)
      setError(null)
      
      const booking = await seatService.createBooking(data)
      
      toast({
        title: "Booking Successful",
        description: `Your seat has been booked successfully. Booking code: ${booking.booking_code}`,
        variant: "default",
      })
      
      navigate('/my-bookings')
    } catch (error: any) {
      setError(error.message || 'Failed to create booking')
      setIsSubmitting(false)
    }
  }

  const renderStepContent = (step: number) => {
    switch (step) {
      case 0:
        return (
          <Box>
            <Typography variant="h6" gutterBottom>
              Select a Seat
            </Typography>
            
            {!queryParams.get('seat') && (
              <Grid container spacing={2} sx={{ mb: 3 }}>
                <Grid item xs={12} md={4}>
                  <FormControl fullWidth>
                    <InputLabel>Library</InputLabel>
                    <Controller
                      name="library_id"
                      control={control}
                      render={({ field }) => (
                        <Select
                          {...field}
                          label="Library"
                          onChange={(e) => {
                            field.onChange(e)
                            handleLibraryChange(e.target.value)
                          }}
                        >
                          <MenuItem value="">Select Library</MenuItem>
                          {libraries.map((library) => (
                            <MenuItem key={library.id} value={library.id}>
                              {library.name}
                            </MenuItem>
                          ))}
                        </Select>
                      )}
                    />
                  </FormControl>
                </Grid>
                <Grid item xs={12} md={4}>
                  <FormControl fullWidth>
                    <InputLabel>Floor</InputLabel>
                    <Controller
                      name="floor_id"
                      control={control}
                      render={({ field }) => (
                        <Select
                          {...field}
                          label="Floor"
                          onChange={(e) => {
                            field.onChange(e)
                            handleFloorChange(e.target.value)
                          }}
                          disabled={!watchedLibrary || floors.length === 0}
                        >
                          <MenuItem value="">Select Floor</MenuItem>
                          {floors.map((floor) => (
                            <MenuItem key={floor.id} value={floor.id}>
                              {floor.floor_name}
                            </MenuItem>
                          ))}
                        </Select>
                      )}
                    />
                  </FormControl>
                </Grid>
                <Grid item xs={12} md={4}>
                  <FormControl fullWidth>
                    <InputLabel>Section</InputLabel>
                    <Controller
                      name="section_id"
                      control={control}
                      render={({ field }) => (
                        <Select
                          {...field}
                          label="Section"
                          onChange={(e) => {
                            field.onChange(e)
                            handleSectionChange(e.target.value)
                          }}
                          disabled={!watchedFloor || sections.length === 0}
                        >
                          <MenuItem value="">Select Section</MenuItem>
                          {sections.map((section) => (
                            <MenuItem key={section.id} value={section.id}>
                              {section.name}
                            </MenuItem>
                          ))}
                        </Select>
                      )}
                    />
                  </FormControl>
                </Grid>
              </Grid>
            )}
            
            {isLoading ? (
              <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
                <LoadingSpinner size="md" />
              </Box>
            ) : seats.length === 0 ? (
              <Alert severity="info" sx={{ mt: 2 }}>
                {watchedSection
                  ? 'No seats available in this section. Please select a different section.'
                  : watchedFloor
                  ? 'Please select a section to view available seats.'
                  : watchedLibrary
                  ? 'Please select a floor to continue.'
                  : 'Please select a library to start.'}
              </Alert>
            ) : (
              <Grid container spacing={2}>
                {seats.map((seat) => (
                  <Grid item xs={12} sm={6} md={4} lg={3} key={seat.id}>
                    <motion.div
                      whileHover={{ y: -5, transition: { duration: 0.2 } }}
                    >
                      <Card
                        sx={{
                          cursor: seat.is_available ? 'pointer' : 'default',
                          opacity: seat.is_available ? 1 : 0.7,
                          border: seat.id === watchedSeat ? 2 : 0,
                          borderColor: 'primary.main',
                        }}
                        onClick={() => seat.is_available && handleSeatSelect(seat)}
                      >
                        <CardContent>
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
                            {seat.seat_type_display}
                          </Typography>
                          
                          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mb: 2 }}>
                            {seat.has_power_outlet && (
                              <Chip icon={<EventSeat />} label="Power" size="small" variant="outlined" />
                            )}
                            {seat.has_ethernet && (
                              <Chip icon={<EventSeat />} label="Ethernet" size="small" variant="outlined" />
                            )}
                            {seat.has_monitor && (
                              <Chip icon={<EventSeat />} label="Monitor" size="small" variant="outlined" />
                            )}
                          </Box>
                          
                          {!seat.is_available && (
                            <Typography variant="body2" color="error">
                              Not available
                            </Typography>
                          )}
                        </CardContent>
                      </Card>
                    </motion.div>
                  </Grid>
                ))}
              </Grid>
            )}
          </Box>
        )
      case 1:
        return (
          <Box>
            <Typography variant="h6" gutterBottom>
              Choose Time
            </Typography>
            
            {selectedSeat && (
              <Card sx={{ mb: 3 }}>
                <CardContent>
                  <Typography variant="subtitle1" gutterBottom>
                    Selected Seat: {selectedSeat.seat_number}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {selectedSeat.library_name} • {selectedSeat.floor_name} • {selectedSeat.section_name}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Type: {selectedSeat.seat_type_display}
                  </Typography>
                </CardContent>
              </Card>
            )}
            
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={4}>
                <Controller
                  name="booking_date"
                  control={control}
                  render={({ field }) => (
                    <DatePicker
                      label="Date"
                      value={field.value ? new Date(field.value) : null}
                      onChange={(newValue) => {
                        if (newValue) {
                          field.onChange(newValue.toISOString().split('T')[0])
                        }
                      }}
                      slotProps={{
                        textField: {
                          fullWidth: true,
                          error: !!errors.booking_date,
                          helperText: errors.booking_date?.message,
                        }
                      }}
                    />
                  )}
                />
              </Grid>
              <Grid item xs={12} md={4}>
                <Controller
                  name="start_time"
                  control={control}
                  render={({ field }) => (
                    <TimePicker
                      label="Start Time"
                      value={field.value ? new Date(`2023-01-01T${field.value}`) : null}
                      onChange={(newValue) => {
                        if (newValue) {
                          const timeString = newValue.toTimeString().split(' ')[0].substring(0, 5)
                          field.onChange(timeString)
                        }
                      }}
                      slotProps={{
                        textField: {
                          fullWidth: true,
                          error: !!errors.start_time,
                          helperText: errors.start_time?.message,
                        }
                      }}
                    />
                  )}
                />
              </Grid>
              <Grid item xs={12} md={4}>
                <Controller
                  name="end_time"
                  control={control}
                  render={({ field }) => (
                    <TimePicker
                      label="End Time"
                      value={field.value ? new Date(`2023-01-01T${field.value}`) : null}
                      onChange={(newValue) => {
                        if (newValue) {
                          const timeString = newValue.toTimeString().split(' ')[0].substring(0, 5)
                          field.onChange(timeString)
                        }
                      }}
                      slotProps={{
                        textField: {
                          fullWidth: true,
                          error: !!errors.end_time,
                          helperText: errors.end_time?.message,
                        }
                      }}
                    />
                  )}
                />
              </Grid>
            </Grid>
            
            <Typography variant="subtitle1" gutterBottom>
              Available Time Slots
            </Typography>
            
            {isLoading ? (
              <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
                <LoadingSpinner size="md" />
              </Box>
            ) : availableTimeSlots.length === 0 ? (
              <Alert severity="info">
                No available time slots for the selected date. Please try another date.
              </Alert>
            ) : (
              <Grid container spacing={2}>
                {availableTimeSlots.map((slot, index) => (
                  <Grid item xs={12} sm={6} md={4} key={index}>
                    <motion.div
                      whileHover={{ y: -5, transition: { duration: 0.2 } }}
                    >
                      <Card
                        sx={{ cursor: 'pointer' }}
                        onClick={() => handleTimeSlotSelect(slot.start_time, slot.end_time)}
                      >
                        <CardContent>
                          <Typography variant="subtitle1">
                            {formatTime(slot.start_time)} - {formatTime(slot.end_time)}
                          </Typography>
                          <Typography variant="body2" color="text.secondary">
                            Duration: {Math.round(slot.duration_minutes / 60 * 10) / 10} hours
                          </Typography>
                        </CardContent>
                      </Card>
                    </motion.div>
                  </Grid>
                ))}
              </Grid>
            )}
            
            <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 3 }}>
              <Button
                variant="outlined"
                onClick={handleBack}
                startIcon={<ArrowBack />}
              >
                Back
              </Button>
              <Button
                variant="contained"
                onClick={handleNext}
                endIcon={<NavigateNext />}
                disabled={!watch('start_time') || !watch('end_time')}
              >
                Next
              </Button>
            </Box>
          </Box>
        )
      case 2:
        return (
          <Box>
            <Typography variant="h6" gutterBottom>
              Confirm Booking
            </Typography>
            
            <Card sx={{ mb: 3 }}>
              <CardContent>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" color="text.secondary">
                      Seat
                    </Typography>
                    <Typography variant="body1" gutterBottom>
                      {selectedSeat?.seat_number}
                    </Typography>
                    
                    <Typography variant="subtitle2" color="text.secondary">
                      Location
                    </Typography>
                    <Typography variant="body1" gutterBottom>
                      {selectedSeat?.library_name}, {selectedSeat?.floor_name}, {selectedSeat?.section_name}
                    </Typography>
                    
                    <Typography variant="subtitle2" color="text.secondary">
                      Seat Type
                    </Typography>
                    <Typography variant="body1" gutterBottom>
                      {selectedSeat?.seat_type_display}
                    </Typography>
                  </Grid>
                  
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" color="text.secondary">
                      Date
                    </Typography>
                    <Typography variant="body1" gutterBottom>
                      {formatDate(watch('booking_date'))}
                    </Typography>
                    
                    <Typography variant="subtitle2" color="text.secondary">
                      Time
                    </Typography>
                    <Typography variant="body1" gutterBottom>
                      {watch('start_time')} - {watch('end_time')}
                    </Typography>
                    
                    <Typography variant="subtitle2" color="text.secondary">
                      Duration
                    </Typography>
                    <Typography variant="body1" gutterBottom>
                      {(() => {
                        const start = new Date(`2023-01-01T${watch('start_time')}`)
                        const end = new Date(`2023-01-01T${watch('end_time')}`)
                        const diffMs = end.getTime() - start.getTime()
                        const diffHrs = diffMs / (1000 * 60 * 60)
                        return `${diffHrs} hours`
                      })()}
                    </Typography>
                  </Grid>
                </Grid>
              </CardContent>
            </Card>
            
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12}>
                <Controller
                  name="purpose"
                  control={control}
                  render={({ field }) => (
                    <TextField
                      {...field}
                      label="Purpose of Booking"
                      fullWidth
                      placeholder="e.g., Study, Group Project, Research"
                    />
                  )}
                />
              </Grid>
              <Grid item xs={12}>
                <Controller
                  name="special_requirements"
                  control={control}
                  render={({ field }) => (
                    <TextField
                      {...field}
                      label="Special Requirements"
                      fullWidth
                      placeholder="Any special requirements or accommodations needed"
                    />
                  )}
                />
              </Grid>
              <Grid item xs={12}>
                <Controller
                  name="notes"
                  control={control}
                  render={({ field }) => (
                    <TextField
                      {...field}
                      label="Additional Notes"
                      fullWidth
                      multiline
                      rows={3}
                      placeholder="Any additional notes for the library staff"
                    />
                  )}
                />
              </Grid>
            </Grid>
            
            {error && (
              <Alert severity="error" sx={{ mb: 3 }}>
                {error}
              </Alert>
            )}
            
            <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
              <Button
                variant="outlined"
                onClick={handleBack}
                startIcon={<ArrowBack />}
              >
                Back
              </Button>
              <Button
                variant="contained"
                onClick={handleSubmit(onSubmit)}
                disabled={isSubmitting}
                endIcon={<Check />}
              >
                {isSubmitting ? <LoadingSpinner size="sm" /> : 'Confirm Booking'}
              </Button>
            </Box>
          </Box>
        )
      default:
        return null
    }
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
            onClick={() => navigate('/seats')}
            underline="hover"
            color="inherit"
          >
            Seats
          </MuiLink>
          <Typography color="text.primary">Book a Seat</Typography>
        </Breadcrumbs>

        <Box sx={{ mb: 4 }}>
          <Typography variant="h4" component="h1" gutterBottom>
            Book a Seat
          </Typography>
          <Typography variant="body1" color="text.secondary">
            Reserve your study space in advance.
          </Typography>
        </Box>

        <Card sx={{ mb: 4 }}>
          <CardContent>
            <Stepper activeStep={activeStep} alternativeLabel sx={{ mb: 4 }}>
              {steps.map((label) => (
                <Step key={label}>
                  <StepLabel>{label}</StepLabel>
                </Step>
              ))}
            </Stepper>
            
            {renderStepContent(activeStep)}
          </CardContent>
        </Card>
      </motion.div>
    </Box>
  )
}