import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  Box,
  TextField,
  Button,
  Typography,
  Alert,
  InputAdornment,
  IconButton,
  Grid,
  MenuItem,
  Stepper,
  Step,
  StepLabel,
} from '@mui/material'
import {
  Visibility,
  VisibilityOff,
  Email,
  Person,
  Badge,
  Phone,
  Home,
  LocationCity,
  Cake,
  LockOutlined,
} from '@mui/icons-material'
import { motion } from 'framer-motion'
import { useForm, Controller } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { useAuthStore } from '../../stores/authStore'
import { authService } from '../../services/authService'
import { LoadingSpinner } from '../../components/ui/loading-spinner'
import { isValidCRN } from '../../lib/utils'
import { useToast } from '../../hooks/use-toast'

const registerSchema = z.object({
  username: z.string().min(3, 'Username must be at least 3 characters'),
  email: z.string().email('Please enter a valid email address'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  password_confirm: z.string(),
  first_name: z.string().min(1, 'First name is required'),
  last_name: z.string().min(1, 'Last name is required'),
  crn: z.string().refine(isValidCRN, {
    message: 'CRN must be in format ICAP-CA-YYYY-####',
  }),
  phone_number: z.string().optional(),
  date_of_birth: z.string().optional(),
  gender: z.enum(['M', 'F', 'O']).optional(),
  address: z.string().optional(),
  city: z.string().optional(),
}).refine((data) => data.password === data.password_confirm, {
  message: "Passwords don't match",
  path: ['password_confirm'],
})

type RegisterForm = z.infer<typeof registerSchema>

const steps = ['Account Information', 'Personal Details', 'ICAP Information']

export function RegisterPage() {
  const navigate = useNavigate()
  const { toast } = useToast()
  const { register: registerUser, isLoading, error, clearError } = useAuthStore()
  const [showPassword, setShowPassword] = useState(false)
  const [activeStep, setActiveStep] = useState(0)
  const [registrationError, setRegistrationError] = useState<string | null>(null)

  const {
    register,
    control,
    handleSubmit,
    watch,
    trigger,
    formState: { errors, isValid },
    reset,
  } = useForm<RegisterForm>({
    resolver: zodResolver(registerSchema),
    mode: 'onChange',
    defaultValues: {
      username: '',
      email: '',
      password: '',
      password_confirm: '',
      first_name: '',
      last_name: '',
      crn: '',
      phone_number: '',
      date_of_birth: '',
      gender: 'M',
      address: '',
      city: '',
    },
  })

  const watchEmail = watch('email')

  const handleNext = async () => {
    let fieldsToValidate: (keyof RegisterForm)[] = []
    
    if (activeStep === 0) {
      fieldsToValidate = ['username', 'email', 'password', 'password_confirm']
    } else if (activeStep === 1) {
      fieldsToValidate = ['first_name', 'last_name', 'phone_number', 'date_of_birth', 'gender']
    }
    
    const isStepValid = await trigger(fieldsToValidate)
    
    if (isStepValid) {
      setActiveStep((prevStep) => prevStep + 1)
    }
  }

  const handleBack = () => {
    setActiveStep((prevStep) => prevStep - 1)
  }

  const onSubmit = async (data: RegisterForm) => {
    try {
      clearError()
      setRegistrationError(null)
      
      await registerUser(data)
      
      toast({
        title: "Registration Successful",
        description: "Please check your email to verify your account.",
        variant: "default",
      })
      
      navigate('/auth/login', { 
        state: { 
          message: 'Registration successful! Please check your email to verify your account before logging in.' 
        } 
      })
    } catch (error: any) {
      setRegistrationError(error.message || "An error occurred during registration")
      // Don't reset the form or change the step on error
    }
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
    >
      <Box component="form" onSubmit={handleSubmit(onSubmit)} noValidate>
        <Typography variant="h4" component="h1" gutterBottom textAlign="center">
          Create Account
        </Typography>
        <Typography variant="body1" color="text.secondary" textAlign="center" sx={{ mb: 3 }}>
          Join Smart Lib to access all features
        </Typography>

        {error && (
          <Alert severity="error" sx={{ mb: 3 }}>
            {error}
          </Alert>
        )}

        {registrationError && (
          <Alert severity="error" sx={{ mb: 3 }}>
            {registrationError}
          </Alert>
        )}

        <Stepper activeStep={activeStep} sx={{ mb: 4 }}>
          {steps.map((label) => (
            <Step key={label}>
              <StepLabel>{label}</StepLabel>
            </Step>
          ))}
        </Stepper>

        {activeStep === 0 && (
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.3 }}
          >
            <TextField
              {...register('username')}
              fullWidth
              label="Username"
              autoComplete="username"
              error={!!errors.username}
              helperText={errors.username?.message}
              sx={{ mb: 2 }}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <Person color="action" />
                  </InputAdornment>
                ),
              }}
            />

            <TextField
              {...register('email')}
              fullWidth
              label="Email Address"
              type="email"
              autoComplete="email"
              error={!!errors.email}
              helperText={errors.email?.message}
              sx={{ mb: 2 }}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <Email color="action" />
                  </InputAdornment>
                ),
              }}
            />

            <TextField
              {...register('password')}
              fullWidth
              label="Password"
              type={showPassword ? 'text' : 'password'}
              autoComplete="new-password"
              error={!!errors.password}
              helperText={errors.password?.message}
              sx={{ mb: 2 }}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <LockOutlined color="action" />
                  </InputAdornment>
                ),
                endAdornment: (
                  <InputAdornment position="end">
                    <IconButton
                      aria-label="toggle password visibility"
                      onClick={() => setShowPassword(!showPassword)}
                      edge="end"
                    >
                      {showPassword ? <VisibilityOff /> : <Visibility />}
                    </IconButton>
                  </InputAdornment>
                ),
              }}
            />

            <TextField
              {...register('password_confirm')}
              fullWidth
              label="Confirm Password"
              type={showPassword ? 'text' : 'password'}
              autoComplete="new-password"
              error={!!errors.password_confirm}
              helperText={errors.password_confirm?.message}
              sx={{ mb: 3 }}
            />
          </motion.div>
        )}

        {activeStep === 1 && (
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.3 }}
          >
            <Grid container spacing={2}>
              <Grid item xs={12} sm={6}>
                <TextField
                  {...register('first_name')}
                  fullWidth
                  label="First Name"
                  autoComplete="given-name"
                  error={!!errors.first_name}
                  helperText={errors.first_name?.message}
                  sx={{ mb: 2 }}
                  InputProps={{
                    startAdornment: (
                      <InputAdornment position="start">
                        <Person color="action" />
                      </InputAdornment>
                    ),
                  }}
                />
              </Grid>
              <Grid item xs={12} sm={6}>
                <TextField
                  {...register('last_name')}
                  fullWidth
                  label="Last Name"
                  autoComplete="family-name"
                  error={!!errors.last_name}
                  helperText={errors.last_name?.message}
                  sx={{ mb: 2 }}
                />
              </Grid>
            </Grid>

            <Grid container spacing={2}>
              <Grid item xs={12} sm={6}>
                <TextField
                  {...register('phone_number')}
                  fullWidth
                  label="Phone Number"
                  autoComplete="tel"
                  error={!!errors.phone_number}
                  helperText={errors.phone_number?.message}
                  sx={{ mb: 2 }}
                  InputProps={{
                    startAdornment: (
                      <InputAdornment position="start">
                        <Phone color="action" />
                      </InputAdornment>
                    ),
                  }}
                />
              </Grid>
              <Grid item xs={12} sm={6}>
                <TextField
                  {...register('date_of_birth')}
                  fullWidth
                  label="Date of Birth"
                  type="date"
                  InputLabelProps={{ shrink: true }}
                  error={!!errors.date_of_birth}
                  helperText={errors.date_of_birth?.message}
                  sx={{ mb: 2 }}
                  InputProps={{
                    startAdornment: (
                      <InputAdornment position="start">
                        <Cake color="action" />
                      </InputAdornment>
                    ),
                  }}
                />
              </Grid>
            </Grid>

            <Controller
              name="gender"
              control={control}
              render={({ field }) => (
                <TextField
                  {...field}
                  select
                  fullWidth
                  label="Gender"
                  error={!!errors.gender}
                  helperText={errors.gender?.message}
                  sx={{ mb: 2 }}
                >
                  <MenuItem value="M">Male</MenuItem>
                  <MenuItem value="F">Female</MenuItem>
                  <MenuItem value="O">Other</MenuItem>
                </TextField>
              )}
            />

            <TextField
              {...register('address')}
              fullWidth
              label="Address"
              autoComplete="street-address"
              error={!!errors.address}
              helperText={errors.address?.message}
              sx={{ mb: 2 }}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <Home color="action" />
                  </InputAdornment>
                ),
              }}
            />

            <TextField
              {...register('city')}
              fullWidth
              label="City"
              autoComplete="address-level2"
              error={!!errors.city}
              helperText={errors.city?.message}
              sx={{ mb: 3 }}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <LocationCity color="action" />
                  </InputAdornment>
                ),
              }}
            />
          </motion.div>
        )}

        {activeStep === 2 && (
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.3 }}
          >
            <Alert severity="info" sx={{ mb: 3 }}>
              Please enter your ICAP CA Registration Number (CRN) in the format ICAP-CA-YYYY-####
            </Alert>

            <TextField
              {...register('crn')}
              fullWidth
              label="ICAP CA Registration Number (CRN)"
              placeholder="ICAP-CA-2023-1234"
              error={!!errors.crn}
              helperText={errors.crn?.message}
              sx={{ mb: 3 }}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <Badge color="action" />
                  </InputAdornment>
                ),
              }}
            />

            <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
              By registering, you agree to the Smart Lib Terms of Service and Privacy Policy.
            </Typography>
          </motion.div>
        )}

        <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 2 }}>
          <Button
            disabled={activeStep === 0}
            onClick={handleBack}
            variant="outlined"
          >
            Back
          </Button>
          
          {activeStep === steps.length - 1 ? (
            <Button
              type="submit"
              variant="contained"
              disabled={isLoading}
              startIcon={isLoading ? <LoadingSpinner size="sm" /> : null}
            >
              Register
            </Button>
          ) : (
            <Button
              variant="contained"
              onClick={handleNext}
              disabled={
                (activeStep === 0 && !watchEmail)
              }
            >
              Next
            </Button>
          )}
        </Box>

        <Box sx={{ textAlign: 'center', mt: 3 }}>
          <Typography variant="body2" color="text.secondary">
            Already have an account?{' '}
            <Link
              to="/auth/login"
              style={{ textDecoration: 'none', color: 'inherit' }}
            >
              <Typography component="span" color="primary" sx={{ font: 'inherit' }}>
                Sign in
              </Typography>
            </Link>
          </Typography>
        </Box>
      </Box>
    </motion.div>
  )
}