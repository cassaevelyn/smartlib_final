import { useState } from 'react'
import { Link, useNavigate, useLocation } from 'react-router-dom'
import {
  Box,
  TextField,
  Button,
  Typography,
  Alert,
  InputAdornment,
  IconButton,
  FormControlLabel,
  Checkbox,
  Divider,
} from '@mui/material'
import { Visibility, VisibilityOff, Email, Lock } from '@mui/icons-material'
import { motion } from 'framer-motion'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { useAuthStore } from '../../stores/authStore'
import { LoadingSpinner } from '../../components/ui/loading-spinner'
import { useToast } from '../../hooks/use-toast'
import { authService } from '../../services/authService'

const loginSchema = z.object({
  email: z.string().email('Please enter a valid email address'),
  password: z.string().min(1, 'Password is required'),
  rememberMe: z.boolean().optional(),
})

type LoginForm = z.infer<typeof loginSchema>

// OTP verification schema
const otpSchema = z.object({
  email: z.string().email('Please enter a valid email address'),
  otp: z.string().length(6, 'OTP must be 6 digits'),
})

type OtpForm = z.infer<typeof otpSchema>

export function LoginPage() {
  const navigate = useNavigate()
  const location = useLocation()
  const { toast } = useToast()
  const { login, isLoading, error, clearError } = useAuthStore()
  const [showPassword, setShowPassword] = useState(false)
  const [verificationSent, setVerificationSent] = useState(false)
  const [isVerifyingOtp, setIsVerifyingOtp] = useState(false)
  const [isResending, setIsResending] = useState(false)
  const [otp, setOtp] = useState('')
  const [otpError, setOtpError] = useState<string | null>(null)
  const [cooldownInfo, setCooldownInfo] = useState<{
    attemptsRemaining: number;
    cooldownMinutes: number;
  } | null>(null)

  const from = location.state?.from?.pathname || '/'

  const {
    register,
    handleSubmit,
    formState: { errors },
    getValues,
  } = useForm<LoginForm>({
    resolver: zodResolver(loginSchema),
    defaultValues: {
      email: '',
      password: '',
      rememberMe: false,
    },
  })

  const onSubmit = async (data: LoginForm) => {
    try {
      clearError()
      
      await login({ email: data.email, password: data.password })
      
      toast({
        title: "Login Successful",
        description: "Welcome back to Smart Lib!",
        variant: "default",
      })
      
      navigate(from, { replace: true })
    } catch (error: any) {
      // Check if this is the special 'account_not_active' error
      if (error.code === 'account_not_active') {
        setVerificationSent(true)
        toast({
          title: "Account Not Verified",
          description: "A verification email has been sent to your address. Please verify your email to continue.",
          variant: "warning",
        })
      } else {
        toast({
          title: "Login Failed",
          description: error.message || "Invalid credentials. Please try again.",
          variant: "destructive",
        })
      }
    }
  }

  const handleResendVerification = async () => {
    const email = getValues('email')
    if (!email) {
      toast({
        title: "Email Required",
        description: "Please enter your email address to resend verification",
        variant: "destructive",
      })
      return
    }
    
    try {
      setIsResending(true)
      setOtpError(null)
      
      const response = await authService.sendOtp(email)
      
      toast({
        title: "Verification Email Sent",
        description: "A new verification email has been sent to your address",
        variant: "default",
      })
      
      setVerificationSent(true)
      
      // Store cooldown information
      setCooldownInfo({
        attemptsRemaining: response.attempts_remaining,
        cooldownMinutes: response.cooldown_minutes
      })
      
    } catch (error: any) {
      toast({
        title: "Failed to Send Verification",
        description: error.message || "Failed to send verification email",
        variant: "destructive",
      })
    } finally {
      setIsResending(false)
    }
  }

  const handleVerifyOtp = async () => {
    const email = getValues('email')
    if (!email || !otp) {
      setOtpError("Both email and verification code are required")
      return
    }
    
    try {
      setIsVerifyingOtp(true)
      setOtpError(null)
      
      await authService.verifyOtp(email, otp)
      
      toast({
        title: "Email Verified",
        description: "Your email has been verified successfully. You can now log in.",
        variant: "default",
      })
      
      // Reset verification state
      setVerificationSent(false)
      setOtp('')
      
      // Show success message
      navigate('/auth/login', { 
        state: { 
          message: 'Email verification successful! You can now log in.' 
        } 
      })
    } catch (error: any) {
      setOtpError(error.message || 'Failed to verify email')
    } finally {
      setIsVerifyingOtp(false)
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
          Welcome Back
        </Typography>
        <Typography variant="body1" color="text.secondary" textAlign="center" sx={{ mb: 3 }}>
          Sign in to your Smart Lib account
        </Typography>

        {error && (
          <Alert severity="error" sx={{ mb: 3 }}>
            {error}
          </Alert>
        )}

        {location.state?.message && (
          <Alert severity="success" sx={{ mb: 3 }}>
            {location.state.message}
          </Alert>
        )}
        
        {verificationSent ? (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.3 }}
          >
            <Alert severity="warning" sx={{ mb: 3 }}>
              Your account needs to be verified. A verification code has been sent to your email address.
            </Alert>
            
            <TextField
              fullWidth
              label="Verification Code"
              value={otp}
              onChange={(e) => setOtp(e.target.value)}
              placeholder="Enter 6-digit code"
              error={!!otpError}
              helperText={otpError}
              sx={{ mb: 2 }}
            />
            
            {cooldownInfo && (
              <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 2 }}>
                You have {cooldownInfo.attemptsRemaining} attempts remaining. 
                {cooldownInfo.cooldownMinutes > 0 && ` Cooldown period: ${cooldownInfo.cooldownMinutes} minutes.`}
              </Typography>
            )}
            
            <Box sx={{ display: 'flex', gap: 2, mb: 3 }}>
              <Button
                variant="contained"
                fullWidth
                onClick={handleVerifyOtp}
                disabled={isVerifyingOtp || otp.length !== 6}
              >
                {isVerifyingOtp ? <LoadingSpinner size="sm" /> : 'Verify Code'}
              </Button>
              
              <Button
                variant="outlined"
                fullWidth
                onClick={handleResendVerification}
                disabled={isResending}
              >
                {isResending ? <LoadingSpinner size="sm" /> : 'Resend Code'}
              </Button>
            </Box>
            
            <Button
              variant="text"
              fullWidth
              onClick={() => setVerificationSent(false)}
              sx={{ mb: 2 }}
            >
              Back to Login
            </Button>
          </motion.div>
        ) : (
          <>
            <TextField
              {...register('email')}
              fullWidth
              label="Email Address"
              type="email"
              autoComplete="email"
              autoFocus
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
              autoComplete="current-password"
              error={!!errors.password}
              helperText={errors.password?.message}
              sx={{ mb: 2 }}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <Lock color="action" />
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

            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
              <FormControlLabel
                control={<Checkbox {...register('rememberMe')} />}
                label="Remember me"
              />
              <Link
                to="/auth/forgot-password"
                style={{ textDecoration: 'none', color: 'inherit' }}
              >
                <Typography variant="body2" color="primary">
                  Forgot password?
                </Typography>
              </Link>
            </Box>

            <Button
              type="submit"
              fullWidth
              variant="contained"
              size="large"
              disabled={isLoading}
              sx={{ mb: 2, py: 1.5 }}
            >
              {isLoading ? <LoadingSpinner size="sm" /> : 'Sign In'}
            </Button>
          </>
        )}

        <Divider sx={{ my: 2 }}>
          <Typography variant="body2" color="text.secondary">
            OR
          </Typography>
        </Divider>

        <Box sx={{ textAlign: 'center' }}>
          <Typography variant="body2" color="text.secondary">
            Don't have an account?{' '}
            <Link
              to="/auth/register"
              style={{ textDecoration: 'none', color: 'inherit' }}
            >
              <Typography component="span" color="primary" sx={{ font: 'inherit' }}>
                Sign up
              </Typography>
            </Link>
          </Typography>
        </Box>
      </Box>
    </motion.div>
  )
}