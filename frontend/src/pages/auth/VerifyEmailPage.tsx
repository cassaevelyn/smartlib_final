import { useState, useEffect, useRef } from 'react'
import { useParams, useNavigate, Link, useSearchParams } from 'react-router-dom'
import {
  Box,
  Typography,
  Button,
  Alert,
  Paper,
  TextField,
  InputAdornment,
  CircularProgress,
  Grid,
} from '@mui/material'
import {
  CheckCircle,
  Error as ErrorIcon,
  Email,
  ArrowBack,
} from '@mui/icons-material'
import { motion } from 'framer-motion'
import { authService } from '../../services/authService'
import { useToast } from '../../hooks/use-toast'
import { useAuthStore } from '../../stores/authStore'

export function VerifyEmailPage() {
  const { token } = useParams<{ token: string }>()
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  const { toast } = useToast()
  const { user, isAuthenticated } = useAuthStore()
  
  const [isLoading, setIsLoading] = useState(false)
  const [isVerified, setIsVerified] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [email, setEmail] = useState<string>('')
  const [isResending, setIsResending] = useState(false)
  const [otp, setOtp] = useState<string>('')
  const [isVerifyingOtp, setIsVerifyingOtp] = useState(false)
  const [showOtpInput, setShowOtpInput] = useState(false)
  const [cooldownInfo, setCooldownInfo] = useState<{
    attemptsRemaining: number;
    cooldownMinutes: number;
  } | null>(null)
  const [resendTimer, setResendTimer] = useState<number>(0)
  const [isResendDisabled, setIsResendDisabled] = useState<boolean>(false)
  
  // Use a ref to track if we've already made the API call
  const hasFetched = useRef(false)
  
  // Check if we're in success or failure mode from URL path
  const isSuccess = window.location.pathname.includes('/success')
  const isFailure = window.location.pathname.includes('/failed')
  const failureReason = searchParams.get('reason')
  const successReason = searchParams.get('reason')

  // Timer effect for resend cooldown
  useEffect(() => {
    let timerId: NodeJS.Timeout | null = null;
    
    if (resendTimer > 0) {
      setIsResendDisabled(true);
      timerId = setInterval(() => {
        setResendTimer(prev => {
          if (prev <= 1) {
            setIsResendDisabled(false);
            return 0;
          }
          return prev - 1;
        });
      }, 1000);
    } else {
      setIsResendDisabled(false);
    }
    
    return () => {
      if (timerId) clearInterval(timerId);
    };
  }, [resendTimer]);

  useEffect(() => {
    // If user is already verified, show success state
    if (user?.is_verified) {
      setIsVerified(true)
      setError(null)
      setIsLoading(false)
      return
    }
    
    // If we're in success or failure mode, set the appropriate state
    if (isSuccess) {
      setIsVerified(true)
      setError(null)
      setIsLoading(false)
    } else if (isFailure) {
      setIsVerified(false)
      
      // Set appropriate error message based on reason
      if (failureReason === 'expired') {
        setError('Your verification link has expired. Please request a new one.')
      } else if (failureReason === 'token_already_used') {
        setError('This verification link has already been used. Please request a new one.')
        setShowOtpInput(true) // Automatically show OTP input for convenience
      } else if (failureReason === 'invalid') {
        setError('Invalid verification link. Please request a new one.')
      } else {
        setError('Verification failed. Please request a new verification link.')
      }
      
      setIsLoading(false)
    }
    // If we have a token in the URL, verify it
    else if (token && !hasFetched.current) {
      hasFetched.current = true
      verifyEmail()
    } 
    // Otherwise, we're in manual verification mode
    else {
      setIsLoading(false)
    }
  }, [token, isSuccess, isFailure, failureReason, user])

  const verifyEmail = async () => {
    try {
      setIsLoading(true)
      const response = await authService.verifyEmail(token!)
      
      if (response.status === 'success') {
        setIsVerified(true)
        setError(null)
        
        toast({
          title: "Email Verified",
          description: "Your email has been verified successfully.",
          variant: "default",
        })
        
        // Navigate to success page with the reason
        navigate(`/auth/verify-email/success?reason=${response.reason || 'verified_successfully'}`, { replace: true })
      } else {
        // Handle error case
        setError(response.error || 'Failed to verify email')
        setIsVerified(false)
        
        toast({
          title: "Verification Failed",
          description: response.error || 'Failed to verify email',
          variant: "destructive",
        })
        
        // Navigate to failure page with reason
        navigate(`/auth/verify-email/failed?reason=${response.reason || 'unknown'}`, { replace: true })
      }
    } catch (error: any) {
      setError(error.message || 'Failed to verify email. The token may be invalid or expired.')
      setIsVerified(false)
      
      toast({
        title: "Verification Failed",
        description: error.message || 'Failed to verify email',
        variant: "destructive",
      })
      
      // Navigate to failure page
      navigate('/auth/verify-email/failed?reason=unknown', { replace: true })
    } finally {
      setIsLoading(false)
    }
  }

  const handleResendVerification = async () => {
    if (!email) {
      toast({
        title: "Email Required",
        description: "Please enter your email address",
        variant: "destructive",
      })
      return
    }
    
    try {
      setIsResending(true)
      setError(null)
      
      // Only check if user is already verified if we're currently authenticated
      if (isAuthenticated) {
        try {
          const user = await authService.getProfile()
          if (user.is_verified) {
            toast({
              title: "Already Verified",
              description: "Your account is already verified. You can now log in.",
              variant: "default",
            })
            setIsVerified(true)
            setError(null)
            
            // Navigate to success page
            navigate('/auth/verify-email/success?reason=already_verified', { replace: true })
            return
          }
        } catch (error) {
          // If we can't get the user profile, continue with sending OTP
          console.log("Not authenticated or couldn't fetch profile, continuing with OTP flow")
        }
      }
      
      const response = await authService.sendOtp(email)
      
      toast({
        title: "Verification Email Sent",
        description: "A new verification code has been sent to your email",
        variant: "default",
      })
      
      // Show OTP input field after sending
      setShowOtpInput(true)
      setError(null)
      
      // Store cooldown information
      setCooldownInfo({
        attemptsRemaining: response.attempts_remaining,
        cooldownMinutes: response.cooldown_minutes
      })
      
      // Set the resend timer based on cooldown minutes
      if (response.cooldown_minutes > 0) {
        setResendTimer(response.cooldown_minutes * 60);
      } else {
        // Default to 60 seconds if no cooldown provided
        setResendTimer(60);
      }
    } catch (error: any) {
      // Check if the error message indicates the account is already verified
      if (error.message && error.message.toLowerCase().includes('already verified')) {
        toast({
          title: "Already Verified",
          description: "Your account is already verified. You can now log in.",
          variant: "default",
        })
        setIsVerified(true)
        setError(null)
        
        // Navigate to success page
        navigate('/auth/verify-email/success?reason=already_verified', { replace: true })
      } else if (error.message && error.message.toLowerCase().includes('no account found')) {
        // Email doesn't exist
        toast({
          title: "Email Not Found",
          description: "No account exists with this email address. Please check and try again.",
          variant: "destructive",
        })
        setError("No account found with this email address. Please check and try again.");
      } else {
        toast({
          title: "Failed to Send Verification",
          description: error.message || 'Failed to send verification email',
          variant: "destructive",
        })
        setError(error.message || "Failed to send verification email. Please try again later.");
      }
    } finally {
      setIsResending(false)
    }
  }

  const handleVerifyOtp = async () => {
    if (!email || !otp) {
      toast({
        title: "Information Required",
        description: "Please enter both email and verification code",
        variant: "destructive",
      })
      return
    }
    
    try {
      setIsVerifyingOtp(true)
      setError(null)
      
      // First check if user is already verified
      if (isAuthenticated) {
        try {
          const user = await authService.getProfile()
          if (user.is_verified) {
            setIsVerified(true)
            toast({
              title: "Already Verified",
              description: "Your account is already verified. You can now log in.",
              variant: "default",
            })
            
            // Navigate to success page
            navigate('/auth/verify-email/success?reason=already_verified', { replace: true })
            return
          }
        } catch (error) {
          // If we can't get the user profile, continue with verification
        }
      }
      
      const response = await authService.verifyOtp(email, otp)
      
      setIsVerified(true)
      setError(null)
      
      toast({
        title: "Email Verified",
        description: "Your email has been verified successfully.",
        variant: "default",
      })
      
      // Navigate to success page
      navigate('/auth/verify-email/success?reason=verified_successfully', { replace: true })
    } catch (error: any) {
      // Check if the error message indicates the account is already verified
      if (error.message && error.message.toLowerCase().includes('already verified')) {
        setIsVerified(true)
        setError(null)
        toast({
          title: "Already Verified",
          description: "Your account is already verified. You can now log in.",
          variant: "default",
        })
        
        // Navigate to success page
        navigate('/auth/verify-email/success?reason=already_verified', { replace: true })
      } else {
        toast({
          title: "Verification Failed",
          description: error.message || 'Failed to verify email',
          variant: "destructive",
        })
        setError(error.message || 'Failed to verify email')
      }
    } finally {
      setIsVerifyingOtp(false)
    }
  }

  // Determine what to render based on the current state
  const renderContent = () => {
    // Loading state
    if (isLoading) {
      return (
        <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', mt: 4 }}>
          <CircularProgress size={60} thickness={4} />
          <Typography variant="body1" sx={{ mt: 2 }}>
            Verifying your email address...
          </Typography>
        </Box>
      )
    }
    
    // Success state
    if (isVerified) {
      return (
        <motion.div
          initial={{ scale: 0.8, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ duration: 0.5 }}
        >
          <Box sx={{ mt: 4, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
            <CheckCircle color="success" sx={{ fontSize: 80, mb: 2 }} />
            <Typography variant="h5" gutterBottom>
              {successReason === 'already_verified' 
                ? 'Your Account is Already Verified!' 
                : 'Email Verified Successfully!'}
            </Typography>
            <Typography variant="body1" color="text.secondary" paragraph>
              {successReason === 'already_verified'
                ? 'Your email has already been verified. You can now log in to your account.'
                : 'Your email has been verified. You can now log in to your account.'}
            </Typography>
            <Button
              variant="contained"
              size="large"
              onClick={() => navigate('/auth/login')}
              sx={{ mt: 2 }}
            >
              Go to Login
            </Button>
          </Box>
        </motion.div>
      )
    }
    
    // Error/Manual verification state
    return (
      <motion.div
        initial={{ scale: 0.8, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ duration: 0.5 }}
      >
        <Box sx={{ mt: 4, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
          {error && (
            <>
              <ErrorIcon color="error" sx={{ fontSize: 80, mb: 2 }} />
              <Typography variant="h5" gutterBottom>
                Verification Failed
              </Typography>
              <Alert severity="error" sx={{ mb: 3 }}>
                {error}
              </Alert>
            </>
          )}
          
          <Typography variant="body1" paragraph>
            {error 
              ? 'Please try again or request a new verification email.'
              : 'Enter your email and verification code to verify your account.'}
          </Typography>
          
          <Paper elevation={3} sx={{ p: 3, width: '100%', maxWidth: 400, mt: 2 }}>
            <Typography variant="h6" gutterBottom>
              {error ? 'Request New Verification' : 'Verify Your Email'}
            </Typography>
            <TextField
              fullWidth
              label="Email Address"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              margin="normal"
              required
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <Email color="action" />
                  </InputAdornment>
                ),
              }}
            />
            
            {showOtpInput && (
              <TextField
                fullWidth
                label="Verification Code"
                value={otp}
                onChange={(e) => setOtp(e.target.value)}
                margin="normal"
                required
                placeholder="Enter 6-digit code"
              />
            )}
            
            {cooldownInfo && (
              <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 2 }}>
                You have {cooldownInfo.attemptsRemaining} attempts remaining. 
                {cooldownInfo.cooldownMinutes > 0 && ` Cooldown period: ${cooldownInfo.cooldownMinutes} minutes.`}
              </Typography>
            )}
            
            <Grid container spacing={2} sx={{ mt: 2 }}>
              <Grid item xs={12} sm={6}>
                <Button
                  variant="outlined"
                  fullWidth
                  onClick={() => navigate('/auth/login')}
                  startIcon={<ArrowBack />}
                >
                  Back to Login
                </Button>
              </Grid>
              <Grid item xs={12} sm={6}>
                {showOtpInput ? (
                  <Button
                    variant="contained"
                    fullWidth
                    onClick={handleVerifyOtp}
                    disabled={isVerifyingOtp || !email || otp.length !== 6}
                  >
                    {isVerifyingOtp ? <CircularProgress size={24} /> : 'Verify Code'}
                  </Button>
                ) : (
                  <Button
                    variant="contained"
                    fullWidth
                    onClick={handleResendVerification}
                    disabled={isResending || !email || isResendDisabled}
                  >
                    {isResending ? <CircularProgress size={24} /> : 
                     isResendDisabled ? `Resend (${resendTimer}s)` : 'Send Verification'}
                  </Button>
                )}
              </Grid>
            </Grid>
            
            {showOtpInput && (
              <Button
                variant="text"
                onClick={() => setShowOtpInput(false)}
                sx={{ mt: 1 }}
              >
                Back to Email Entry
              </Button>
            )}
          </Paper>
        </Box>
      </motion.div>
    )
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
    >
      <Box sx={{ textAlign: 'center' }}>
        <Typography variant="h4" component="h1" gutterBottom>
          Email Verification
        </Typography>

        {renderContent()}
      </Box>
    </motion.div>
  )
}