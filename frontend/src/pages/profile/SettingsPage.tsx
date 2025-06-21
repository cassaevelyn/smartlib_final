import { useState } from 'react'
import {
  Box,
  Typography,
  Grid,
  Card,
  CardContent,
  Button,
  TextField,
  Divider,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Switch,
  FormControlLabel,
  Alert,
  InputAdornment,
  IconButton,
} from '@mui/material'
import {
  Notifications,
  Email,
  Visibility,
  VisibilityOff,
  Lock,
  Save,
  NotificationsActive,
  EventAvailable,
  MenuBook,
  Language,
} from '@mui/icons-material'
import { motion } from 'framer-motion'
import { useForm, Controller } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { useAuthStore } from '../../stores/authStore'
import { authService } from '../../services/authService'
import { LoadingSpinner } from '../../components/ui/loading-spinner'
import { useToast } from '../../hooks/use-toast'

// Schema for password change
const passwordSchema = z.object({
  old_password: z.string().min(1, 'Current password is required'),
  new_password: z.string().min(8, 'Password must be at least 8 characters'),
  confirm_password: z.string().min(1, 'Please confirm your password'),
}).refine((data) => data.new_password === data.confirm_password, {
  message: "Passwords don't match",
  path: ['confirm_password'],
})

type PasswordForm = z.infer<typeof passwordSchema>

// Schema for notification preferences
const notificationSchema = z.object({
  email_notifications: z.boolean().default(true),
  booking_reminders: z.boolean().default(true),
  event_notifications: z.boolean().default(true),
  book_due_reminders: z.boolean().default(true),
  loyalty_updates: z.boolean().default(true),
})

type NotificationForm = z.infer<typeof notificationSchema>

export function SettingsPage() {
  const { user, updateUser } = useAuthStore()
  const { toast } = useToast()
  
  const [showPassword, setShowPassword] = useState(false)
  const [showNewPassword, setShowNewPassword] = useState(false)
  const [isSubmittingPassword, setIsSubmittingPassword] = useState(false)
  const [isSubmittingNotifications, setIsSubmittingNotifications] = useState(false)
  const [passwordError, setPasswordError] = useState<string | null>(null)
  const [notificationError, setNotificationError] = useState<string | null>(null)

  // Password form
  const {
    control: passwordControl,
    handleSubmit: handlePasswordSubmit,
    reset: resetPasswordForm,
    formState: { errors: passwordErrors },
  } = useForm<PasswordForm>({
    resolver: zodResolver(passwordSchema),
    defaultValues: {
      old_password: '',
      new_password: '',
      confirm_password: '',
    },
  })

  // Notification form
  const {
    control: notificationControl,
    handleSubmit: handleNotificationSubmit,
    formState: { errors: notificationErrors },
  } = useForm<NotificationForm>({
    resolver: zodResolver(notificationSchema),
    defaultValues: {
      email_notifications: true,
      booking_reminders: true,
      event_notifications: true,
      book_due_reminders: true,
      loyalty_updates: true,
    },
  })

  const onPasswordSubmit = async (data: PasswordForm) => {
    try {
      setIsSubmittingPassword(true)
      setPasswordError(null)
      
      await authService.changePassword(data.old_password, data.new_password)
      
      toast({
        title: "Password Updated",
        description: "Your password has been changed successfully.",
        variant: "default",
      })
      
      resetPasswordForm()
    } catch (error: any) {
      setPasswordError(error.message || 'Failed to update password')
    } finally {
      setIsSubmittingPassword(false)
    }
  }

  const onNotificationSubmit = async (data: NotificationForm) => {
    try {
      setIsSubmittingNotifications(true)
      setNotificationError(null)
      
      // In a real app, this would be an actual API call to update notification preferences
      // For now, we'll simulate the update
      await new Promise(resolve => setTimeout(resolve, 1000))
      
      toast({
        title: "Preferences Updated",
        description: "Your notification preferences have been updated successfully.",
        variant: "default",
      })
    } catch (error: any) {
      setNotificationError(error.message || 'Failed to update notification preferences')
    } finally {
      setIsSubmittingNotifications(false)
    }
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
            Account Settings
          </Typography>
          <Typography variant="body1" color="text.secondary">
            Manage your account settings and preferences.
          </Typography>
        </Box>

        <Grid container spacing={3}>
          {/* Password Change */}
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Change Password
                </Typography>
                <Divider sx={{ mb: 3 }} />
                
                {passwordError && (
                  <Alert severity="error" sx={{ mb: 3 }}>
                    {passwordError}
                  </Alert>
                )}
                
                <Box component="form" onSubmit={handlePasswordSubmit(onPasswordSubmit)} noValidate>
                  <Controller
                    name="old_password"
                    control={passwordControl}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="Current Password"
                        type={showPassword ? 'text' : 'password'}
                        fullWidth
                        margin="normal"
                        error={!!passwordErrors.old_password}
                        helperText={passwordErrors.old_password?.message}
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
                    )}
                  />
                  
                  <Controller
                    name="new_password"
                    control={passwordControl}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="New Password"
                        type={showNewPassword ? 'text' : 'password'}
                        fullWidth
                        margin="normal"
                        error={!!passwordErrors.new_password}
                        helperText={passwordErrors.new_password?.message}
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
                                onClick={() => setShowNewPassword(!showNewPassword)}
                                edge="end"
                              >
                                {showNewPassword ? <VisibilityOff /> : <Visibility />}
                              </IconButton>
                            </InputAdornment>
                          ),
                        }}
                      />
                    )}
                  />
                  
                  <Controller
                    name="confirm_password"
                    control={passwordControl}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="Confirm New Password"
                        type={showNewPassword ? 'text' : 'password'}
                        fullWidth
                        margin="normal"
                        error={!!passwordErrors.confirm_password}
                        helperText={passwordErrors.confirm_password?.message}
                        InputProps={{
                          startAdornment: (
                            <InputAdornment position="start">
                              <Lock color="action" />
                            </InputAdornment>
                          ),
                        }}
                      />
                    )}
                  />
                  
                  <Box sx={{ mt: 3, display: 'flex', justifyContent: 'flex-end' }}>
                    <Button
                      type="submit"
                      variant="contained"
                      disabled={isSubmittingPassword}
                      startIcon={isSubmittingPassword ? <LoadingSpinner size="sm" /> : <Save />}
                    >
                      Update Password
                    </Button>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>

          {/* Notification Preferences */}
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Notification Preferences
                </Typography>
                <Divider sx={{ mb: 3 }} />
                
                {notificationError && (
                  <Alert severity="error" sx={{ mb: 3 }}>
                    {notificationError}
                  </Alert>
                )}
                
                <Box component="form" onSubmit={handleNotificationSubmit(onNotificationSubmit)} noValidate>
                  <List>
                    <ListItem>
                      <ListItemIcon>
                        <Email />
                      </ListItemIcon>
                      <ListItemText
                        primary="Email Notifications"
                        secondary="Receive notifications via email"
                      />
                      <Controller
                        name="email_notifications"
                        control={notificationControl}
                        render={({ field }) => (
                          <Switch
                            checked={field.value}
                            onChange={(e) => field.onChange(e.target.checked)}
                          />
                        )}
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon>
                        <EventAvailable />
                      </ListItemIcon>
                      <ListItemText
                        primary="Booking Reminders"
                        secondary="Receive reminders about your upcoming seat bookings"
                      />
                      <Controller
                        name="booking_reminders"
                        control={notificationControl}
                        render={({ field }) => (
                          <Switch
                            checked={field.value}
                            onChange={(e) => field.onChange(e.target.checked)}
                          />
                        )}
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon>
                        <NotificationsActive />
                      </ListItemIcon>
                      <ListItemText
                        primary="Event Notifications"
                        secondary="Receive updates about events you're registered for"
                      />
                      <Controller
                        name="event_notifications"
                        control={notificationControl}
                        render={({ field }) => (
                          <Switch
                            checked={field.value}
                            onChange={(e) => field.onChange(e.target.checked)}
                          />
                        )}
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon>
                        <MenuBook />
                      </ListItemIcon>
                      <ListItemText
                        primary="Book Due Reminders"
                        secondary="Receive reminders when your books are due"
                      />
                      <Controller
                        name="book_due_reminders"
                        control={notificationControl}
                        render={({ field }) => (
                          <Switch
                            checked={field.value}
                            onChange={(e) => field.onChange(e.target.checked)}
                          />
                        )}
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon>
                        <EmojiEvents />
                      </ListItemIcon>
                      <ListItemText
                        primary="Loyalty Program Updates"
                        secondary="Receive updates about your loyalty points and rewards"
                      />
                      <Controller
                        name="loyalty_updates"
                        control={notificationControl}
                        render={({ field }) => (
                          <Switch
                            checked={field.value}
                            onChange={(e) => field.onChange(e.target.checked)}
                          />
                        )}
                      />
                    </ListItem>
                  </List>
                  
                  <Box sx={{ mt: 3, display: 'flex', justifyContent: 'flex-end' }}>
                    <Button
                      type="submit"
                      variant="contained"
                      disabled={isSubmittingNotifications}
                      startIcon={isSubmittingNotifications ? <LoadingSpinner size="sm" /> : <Save />}
                    >
                      Save Preferences
                    </Button>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>

          {/* Language Preferences */}
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Language Preferences
                </Typography>
                <Divider sx={{ mb: 3 }} />
                
                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                  <Language sx={{ mr: 2 }} />
                  <Typography variant="body1">
                    Preferred Language: <strong>English</strong>
                  </Typography>
                </Box>
                
                <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                  Language preferences are currently managed system-wide. Contact support to change your language.
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </motion.div>
    </Box>
  )
}