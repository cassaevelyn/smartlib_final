import { useState, useEffect } from 'react'
import {
  Box,
  Typography,
  Grid,
  Card,
  CardContent,
  Button,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  ListItemSecondaryAction,
  IconButton,
  Divider,
  Chip,
  Tabs,
  Tab,
  Menu,
  MenuItem,
  Pagination,
  Alert,
} from '@mui/material'
import {
  Notifications,
  NotificationsActive,
  NotificationsOff,
  Delete,
  MoreVert,
  CheckCircle,
  Info,
  Warning,
  Error as ErrorIcon,
  FilterList,
} from '@mui/icons-material'
import { motion } from 'framer-motion'
import { notificationService } from '../../services/notificationService'
import { Notification } from '../../types'
import { LoadingSpinner } from '../../components/ui/loading-spinner'
import { useToast } from '../../hooks/use-toast'
import { formatRelativeTime } from '../../lib/utils'

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
      id={`notifications-tabpanel-${index}`}
      aria-labelledby={`notifications-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </div>
  )
}

export function NotificationsPage() {
  const { toast } = useToast()
  
  const [notifications, setNotifications] = useState<Notification[]>([])
  const [filteredNotifications, setFilteredNotifications] = useState<Notification[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [tabValue, setTabValue] = useState(0)
  const [totalPages, setTotalPages] = useState(1)
  const [currentPage, setCurrentPage] = useState(1)
  
  // Menu state
  const [menuAnchorEl, setMenuAnchorEl] = useState<null | HTMLElement>(null)
  const [selectedNotification, setSelectedNotification] = useState<Notification | null>(null)

  useEffect(() => {
    fetchNotifications()
  }, [currentPage, tabValue])

  const fetchNotifications = async () => {
    try {
      setIsLoading(true)
      setError(null)
      
      // Build query parameters based on tab
      const params: any = {
        page: currentPage,
      }
      
      if (tabValue === 1) { // Unread
        params.is_read = false
      } else if (tabValue === 2) { // Read
        params.is_read = true
      }
      
      const response = await notificationService.getNotifications(params)
      setNotifications(response.results)
      setFilteredNotifications(response.results)
      setTotalPages(Math.ceil(response.count / 20)) // Assuming 20 items per page
    } catch (error: any) {
      setError(error.message || 'Failed to fetch notifications')
    } finally {
      setIsLoading(false)
    }
  }

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue)
    setCurrentPage(1) // Reset to first page when changing tabs
  }

  const handlePageChange = (event: React.ChangeEvent<unknown>, value: number) => {
    setCurrentPage(value)
  }

  const handleMenuOpen = (event: React.MouseEvent<HTMLElement>, notification: Notification) => {
    setMenuAnchorEl(event.currentTarget)
    setSelectedNotification(notification)
  }

  const handleMenuClose = () => {
    setMenuAnchorEl(null)
    setSelectedNotification(null)
  }

  const handleMarkAsRead = async (notification: Notification) => {
    try {
      await notificationService.markAsRead(notification.id)
      
      // Update local state
      setNotifications(prevNotifications =>
        prevNotifications.map(n =>
          n.id === notification.id ? { ...n, is_read: true } : n
        )
      )
      
      toast({
        title: "Notification Marked as Read",
        description: "The notification has been marked as read.",
        variant: "default",
      })
      
      handleMenuClose()
      
      // Refresh if we're on the unread tab
      if (tabValue === 1) {
        fetchNotifications()
      }
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || 'Failed to mark notification as read',
        variant: "destructive",
      })
    }
  }

  const handleMarkAllAsRead = async () => {
    try {
      await notificationService.markAllAsRead()
      
      // Update local state
      setNotifications(prevNotifications =>
        prevNotifications.map(n => ({ ...n, is_read: true }))
      )
      
      toast({
        title: "All Notifications Marked as Read",
        description: "All notifications have been marked as read.",
        variant: "default",
      })
      
      // Refresh if we're on the unread tab
      if (tabValue === 1) {
        fetchNotifications()
      }
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || 'Failed to mark all notifications as read',
        variant: "destructive",
      })
    }
  }

  const handleDeleteNotification = async (notification: Notification) => {
    try {
      await notificationService.deleteNotification(notification.id)
      
      // Update local state
      setNotifications(prevNotifications =>
        prevNotifications.filter(n => n.id !== notification.id)
      )
      setFilteredNotifications(prevNotifications =>
        prevNotifications.filter(n => n.id !== notification.id)
      )
      
      toast({
        title: "Notification Deleted",
        description: "The notification has been deleted.",
        variant: "default",
      })
      
      handleMenuClose()
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || 'Failed to delete notification',
        variant: "destructive",
      })
    }
  }

  const getNotificationIcon = (type: string) => {
    switch (type) {
      case 'SUCCESS':
        return <CheckCircle color="success" />
      case 'INFO':
        return <Info color="info" />
      case 'WARNING':
        return <Warning color="warning" />
      case 'ERROR':
        return <ErrorIcon color="error" />
      default:
        return <Info color="info" />
    }
  }

  const getNotificationColor = (type: string) => {
    switch (type) {
      case 'SUCCESS':
        return 'success.light'
      case 'INFO':
        return 'info.light'
      case 'WARNING':
        return 'warning.light'
      case 'ERROR':
        return 'error.light'
      default:
        return 'info.light'
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
            Notifications
          </Typography>
          <Typography variant="body1" color="text.secondary">
            View and manage your notifications.
          </Typography>
        </Box>

        <Card>
          <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
            <Tabs
              value={tabValue}
              onChange={handleTabChange}
              aria-label="notification tabs"
              variant="fullWidth"
            >
              <Tab 
                icon={<Notifications />} 
                label="All" 
                iconPosition="start" 
              />
              <Tab 
                icon={<NotificationsActive />} 
                label="Unread" 
                iconPosition="start" 
              />
              <Tab 
                icon={<NotificationsOff />} 
                label="Read" 
                iconPosition="start" 
              />
            </Tabs>
          </Box>
          
          <Box sx={{ p: 2 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
              <Typography variant="subtitle1">
                {tabValue === 0 ? 'All Notifications' : 
                 tabValue === 1 ? 'Unread Notifications' : 
                 'Read Notifications'}
              </Typography>
              <Box sx={{ display: 'flex', gap: 1 }}>
                <Button
                  variant="outlined"
                  size="small"
                  startIcon={<FilterList />}
                >
                  Filter
                </Button>
                <Button
                  variant="outlined"
                  size="small"
                  startIcon={<CheckCircle />}
                  onClick={handleMarkAllAsRead}
                >
                  Mark All as Read
                </Button>
              </Box>
            </Box>
            
            {isLoading ? (
              <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
                <LoadingSpinner size="md" />
              </Box>
            ) : error ? (
              <Alert severity="error" sx={{ mb: 2 }}>
                {error}
              </Alert>
            ) : filteredNotifications.length === 0 ? (
              <Box sx={{ textAlign: 'center', py: 4 }}>
                <Typography variant="body1" color="text.secondary" gutterBottom>
                  No notifications found
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {tabValue === 0 ? 'You have no notifications yet.' : 
                   tabValue === 1 ? 'You have no unread notifications.' : 
                   'You have no read notifications.'}
                </Typography>
              </Box>
            ) : (
              <>
                <List>
                  {filteredNotifications.map((notification) => (
                    <motion.div
                      key={notification.id}
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ duration: 0.3 }}
                    >
                      <ListItem
                        alignItems="flex-start"
                        sx={{
                          mb: 1,
                          borderRadius: 1,
                          bgcolor: notification.is_read ? 'background.paper' : 'action.hover',
                          borderLeft: 4,
                          borderColor: getNotificationColor(notification.type),
                        }}
                      >
                        <ListItemIcon>
                          {getNotificationIcon(notification.type)}
                        </ListItemIcon>
                        <ListItemText
                          primary={
                            <Typography
                              variant="subtitle1"
                              sx={{ fontWeight: notification.is_read ? 'normal' : 'bold' }}
                            >
                              {notification.title}
                            </Typography>
                          }
                          secondary={
                            <>
                              <Typography
                                variant="body2"
                                component="span"
                                color="text.primary"
                              >
                                {notification.message}
                              </Typography>
                              <Typography
                                variant="caption"
                                component="div"
                                color="text.secondary"
                              >
                                {formatRelativeTime(notification.created_at)}
                              </Typography>
                            </>
                          }
                        />
                        <ListItemSecondaryAction>
                          <IconButton
                            edge="end"
                            aria-label="more"
                            onClick={(e) => handleMenuOpen(e, notification)}
                          >
                            <MoreVert />
                          </IconButton>
                        </ListItemSecondaryAction>
                      </ListItem>
                    </motion.div>
                  ))}
                </List>
                
                {/* Pagination */}
                {totalPages > 1 && (
                  <Box sx={{ display: 'flex', justifyContent: 'center', mt: 2 }}>
                    <Pagination
                      count={totalPages}
                      page={currentPage}
                      onChange={handlePageChange}
                      color="primary"
                    />
                  </Box>
                )}
              </>
            )}
          </Box>
        </Card>

        {/* Notification Menu */}
        <Menu
          anchorEl={menuAnchorEl}
          open={Boolean(menuAnchorEl)}
          onClose={handleMenuClose}
        >
          {selectedNotification && !selectedNotification.is_read && (
            <MenuItem onClick={() => handleMarkAsRead(selectedNotification)}>
              <ListItemIcon>
                <CheckCircle fontSize="small" />
              </ListItemIcon>
              <ListItemText>Mark as read</ListItemText>
            </MenuItem>
          )}
          {selectedNotification && selectedNotification.action_url && (
            <MenuItem onClick={() => {
              window.location.href = selectedNotification.action_url || '#'
              handleMenuClose()
            }}>
              <ListItemIcon>
                <Info fontSize="small" />
              </ListItemIcon>
              <ListItemText>View details</ListItemText>
            </MenuItem>
          )}
          {selectedNotification && (
            <MenuItem onClick={() => handleDeleteNotification(selectedNotification)}>
              <ListItemIcon>
                <Delete fontSize="small" />
              </ListItemIcon>
              <ListItemText>Delete</ListItemText>
            </MenuItem>
          )}
        </Menu>
      </motion.div>
    </Box>
  )
}