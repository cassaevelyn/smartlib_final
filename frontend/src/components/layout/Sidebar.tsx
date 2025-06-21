import {
  Drawer,
  List,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Divider,
  Box,
  Typography,
  Avatar,
  Chip,
  Badge,
} from '@mui/material'
import {
  Dashboard,
  LocalLibrary,
  EventSeat,
  MenuBook,
  Event,
  Person,
  Settings,
  AdminPanelSettings,
  Analytics,
  People,
  Notifications,
  CreditCard,
} from '@mui/icons-material'
import { useLocation, useNavigate } from 'react-router-dom'
import { useAuthStore } from '../../stores/authStore'
import { motion } from 'framer-motion'
import { useState, useEffect } from 'react'
import { notificationService } from '../../services/notificationService'

interface SidebarProps {
  open: boolean
  onClose: () => void
  variant: 'temporary' | 'persistent'
}

const menuItems = [
  { text: 'Dashboard', icon: Dashboard, path: '/' },
  { text: 'Libraries', icon: LocalLibrary, path: '/libraries' },
  { text: 'Seats', icon: EventSeat, path: '/seats' },
  { text: 'Books', icon: MenuBook, path: '/books' },
  { text: 'Events', icon: Event, path: '/events' },
]

const userMenuItems = [
  { text: 'My Libraries', icon: LocalLibrary, path: '/my-libraries' },
  { text: 'My Bookings', icon: EventSeat, path: '/my-bookings' },
  { text: 'My Reservations', icon: MenuBook, path: '/my-reservations' },
  { text: 'My Events', icon: Event, path: '/my-events' },
  { text: 'Notifications', icon: Notifications, path: '/notifications', badge: true },
  { text: 'Subscriptions', icon: CreditCard, path: '/subscriptions' },
  { text: 'Profile', icon: Person, path: '/profile' },
  { text: 'Settings', icon: Settings, path: '/settings' },
]

const superAdminMenuItems = [
  { text: 'SuperAdmin Dashboard', icon: AdminPanelSettings, path: '/superadmin' },
  { text: 'Users', icon: People, path: '/superadmin/users' },
  { text: 'Admins', icon: AdminPanelSettings, path: '/superadmin/admins' },
  { text: 'Libraries', icon: LocalLibrary, path: '/superadmin/libraries' },
  { text: 'Library Applications', icon: LocalLibrary, path: '/superadmin/library-applications' },
  { text: 'Seats', icon: EventSeat, path: '/superadmin/seats' },
  { text: 'Books', icon: MenuBook, path: '/superadmin/books' },
  { text: 'Events', icon: Event, path: '/superadmin/events' },
  { text: 'Analytics', icon: Analytics, path: '/superadmin/analytics' },
]

// Admin menu items
const adminMenuItems = [
  { text: 'Admin Dashboard', icon: AdminPanelSettings, path: '/admin' },
  { text: 'Manage Library', icon: LocalLibrary, path: '/admin/managed-library' },
  { text: 'Users', icon: People, path: '/admin/users' },
]

export function Sidebar({ open, onClose, variant }: SidebarProps) {
  const location = useLocation()
  const navigate = useNavigate()
  const { user } = useAuthStore()
  const [unreadCount, setUnreadCount] = useState(0)

  useEffect(() => {
    fetchUnreadCount()
    
    // Set up polling for unread count
    const interval = setInterval(fetchUnreadCount, 60000) // Check every minute
    
    return () => clearInterval(interval)
  }, [])

  const fetchUnreadCount = async () => {
    try {
      const response = await notificationService.getUnreadCount()
      setUnreadCount(response.count)
    } catch (error) {
      console.error('Failed to fetch unread count:', error)
    }
  }

  const handleNavigation = (path: string) => {
    navigate(path)
    if (variant === 'temporary') {
      onClose()
    }
  }

  const isActive = (path: string) => {
    if (path === '/') {
      // Only match exactly '/' or '/dashboard'
      return location.pathname === '/' || location.pathname === '/dashboard'
    }
    
    // For other paths, check if the current path starts with this path
    // But ensure it's a complete segment match (e.g., '/profile' should not match '/profile-something')
    // Also ensure that paths like '/superadmin' don't match '/superadmin/users'
    if (path === '/superadmin' || path === '/admin') {
      return location.pathname === path
    }
    
    return location.pathname === path || 
           (location.pathname.startsWith(path) && 
            (location.pathname.length === path.length || location.pathname[path.length] === '/'))
  }

  const drawerContent = (
    <Box sx={{ width: 280, height: '100%', display: 'flex', flexDirection: 'column' }}>
      {/* User Profile Section */}
      <Box sx={{ p: 3, borderBottom: 1, borderColor: 'divider' }}>
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
          <Avatar
            src={user?.avatar}
            sx={{ width: 48, height: 48, mr: 2 }}
          >
            {user?.first_name?.[0]}{user?.last_name?.[0]}
          </Avatar>
          <Box sx={{ flexGrow: 1, minWidth: 0 }}>
            <Typography variant="subtitle1" noWrap>
              {user?.full_name}
            </Typography>
            <Typography variant="body2" color="text.secondary" noWrap>
              {user?.email}
            </Typography>
          </Box>
        </Box>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Chip
            label={user?.role?.replace('_', ' ')}
            size="small"
            color={user?.role === 'SUPER_ADMIN' ? 'error' : user?.role === 'ADMIN' ? 'warning' : 'primary'}
            sx={{ fontSize: '0.75rem' }}
          />
          {user?.has_active_subscription && (
            <Chip
              label="Premium"
              size="small"
              color="success"
              sx={{ fontSize: '0.75rem' }}
            />
          )}
        </Box>
      </Box>

      {/* Main Navigation */}
      <Box sx={{ flexGrow: 1, overflow: 'auto' }}>
        {/* Only show general menu items for students, not for admins */}
        {user?.role === 'STUDENT' && (
          <List>
            {menuItems.map((item) => (
              <motion.div
                key={item.path}
                whileHover={{ x: 4 }}
                transition={{ type: 'spring', stiffness: 300, damping: 30 }}
              >
                <ListItem disablePadding>
                  <ListItemButton
                    selected={isActive(item.path)}
                    onClick={() => handleNavigation(item.path)}
                    sx={{
                      mx: 1,
                      borderRadius: 2,
                      '&.Mui-selected': {
                        backgroundColor: 'primary.main',
                        color: 'primary.contrastText',
                        '&:hover': {
                          backgroundColor: 'primary.dark',
                        },
                        '& .MuiListItemIcon-root': {
                          color: 'primary.contrastText',
                        },
                      },
                    }}
                  >
                    <ListItemIcon>
                      <item.icon />
                    </ListItemIcon>
                    <ListItemText primary={item.text} />
                  </ListItemButton>
                </ListItem>
              </motion.div>
            ))}
          </List>
        )}

        <Divider sx={{ my: 2 }} />

        {/* User Menu */}
        <Typography variant="overline" sx={{ px: 3, color: 'text.secondary' }}>
          My Account
        </Typography>
        <List>
          {userMenuItems.map((item) => (
            <motion.div
              key={item.path}
              whileHover={{ x: 4 }}
              transition={{ type: 'spring', stiffness: 300, damping: 30 }}
            >
              <ListItem disablePadding>
                <ListItemButton
                  selected={isActive(item.path)}
                  onClick={() => handleNavigation(item.path)}
                  sx={{
                    mx: 1,
                    borderRadius: 2,
                    '&.Mui-selected': {
                      backgroundColor: 'primary.main',
                      color: 'primary.contrastText',
                      '&:hover': {
                        backgroundColor: 'primary.dark',
                      },
                      '& .MuiListItemIcon-root': {
                        color: 'primary.contrastText',
                      },
                    },
                  }}
                >
                  <ListItemIcon>
                    {item.badge ? (
                      <Badge badgeContent={unreadCount} color="error">
                        <item.icon />
                      </Badge>
                    ) : (
                      <item.icon />
                    )}
                  </ListItemIcon>
                  <ListItemText primary={item.text} />
                </ListItemButton>
              </ListItem>
            </motion.div>
          ))}
        </List>

        {/* Admin Menu - Only for regular admins */}
        {user?.role === 'ADMIN' && (
          <>
            <Divider sx={{ my: 2 }} />
            <Typography variant="overline" sx={{ px: 3, color: 'text.secondary' }}>
              Administration
            </Typography>
            <List>
              {adminMenuItems.map((item) => (
                <motion.div
                  key={item.path}
                  whileHover={{ x: 4 }}
                  transition={{ type: 'spring', stiffness: 300, damping: 30 }}
                >
                  <ListItem disablePadding>
                    <ListItemButton
                      selected={isActive(item.path)}
                      onClick={() => handleNavigation(item.path)}
                      sx={{
                        mx: 1,
                        borderRadius: 2,
                        '&.Mui-selected': {
                          backgroundColor: 'primary.main',
                          color: 'primary.contrastText',
                          '&:hover': {
                            backgroundColor: 'primary.dark',
                          },
                          '& .MuiListItemIcon-root': {
                            color: 'primary.contrastText',
                          },
                        },
                      }}
                    >
                      <ListItemIcon>
                        <item.icon />
                      </ListItemIcon>
                      <ListItemText primary={item.text} />
                    </ListItemButton>
                  </ListItem>
                </motion.div>
              ))}
            </List>
          </>
        )}

        {/* SuperAdmin Menu */}
        {user?.role === 'SUPER_ADMIN' && (
          <>
            <Divider sx={{ my: 2 }} />
            <Typography variant="overline" sx={{ px: 3, color: 'text.secondary' }}>
              Super Administration
            </Typography>
            <List>
              {superAdminMenuItems.map((item) => (
                <motion.div
                  key={item.path}
                  whileHover={{ x: 4 }}
                  transition={{ type: 'spring', stiffness: 300, damping: 30 }}
                >
                  <ListItem disablePadding>
                    <ListItemButton
                      selected={isActive(item.path)}
                      onClick={() => handleNavigation(item.path)}
                      sx={{
                        mx: 1,
                        borderRadius: 2,
                        '&.Mui-selected': {
                          backgroundColor: 'primary.main',
                          color: 'primary.contrastText',
                          '&:hover': {
                            backgroundColor: 'primary.dark',
                          },
                          '& .MuiListItemIcon-root': {
                            color: 'primary.contrastText',
                          },
                        },
                      }}
                    >
                      <ListItemIcon>
                        <item.icon />
                      </ListItemIcon>
                      <ListItemText primary={item.text} />
                    </ListItemButton>
                  </ListItem>
                </motion.div>
              ))}
            </List>
          </>
        )}
      </Box>
    </Box>
  )

  return (
    <Drawer
      variant={variant}
      open={open}
      onClose={onClose}
      ModalProps={{
        keepMounted: true, // Better open performance on mobile
      }}
      sx={{
        '& .MuiDrawer-paper': {
          boxSizing: 'border-box',
          width: 280,
          borderRight: 1,
          borderColor: 'divider',
        },
      }}
    >
      {drawerContent}
    </Drawer>
  )
}