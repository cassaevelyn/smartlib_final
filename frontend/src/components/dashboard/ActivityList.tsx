import { ReactNode } from 'react'
import { 
  List, 
  ListItem, 
  ListItemIcon, 
  ListItemText, 
  Typography, 
  Chip, 
  Box, 
  Button,
  Divider,
} from '@mui/material'
import { ChevronRight } from '@mui/icons-material'
import { motion } from 'framer-motion'
import { RecentActivity } from '../../types'
import { formatRelativeTime } from '../../lib/utils'

interface ActivityListProps {
  activities: RecentActivity[]
  title: string
  icon: ReactNode
  onViewAll?: () => void
  emptyMessage?: string
}

export function ActivityList({ 
  activities, 
  title, 
  icon, 
  onViewAll, 
  emptyMessage = 'No recent activities' 
}: ActivityListProps) {
  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center' }}>
          {icon}
          <Typography variant="h5" component="h2" sx={{ ml: 1 }}>
            {title}
          </Typography>
        </Box>
        {onViewAll && (
          <Button
            variant="text"
            endIcon={<ChevronRight />}
            onClick={onViewAll}
          >
            View All
          </Button>
        )}
      </Box>
      <Divider sx={{ mb: 2 }} />
      
      {activities.length === 0 ? (
        <Typography variant="body1" color="text.secondary" sx={{ textAlign: 'center', py: 4 }}>
          {emptyMessage}
        </Typography>
      ) : (
        <List>
          {activities.map((activity, index) => (
            <motion.div
              key={activity.id}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.3, delay: index * 0.1 }}
            >
              <ListItem
                alignItems="flex-start"
                secondaryAction={
                  <Chip
                    label={activity.status}
                    size="small"
                    color={
                      activity.status === 'CONFIRMED' || activity.status === 'APPROVED'
                        ? 'success'
                        : activity.status === 'READY_FOR_PICKUP'
                        ? 'info'
                        : 'default'
                    }
                  />
                }
                sx={{ 
                  mb: 1, 
                  borderRadius: 1,
                  '&:hover': { bgcolor: 'action.hover' }
                }}
              >
                <ListItemText
                  primary={activity.title}
                  secondary={
                    <>
                      <Typography
                        component="span"
                        variant="body2"
                        color="text.primary"
                      >
                        {activity.description}
                      </Typography>
                      <Typography
                        component="span"
                        variant="caption"
                        color="text.secondary"
                        sx={{ display: 'block' }}
                      >
                        {formatRelativeTime(activity.timestamp)}
                      </Typography>
                    </>
                  }
                />
              </ListItem>
            </motion.div>
          ))}
        </List>
      )}
    </Box>
  )
}