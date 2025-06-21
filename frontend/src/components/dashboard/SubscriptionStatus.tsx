import { useState, useEffect } from 'react'
import { 
  Box, 
  Typography, 
  Card, 
  CardContent, 
  Button, 
  Chip,
  LinearProgress,
} from '@mui/material'
import { 
  CreditCard,
  CalendarToday,
  AccessTime,
  ArrowForward,
} from '@mui/icons-material'
import { motion } from 'framer-motion'
import { useNavigate } from 'react-router-dom'
import { subscriptionService } from '../../services/subscriptionService'
import { UserSubscription } from '../../types'
import { LoadingSpinner } from '../ui/loading-spinner'
import { formatDate, formatCurrency } from '../../lib/utils'

export function SubscriptionStatus() {
  const navigate = useNavigate()
  const [subscription, setSubscription] = useState<UserSubscription | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetchSubscription()
  }, [])

  const fetchSubscription = async () => {
    try {
      setIsLoading(true)
      setError(null)
      
      const currentSub = await subscriptionService.getCurrentSubscription()
      setSubscription(currentSub)
    } catch (error: any) {
      // No active subscription, that's okay
      setSubscription(null)
      if (error.status !== 404) {
        setError(error.message || 'Failed to fetch subscription')
      }
    } finally {
      setIsLoading(false)
    }
  }

  if (isLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
        <LoadingSpinner size="md" />
      </Box>
    )
  }

  if (error) {
    return (
      <Box sx={{ p: 2 }}>
        <Typography color="error">{error}</Typography>
      </Box>
    )
  }

  if (!subscription) {
    return (
      <Card sx={{ mb: 4 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
            <Box sx={{ display: 'flex', alignItems: 'center' }}>
              <CreditCard color="primary" sx={{ mr: 1 }} />
              <Typography variant="h5" component="h2">
                Subscription
              </Typography>
            </Box>
          </Box>
          
          <Box sx={{ textAlign: 'center', py: 2 }}>
            <Typography variant="body1" color="text.secondary" gutterBottom>
              You don't have an active subscription
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Subscribe to a plan to access premium features
            </Typography>
            <Button
              variant="contained"
              onClick={() => navigate('/subscriptions')}
            >
              View Plans
            </Button>
          </Box>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card sx={{ mb: 4 }}>
      <CardContent>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center' }}>
            <CreditCard color="primary" sx={{ mr: 1 }} />
            <Typography variant="h5" component="h2">
              Subscription
            </Typography>
          </Box>
          <Button
            variant="text"
            endIcon={<ArrowForward />}
            onClick={() => navigate('/subscriptions')}
          >
            Manage
          </Button>
        </Box>
        
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
        >
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
            <Box>
              <Typography variant="h6" gutterBottom>
                {subscription.plan_display}
              </Typography>
              <Chip
                label={subscription.status_display}
                color={subscription.status === 'ACTIVE' ? 'success' : 'warning'}
                size="small"
                sx={{ mr: 1 }}
              />
              {subscription.is_auto_renew && (
                <Chip
                  label="Auto-Renew"
                  color="info"
                  size="small"
                  variant="outlined"
                />
              )}
            </Box>
            <Typography variant="h6" color="primary">
              {formatCurrency(subscription.amount_paid)}
            </Typography>
          </Box>
          
          <Box sx={{ mb: 2 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
              <CalendarToday fontSize="small" color="action" sx={{ mr: 0.5 }} />
              <Typography variant="body2" color="text.secondary">
                {formatDate(subscription.start_date)} - {formatDate(subscription.end_date)}
              </Typography>
            </Box>
            
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
              <AccessTime fontSize="small" color="action" sx={{ mr: 0.5 }} />
              <Typography variant="body2" color="text.secondary">
                {subscription.days_remaining} days remaining
              </Typography>
            </Box>
            
            <Box sx={{ mt: 1 }}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
                <Typography variant="caption" color="text.secondary">
                  0%
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {Math.round(subscription.percentage_remaining)}%
                </Typography>
              </Box>
              <LinearProgress 
                variant="determinate" 
                value={subscription.percentage_remaining} 
                sx={{ height: 6, borderRadius: 3 }}
              />
            </Box>
          </Box>
        </motion.div>
      </CardContent>
    </Card>
  )
}