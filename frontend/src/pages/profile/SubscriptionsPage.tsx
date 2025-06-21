import { useState, useEffect } from 'react'
import {
  Box,
  Typography,
  Grid,
  Card,
  CardContent,
  Button,
  Chip,
  Divider,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Alert,
  LinearProgress,
  Tabs,
  Tab,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  MenuItem,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
} from '@mui/material'
import {
  CreditCard,
  CheckCircle,
  Cancel,
  CalendarToday,
  AccessTime,
  Refresh,
  EventSeat,
  MenuBook,
  Event,
  EmojiEvents,
  ArrowForward,
  History,
  Payment,
  AttachMoney,
  Receipt,
} from '@mui/icons-material'
import { motion } from 'framer-motion'
import { useForm, Controller } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { subscriptionService } from '../../services/subscriptionService'
import { recommendationService } from '../../services/recommendationService'
import { SubscriptionPlan, UserSubscription, SubscriptionTransaction } from '../../types'
import { LoadingSpinner } from '../../components/ui/loading-spinner'
import { useToast } from '../../hooks/use-toast'
import { formatDate, formatCurrency } from '../../lib/utils'

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
      id={`subscription-tabpanel-${index}`}
      aria-labelledby={`subscription-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </div>
  )
}

// Schema for purchase form
const purchaseSchema = z.object({
  plan_id: z.string().min(1, 'Please select a plan'),
  payment_method: z.string().min(1, 'Payment method is required'),
  payment_reference: z.string().optional(),
  is_auto_renew: z.boolean().default(true),
})

type PurchaseForm = z.infer<typeof purchaseSchema>

// Schema for cancel form
const cancelSchema = z.object({
  subscription_id: z.string().min(1, 'Subscription ID is required'),
  cancellation_reason: z.string().optional(),
})

type CancelForm = z.infer<typeof cancelSchema>

// Schema for renew form
const renewSchema = z.object({
  subscription_id: z.string().min(1, 'Subscription ID is required'),
  payment_method: z.string().min(1, 'Payment method is required'),
  payment_reference: z.string().optional(),
})

type RenewForm = z.infer<typeof renewSchema>

export function SubscriptionsPage() {
  const { toast } = useToast()
  
  const [tabValue, setTabValue] = useState(0)
  const [plans, setPlans] = useState<SubscriptionPlan[]>([])
  const [currentSubscription, setCurrentSubscription] = useState<UserSubscription | null>(null)
  const [subscriptions, setSubscriptions] = useState<UserSubscription[]>([])
  const [transactions, setTransactions] = useState<SubscriptionTransaction[]>([])
  const [recommendedPlans, setRecommendedPlans] = useState<any>(null)
  const [selectedPlan, setSelectedPlan] = useState<SubscriptionPlan | null>(null)
  
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  
  // Dialog states
  const [purchaseDialogOpen, setPurchaseDialogOpen] = useState(false)
  const [cancelDialogOpen, setCancelDialogOpen] = useState(false)
  const [renewDialogOpen, setRenewDialogOpen] = useState(false)
  const [isSubmitting, setIsSubmitting] = useState(false)

  // Purchase form
  const {
    control: purchaseControl,
    handleSubmit: handlePurchaseSubmit,
    setValue: setPurchaseValue,
    formState: { errors: purchaseErrors },
    reset: resetPurchaseForm,
  } = useForm<PurchaseForm>({
    resolver: zodResolver(purchaseSchema),
    defaultValues: {
      plan_id: '',
      payment_method: 'CREDIT_CARD',
      payment_reference: '',
      is_auto_renew: true,
    },
  })

  // Cancel form
  const {
    control: cancelControl,
    handleSubmit: handleCancelSubmit,
    setValue: setCancelValue,
    formState: { errors: cancelErrors },
    reset: resetCancelForm,
  } = useForm<CancelForm>({
    resolver: zodResolver(cancelSchema),
    defaultValues: {
      subscription_id: '',
      cancellation_reason: '',
    },
  })

  // Renew form
  const {
    control: renewControl,
    handleSubmit: handleRenewSubmit,
    setValue: setRenewValue,
    formState: { errors: renewErrors },
    reset: resetRenewForm,
  } = useForm<RenewForm>({
    resolver: zodResolver(renewSchema),
    defaultValues: {
      subscription_id: '',
      payment_method: 'CREDIT_CARD',
      payment_reference: '',
    },
  })

  useEffect(() => {
    fetchSubscriptionData()
  }, [])

  const fetchSubscriptionData = async () => {
    try {
      setIsLoading(true)
      setError(null)
      
      // Fetch all subscription data in parallel
      const [plansResponse, currentSubResponse, subscriptionsResponse, transactionsResponse, recommendationsResponse] = 
        await Promise.all([
          subscriptionService.getPlans(),
          subscriptionService.getCurrentSubscription().catch(() => null),
          subscriptionService.getUserSubscriptions(),
          subscriptionService.getTransactions(),
          recommendationService.getSubscriptionsRecommendations()
        ]);
      
      setPlans(plansResponse.results);
      setCurrentSubscription(currentSubResponse);
      setSubscriptions(subscriptionsResponse.results);
      setTransactions(transactionsResponse.results);
      setRecommendedPlans(recommendationsResponse);
      
    } catch (error: any) {
      setError(error.message || 'Failed to fetch subscription data')
    } finally {
      setIsLoading(false)
    }
  }

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue)
  }

  const handlePurchase = (plan: SubscriptionPlan) => {
    setSelectedPlan(plan)
    setPurchaseValue('plan_id', plan.id)
    setPurchaseDialogOpen(true)
  }

  const handleCancel = (subscription: UserSubscription) => {
    setCancelValue('subscription_id', subscription.id)
    setCancelDialogOpen(true)
  }

  const handleRenew = (subscription: UserSubscription) => {
    setRenewValue('subscription_id', subscription.id)
    setRenewDialogOpen(true)
  }

  const onSubmitPurchase = async (data: PurchaseForm) => {
    try {
      setIsSubmitting(true)
      
      await subscriptionService.purchaseSubscription(data)
      
      toast({
        title: "Subscription Purchased",
        description: "Your subscription has been purchased successfully.",
        variant: "default",
      })
      
      setPurchaseDialogOpen(false)
      resetPurchaseForm()
      
      // Refresh subscription data
      fetchSubscriptionData()
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || 'Failed to purchase subscription',
        variant: "destructive",
      })
    } finally {
      setIsSubmitting(false)
    }
  }

  const onSubmitCancel = async (data: CancelForm) => {
    try {
      setIsSubmitting(true)
      
      await subscriptionService.cancelSubscription(data)
      
      toast({
        title: "Subscription Cancelled",
        description: "Your subscription has been cancelled successfully.",
        variant: "default",
      })
      
      setCancelDialogOpen(false)
      resetCancelForm()
      
      // Refresh subscription data
      fetchSubscriptionData()
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || 'Failed to cancel subscription',
        variant: "destructive",
      })
    } finally {
      setIsSubmitting(false)
    }
  }

  const onSubmitRenew = async (data: RenewForm) => {
    try {
      setIsSubmitting(true)
      
      await subscriptionService.renewSubscription(data)
      
      toast({
        title: "Subscription Renewed",
        description: "Your subscription has been renewed successfully.",
        variant: "default",
      })
      
      setRenewDialogOpen(false)
      resetRenewForm()
      
      // Refresh subscription data
      fetchSubscriptionData()
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || 'Failed to renew subscription',
        variant: "destructive",
      })
    } finally {
      setIsSubmitting(false)
    }
  }

  const renderPlanCard = (plan: SubscriptionPlan, featured: boolean = false) => {
    const isCurrentPlan = currentSubscription && currentSubscription.plan === plan.id
    
    return (
      <Card 
        sx={{ 
          height: '100%', 
          display: 'flex', 
          flexDirection: 'column',
          border: featured ? 2 : 0,
          borderColor: 'primary.main',
          position: 'relative',
        }}
      >
        {featured && (
          <Box
            sx={{
              position: 'absolute',
              top: 10,
              right: 0,
              bgcolor: 'primary.main',
              color: 'white',
              px: 2,
              py: 0.5,
              borderTopLeftRadius: 4,
              borderBottomLeftRadius: 4,
              fontWeight: 'bold',
              fontSize: '0.8rem',
            }}
          >
            RECOMMENDED
          </Box>
        )}
        <CardContent sx={{ flexGrow: 1 }}>
          <Box sx={{ mb: 2 }}>
            <Typography variant="h5" gutterBottom>
              {plan.name}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {plan.description}
            </Typography>
          </Box>
          
          <Box sx={{ mb: 3 }}>
            <Box sx={{ display: 'flex', alignItems: 'baseline' }}>
              <Typography variant="h3" component="span">
                {formatCurrency(plan.discounted_price)}
              </Typography>
              <Typography variant="subtitle1" component="span" sx={{ ml: 1 }}>
                / {plan.billing_period_display.toLowerCase()}
              </Typography>
            </Box>
            {plan.discount_percentage > 0 && (
              <Typography variant="body2" color="error">
                <s>{formatCurrency(plan.price)}</s> ({plan.discount_percentage}% off)
              </Typography>
            )}
          </Box>
          
          <Divider sx={{ mb: 2 }} />
          
          <List dense>
            <ListItem>
              <ListItemIcon>
                <MenuBook fontSize="small" />
              </ListItemIcon>
              <ListItemText primary={`${plan.max_book_reservations} book reservations`} />
            </ListItem>
            <ListItem>
              <ListItemIcon>
                <EventSeat fontSize="small" />
              </ListItemIcon>
              <ListItemText primary={`${plan.max_seat_bookings} seat bookings`} />
            </ListItem>
            <ListItem>
              <ListItemIcon>
                <Event fontSize="small" />
              </ListItemIcon>
              <ListItemText primary={`${plan.max_event_registrations} event registrations`} />
            </ListItem>
            {plan.has_premium_book_access && (
              <ListItem>
                <ListItemIcon>
                  <CheckCircle fontSize="small" color="success" />
                </ListItemIcon>
                <ListItemText primary="Access to premium books" />
              </ListItem>
            )}
            {plan.has_premium_seat_access && (
              <ListItem>
                <ListItemIcon>
                  <CheckCircle fontSize="small" color="success" />
                </ListItemIcon>
                <ListItemText primary="Access to premium seats" />
              </ListItem>
            )}
            {plan.has_premium_event_access && (
              <ListItem>
                <ListItemIcon>
                  <CheckCircle fontSize="small" color="success" />
                </ListItemIcon>
                <ListItemText primary="Access to premium events" />
              </ListItem>
            )}
            {plan.features && plan.features.map((feature, index) => (
              <ListItem key={index}>
                <ListItemIcon>
                  <CheckCircle fontSize="small" color="success" />
                </ListItemIcon>
                <ListItemText primary={feature} />
              </ListItem>
            ))}
          </List>
        </CardContent>
        <Box sx={{ p: 2, pt: 0 }}>
          <Button
            variant={isCurrentPlan ? "outlined" : "contained"}
            fullWidth
            disabled={isCurrentPlan}
            onClick={() => handlePurchase(plan)}
          >
            {isCurrentPlan ? 'Current Plan' : 'Subscribe'}
          </Button>
        </Box>
      </Card>
    )
  }

  if (isLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '50vh' }}>
        <LoadingSpinner size="lg" />
      </Box>
    )
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
            Subscriptions
          </Typography>
          <Typography variant="body1" color="text.secondary">
            Manage your subscription plans and access premium features.
          </Typography>
        </Box>

        {error && (
          <Alert severity="error" sx={{ mb: 3 }}>
            {error}
          </Alert>
        )}

        {/* Current Subscription */}
        {currentSubscription ? (
          <Card sx={{ mb: 4 }}>
            <CardContent>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                <Typography variant="h5" component="h2">
                  Current Subscription
                </Typography>
                <Chip
                  label={currentSubscription.status_display}
                  color={currentSubscription.status === 'ACTIVE' ? 'success' : 'warning'}
                />
              </Box>
              
              <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                  <Typography variant="h6" gutterBottom>
                    {currentSubscription.plan_display}
                  </Typography>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                    <CalendarToday fontSize="small" color="action" sx={{ mr: 0.5 }} />
                    <Typography variant="body2" color="text.secondary">
                      {formatDate(currentSubscription.start_date)} - {formatDate(currentSubscription.end_date)}
                    </Typography>
                  </Box>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                    <AccessTime fontSize="small" color="action" sx={{ mr: 0.5 }} />
                    <Typography variant="body2" color="text.secondary">
                      {currentSubscription.days_remaining} days remaining
                    </Typography>
                  </Box>
                  <Box sx={{ mt: 1 }}>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
                      <Typography variant="caption" color="text.secondary">
                        0%
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {Math.round(currentSubscription.percentage_remaining)}%
                      </Typography>
                    </Box>
                    <LinearProgress 
                      variant="determinate" 
                      value={currentSubscription.percentage_remaining} 
                      sx={{ height: 6, borderRadius: 3 }}
                    />
                  </Box>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                    <Typography variant="h6">
                      {formatCurrency(currentSubscription.amount_paid)}
                    </Typography>
                    {currentSubscription.is_auto_renew && (
                      <Chip
                        label="Auto-Renew"
                        color="info"
                        size="small"
                      />
                    )}
                  </Box>
                  <Box sx={{ display: 'flex', gap: 1, mt: 3 }}>
                    <Button
                      variant="outlined"
                      color="error"
                      startIcon={<Cancel />}
                      onClick={() => handleCancel(currentSubscription)}
                    >
                      Cancel Subscription
                    </Button>
                    <Button
                      variant="outlined"
                      startIcon={<Refresh />}
                      onClick={() => handleRenew(currentSubscription)}
                    >
                      Renew
                    </Button>
                  </Box>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        ) : (
          <Alert severity="info" sx={{ mb: 4 }}>
            You don't have an active subscription. Subscribe to a plan to access premium features.
          </Alert>
        )}

        {/* Tabs for different sections */}
        <Card>
          <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
            <Tabs
              value={tabValue}
              onChange={handleTabChange}
              aria-label="subscription tabs"
              variant="fullWidth"
            >
              <Tab 
                icon={<CreditCard />} 
                label="Plans" 
                iconPosition="start" 
              />
              <Tab 
                icon={<History />} 
                label="History" 
                iconPosition="start" 
              />
              <Tab 
                icon={<Receipt />} 
                label="Transactions" 
                iconPosition="start" 
              />
            </Tabs>
          </Box>

          {/* Plans Tab */}
          <TabPanel value={tabValue} index={0}>
            <Typography variant="h6" gutterBottom>
              Available Subscription Plans
            </Typography>
            
            {plans.length === 0 ? (
              <Alert severity="info">
                No subscription plans available at the moment.
              </Alert>
            ) : (
              <Grid container spacing={3}>
                {plans.map((plan) => (
                  <Grid item xs={12} md={4} key={plan.id}>
                    {renderPlanCard(
                      plan, 
                      recommendedPlans?.featured_plan?.id === plan.id || 
                      (recommendedPlans?.has_subscription && recommendedPlans?.upgrade_options?.[0]?.id === plan.id)
                    )}
                  </Grid>
                ))}
              </Grid>
            )}
          </TabPanel>

          {/* History Tab */}
          <TabPanel value={tabValue} index={1}>
            <Typography variant="h6" gutterBottom>
              Subscription History
            </Typography>
            
            {subscriptions.length === 0 ? (
              <Alert severity="info">
                You don't have any subscription history yet.
              </Alert>
            ) : (
              <List>
                {subscriptions.map((subscription) => (
                  <Paper key={subscription.id} sx={{ mb: 2, p: 2 }}>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 1 }}>
                      <Typography variant="h6">
                        {subscription.plan_display}
                      </Typography>
                      <Chip
                        label={subscription.status_display}
                        color={
                          subscription.status === 'ACTIVE' ? 'success' :
                          subscription.status === 'CANCELLED' ? 'error' :
                          subscription.status === 'EXPIRED' ? 'warning' :
                          'default'
                        }
                        size="small"
                      />
                    </Box>
                    
                    <Grid container spacing={2}>
                      <Grid item xs={12} sm={6}>
                        <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                          <CalendarToday fontSize="small" color="action" sx={{ mr: 0.5 }} />
                          <Typography variant="body2" color="text.secondary">
                            {formatDate(subscription.start_date)} - {formatDate(subscription.end_date)}
                          </Typography>
                        </Box>
                        {subscription.cancelled_at && (
                          <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                            <Cancel fontSize="small" color="error" sx={{ mr: 0.5 }} />
                            <Typography variant="body2" color="error">
                              Cancelled on {formatDate(subscription.cancelled_at)}
                            </Typography>
                          </Box>
                        )}
                      </Grid>
                      <Grid item xs={12} sm={6}>
                        <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                          <Payment fontSize="small" color="action" sx={{ mr: 0.5 }} />
                          <Typography variant="body2" color="text.secondary">
                            {formatCurrency(subscription.amount_paid)} - {subscription.payment_status_display}
                          </Typography>
                        </Box>
                        <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                          <CreditCard fontSize="small" color="action" sx={{ mr: 0.5 }} />
                          <Typography variant="body2" color="text.secondary">
                            {subscription.payment_method}
                          </Typography>
                        </Box>
                      </Grid>
                    </Grid>
                    
                    {subscription.status === 'ACTIVE' && (
                      <Box sx={{ display: 'flex', gap: 1, mt: 2 }}>
                        <Button
                          variant="outlined"
                          color="error"
                          size="small"
                          startIcon={<Cancel />}
                          onClick={() => handleCancel(subscription)}
                        >
                          Cancel
                        </Button>
                        <Button
                          variant="outlined"
                          size="small"
                          startIcon={<Refresh />}
                          onClick={() => handleRenew(subscription)}
                        >
                          Renew
                        </Button>
                      </Box>
                    )}
                    
                    {subscription.status === 'EXPIRED' && (
                      <Box sx={{ display: 'flex', gap: 1, mt: 2 }}>
                        <Button
                          variant="outlined"
                          size="small"
                          startIcon={<Refresh />}
                          onClick={() => handleRenew(subscription)}
                        >
                          Renew
                        </Button>
                      </Box>
                    )}
                  </Paper>
                ))}
              </List>
            )}
          </TabPanel>

          {/* Transactions Tab */}
          <TabPanel value={tabValue} index={2}>
            <Typography variant="h6" gutterBottom>
              Transaction History
            </Typography>
            
            {transactions.length === 0 ? (
              <Alert severity="info">
                You don't have any transaction history yet.
              </Alert>
            ) : (
              <TableContainer component={Paper}>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Date</TableCell>
                      <TableCell>Transaction</TableCell>
                      <TableCell>Type</TableCell>
                      <TableCell>Amount</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell>Payment Method</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {transactions.map((transaction) => (
                      <TableRow key={transaction.id}>
                        <TableCell>{formatDate(transaction.created_at)}</TableCell>
                        <TableCell>{transaction.transaction_code}</TableCell>
                        <TableCell>{transaction.transaction_type_display}</TableCell>
                        <TableCell>{formatCurrency(transaction.amount)}</TableCell>
                        <TableCell>
                          <Chip
                            label={transaction.status_display}
                            size="small"
                            color={
                              transaction.status === 'COMPLETED' ? 'success' :
                              transaction.status === 'FAILED' ? 'error' :
                              transaction.status === 'REFUNDED' ? 'warning' :
                              'default'
                            }
                          />
                        </TableCell>
                        <TableCell>{transaction.payment_method}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
          </TabPanel>
        </Card>

        {/* Purchase Dialog */}
        <Dialog
          open={purchaseDialogOpen}
          onClose={() => !isSubmitting && setPurchaseDialogOpen(false)}
          maxWidth="sm"
          fullWidth
        >
          <DialogTitle>Subscribe to Plan</DialogTitle>
          <DialogContent>
            {selectedPlan && (
              <Box sx={{ mb: 3 }}>
                <Typography variant="h6" gutterBottom>
                  {selectedPlan.name}
                </Typography>
                <Typography variant="body1" gutterBottom>
                  {formatCurrency(selectedPlan.discounted_price)} / {selectedPlan.billing_period_display.toLowerCase()}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {selectedPlan.description}
                </Typography>
              </Box>
            )}
            
            <Box component="form" sx={{ mt: 3 }}>
              <Controller
                name="payment_method"
                control={purchaseControl}
                render={({ field }) => (
                  <TextField
                    {...field}
                    select
                    label="Payment Method"
                    fullWidth
                    margin="normal"
                    error={!!purchaseErrors.payment_method}
                    helperText={purchaseErrors.payment_method?.message}
                  >
                    <MenuItem value="CREDIT_CARD">Credit Card</MenuItem>
                    <MenuItem value="DEBIT_CARD">Debit Card</MenuItem>
                    <MenuItem value="BANK_TRANSFER">Bank Transfer</MenuItem>
                    <MenuItem value="MOBILE_PAYMENT">Mobile Payment</MenuItem>
                  </TextField>
                )}
              />
              
              <Controller
                name="payment_reference"
                control={purchaseControl}
                render={({ field }) => (
                  <TextField
                    {...field}
                    label="Payment Reference (Optional)"
                    fullWidth
                    margin="normal"
                    placeholder="Transaction ID or reference number"
                    error={!!purchaseErrors.payment_reference}
                    helperText={purchaseErrors.payment_reference?.message}
                  />
                )}
              />
              
              <Controller
                name="is_auto_renew"
                control={purchaseControl}
                render={({ field }) => (
                  <Box sx={{ mt: 2 }}>
                    <Typography variant="body2" gutterBottom>
                      Auto-Renewal
                    </Typography>
                    <Box sx={{ display: 'flex', gap: 2 }}>
                      <Button
                        variant={field.value ? "contained" : "outlined"}
                        onClick={() => field.onChange(true)}
                      >
                        Enable
                      </Button>
                      <Button
                        variant={!field.value ? "contained" : "outlined"}
                        onClick={() => field.onChange(false)}
                      >
                        Disable
                      </Button>
                    </Box>
                    <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 1 }}>
                      {field.value 
                        ? "Your subscription will automatically renew when it expires." 
                        : "Your subscription will not renew automatically. You'll need to manually renew it."}
                    </Typography>
                  </Box>
                )}
              />
              
              <Alert severity="info" sx={{ mt: 3 }}>
                In a real application, this would connect to a payment gateway to process your payment securely.
                For this demo, we'll simulate a successful payment.
              </Alert>
            </Box>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setPurchaseDialogOpen(false)} disabled={isSubmitting}>
              Cancel
            </Button>
            <Button
              variant="contained"
              onClick={handlePurchaseSubmit(onSubmitPurchase)}
              disabled={isSubmitting}
              startIcon={isSubmitting ? <LoadingSpinner size="sm" /> : <CreditCard />}
            >
              Subscribe
            </Button>
          </DialogActions>
        </Dialog>

        {/* Cancel Dialog */}
        <Dialog
          open={cancelDialogOpen}
          onClose={() => !isSubmitting && setCancelDialogOpen(false)}
          maxWidth="sm"
          fullWidth
        >
          <DialogTitle>Cancel Subscription</DialogTitle>
          <DialogContent>
            <Typography variant="body1" paragraph>
              Are you sure you want to cancel your subscription?
            </Typography>
            <Typography variant="body2" color="text.secondary" paragraph>
              You will still have access to premium features until the end of your current billing period.
            </Typography>
            
            <Controller
              name="cancellation_reason"
              control={cancelControl}
              render={({ field }) => (
                <TextField
                  {...field}
                  label="Reason for Cancellation (Optional)"
                  fullWidth
                  margin="normal"
                  multiline
                  rows={3}
                  error={!!cancelErrors.cancellation_reason}
                  helperText={cancelErrors.cancellation_reason?.message}
                />
              )}
            />
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setCancelDialogOpen(false)} disabled={isSubmitting}>
              Keep Subscription
            </Button>
            <Button
              variant="contained"
              color="error"
              onClick={handleCancelSubmit(onSubmitCancel)}
              disabled={isSubmitting}
              startIcon={isSubmitting ? <LoadingSpinner size="sm" /> : <Cancel />}
            >
              Confirm Cancellation
            </Button>
          </DialogActions>
        </Dialog>

        {/* Renew Dialog */}
        <Dialog
          open={renewDialogOpen}
          onClose={() => !isSubmitting && setRenewDialogOpen(false)}
          maxWidth="sm"
          fullWidth
        >
          <DialogTitle>Renew Subscription</DialogTitle>
          <DialogContent>
            <Typography variant="body1" paragraph>
              Renew your subscription to continue enjoying premium features.
            </Typography>
            
            <Controller
              name="payment_method"
              control={renewControl}
              render={({ field }) => (
                <TextField
                  {...field}
                  select
                  label="Payment Method"
                  fullWidth
                  margin="normal"
                  error={!!renewErrors.payment_method}
                  helperText={renewErrors.payment_method?.message}
                >
                  <MenuItem value="CREDIT_CARD">Credit Card</MenuItem>
                  <MenuItem value="DEBIT_CARD">Debit Card</MenuItem>
                  <MenuItem value="BANK_TRANSFER">Bank Transfer</MenuItem>
                  <MenuItem value="MOBILE_PAYMENT">Mobile Payment</MenuItem>
                </TextField>
              )}
            />
            
            <Controller
              name="payment_reference"
              control={renewControl}
              render={({ field }) => (
                <TextField
                  {...field}
                  label="Payment Reference (Optional)"
                  fullWidth
                  margin="normal"
                  placeholder="Transaction ID or reference number"
                  error={!!renewErrors.payment_reference}
                  helperText={renewErrors.payment_reference?.message}
                />
              )}
            />
            
            <Alert severity="info" sx={{ mt: 3 }}>
              In a real application, this would connect to a payment gateway to process your payment securely.
              For this demo, we'll simulate a successful payment.
            </Alert>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setRenewDialogOpen(false)} disabled={isSubmitting}>
              Cancel
            </Button>
            <Button
              variant="contained"
              onClick={handleRenewSubmit(onSubmitRenew)}
              disabled={isSubmitting}
              startIcon={isSubmitting ? <LoadingSpinner size="sm" /> : <Refresh />}
            >
              Renew Subscription
            </Button>
          </DialogActions>
        </Dialog>
      </motion.div>
    </Box>
  )
}