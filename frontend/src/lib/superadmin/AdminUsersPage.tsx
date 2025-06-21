// frontend/src/pages/superadmin/AdminUsersPage.tsx
import { useState, useEffect } from 'react'
import {
  Box,
  Typography,
  Grid,
  Card,
  CardContent,
  Button,
  TextField,
  InputAdornment,
  Chip,
  Divider,
  Alert,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  IconButton,
  Tooltip,
  MenuItem,
} from '@mui/material'
import { DataGrid, GridColDef, GridRenderCellParams, GridToolbar } from '@mui/x-data-grid'
import {
  Search,
  CheckCircle,
  Cancel,
  Block,
  Person,
  PersonAdd,
  Visibility,
  Edit,
  Delete,
  FilterList,
} from '@mui/icons-material'
import { motion } from 'framer-motion'
import { adminService } from '../../services/adminService'
import { User } from '../../types'
import { LoadingSpinner } from '../../components/ui/loading-spinner'
import { useToast } from '../../hooks/use-toast'
import { formatDate, getRoleColor } from '../utils'

export function SuperAdminUsersPage() {
  const { toast } = useToast()
  
  const [users, setUsers] = useState<User[]>([])
  const [selectedUser, setSelectedUser] = useState<User | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [roleFilter, setRoleFilter] = useState<string>('')
  const [statusFilter, setStatusFilter] = useState<string>('')
  
  // Dialog states
  const [viewDialogOpen, setViewDialogOpen] = useState(false)
  const [approveDialogOpen, setApproveDialogOpen] = useState(false)
  const [rejectDialogOpen, setRejectDialogOpen] = useState(false)
  const [deactivateDialogOpen, setDeactivateDialogOpen] = useState(false)
  const [isProcessing, setIsProcessing] = useState(false)

  useEffect(() => {
    fetchUsers()
  }, [])

  const fetchUsers = async () => {
    try {
      setIsLoading(true)
      setError(null)
      
      const response = await adminService.getUsers()
      setUsers(response.results)
    } catch (error: any) {
      setError(error.message || 'Failed to fetch users')
    } finally {
      setIsLoading(false)
    }
  }

  const handleApproveUser = async () => {
    if (!selectedUser) return
    
    try {
      setIsProcessing(true)
      
      await adminService.approveUser(selectedUser.id)
      
      // Update local state
      setUsers(prevUsers =>
        prevUsers.map(user =>
          user.id === selectedUser.id ? { ...user, is_approved: true } : user
        )
      )
      
      toast({
        title: "User Approved",
        description: `${selectedUser.full_name} has been approved successfully.`,
        variant: "default",
      })
      
      setApproveDialogOpen(false)
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || 'Failed to approve user',
        variant: "destructive",
      })
    } finally {
      setIsProcessing(false)
    }
  }

  const handleRejectUser = async () => {
    if (!selectedUser) return
    
    try {
      setIsProcessing(true)
      
      await adminService.rejectUser(selectedUser.id)
      
      // Update local state
      setUsers(prevUsers =>
        prevUsers.map(user =>
          user.id === selectedUser.id ? { ...user, is_approved: false, is_active: false } : user
        )
      )
      
      toast({
        title: "User Rejected",
        description: `${selectedUser.full_name}'s registration has been rejected.`,
        variant: "default",
      })
      
      setRejectDialogOpen(false)
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || 'Failed to reject user',
        variant: "destructive",
      })
    } finally {
      setIsProcessing(false)
    }
  }

  const handleDeactivateUser = async () => {
    if (!selectedUser) return
    
    try {
      setIsProcessing(true)
      
      await adminService.updateUser(selectedUser.id, { 
        is_active: !selectedUser.is_active 
      })
      
      // Update local state
      setUsers(prevUsers =>
        prevUsers.map(user =>
          user.id === selectedUser.id ? { ...user, is_active: !user.is_active } : user
        )
      )
      
      toast({
        title: selectedUser.is_active ? "User Deactivated" : "User Activated",
        description: `${selectedUser.full_name} has been ${selectedUser.is_active ? 'deactivated' : 'activated'} successfully.`,
        variant: "default",
      })
      
      setDeactivateDialogOpen(false)
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || `Failed to ${selectedUser.is_active ? 'deactivate' : 'activate'} user`,
        variant: "destructive",
      })
    } finally {
      setIsProcessing(false)
    }
  }

  const filteredUsers = users.filter(user => {
    const matchesSearch = searchQuery === '' || 
      user.full_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      user.email.toLowerCase().includes(searchQuery.toLowerCase()) ||
      user.crn.toLowerCase().includes(searchQuery.toLowerCase()) ||
      user.student_id.toLowerCase().includes(searchQuery.toLowerCase())
    
    const matchesRole = roleFilter === '' || user.role === roleFilter
    
    const matchesStatus = statusFilter === '' || 
      (statusFilter === 'APPROVED' && user.is_approved) ||
      (statusFilter === 'PENDING' && !user.is_approved) ||
      (statusFilter === 'ACTIVE' && user.is_active) ||
      (statusFilter === 'INACTIVE' && !user.is_active)
    
    return matchesSearch && matchesRole && matchesStatus
  })

  const columns: GridColDef[] = [
    {
      field: 'full_name',
      headerName: 'Name',
      flex: 1,
      renderCell: (params: GridRenderCellParams<User>) => (
        <Box sx={{ display: 'flex', alignItems: 'center' }}>
          <Person sx={{ mr: 1 }} />
          {params.row.full_name}
        </Box>
      ),
    },
    {
      field: 'email',
      headerName: 'Email',
      flex: 1,
    },
    {
      field: 'crn',
      headerName: 'CRN',
      flex: 1,
    },
    {
      field: 'role',
      headerName: 'Role',
      width: 150,
      renderCell: (params: GridRenderCellParams<User>) => (
        <Chip
          label={params.row.role.replace('_', ' ')}
          size="small"
          className={getRoleColor(params.row.role)}
        />
      ),
    },
    {
      field: 'is_approved',
      headerName: 'Approval',
      width: 150,
      renderCell: (params: GridRenderCellParams<User>) => (
        <Chip
          label={params.row.is_approved ? 'Approved' : 'Pending'}
          size="small"
          color={params.row.is_approved ? 'success' : 'warning'}
          variant="outlined"
        />
      ),
    },
    {
      field: 'is_active',
      headerName: 'Status',
      width: 150,
      renderCell: (params: GridRenderCellParams<User>) => (
        <Chip
          label={params.row.is_active ? 'Active' : 'Inactive'}
          size="small"
          color={params.row.is_active ? 'success' : 'error'}
          variant="outlined"
        />
      ),
    },
    {
      field: 'created_at',
      headerName: 'Registered',
      width: 150,
      valueFormatter: (params) => formatDate(params.value as string),
    },
    {
      field: 'actions',
      headerName: 'Actions',
      width: 200,
      sortable: false,
      renderCell: (params: GridRenderCellParams<User>) => (
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Tooltip title="View Details">
            <IconButton
              size="small"
              onClick={() => {
                setSelectedUser(params.row)
                setViewDialogOpen(true)
              }}
            >
              <Visibility fontSize="small" />
            </IconButton>
          </Tooltip>
          
          {!params.row.is_approved && (
            <Tooltip title="Approve User">
              <IconButton
                size="small"
                color="success"
                onClick={() => {
                  setSelectedUser(params.row)
                  setApproveDialogOpen(true)
                }}
              >
                <CheckCircle fontSize="small" />
              </IconButton>
            </Tooltip>
          )}
          
          {!params.row.is_approved && (
            <Tooltip title="Reject User">
              <IconButton
                size="small"
                color="error"
                onClick={() => {
                  setSelectedUser(params.row)
                  setRejectDialogOpen(true)
                }}
              >
                <Cancel fontSize="small" />
              </IconButton>
            </Tooltip>
          )}
          
          <Tooltip title={params.row.is_active ? "Deactivate User" : "Activate User"}>
            <IconButton
              size="small"
              color={params.row.is_active ? "error" : "success"}
              onClick={() => {
                setSelectedUser(params.row)
                setDeactivateDialogOpen(true)
              }}
            >
              <Block fontSize="small" />
            </IconButton>
          </Tooltip>
        </Box>
      ),
    },
  ]

  return (
    <Box sx={{ p: 3 }}>
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
      >
        <Box sx={{ mb: 4 }}>
          <Typography variant="h4" component="h1" gutterBottom>
            User Management
          </Typography>
          <Typography variant="body1" color="text.secondary">
            Manage user accounts, approvals, and permissions.
          </Typography>
        </Box>

        {error && (
          <Alert severity="error" sx={{ mb: 3 }}>
            {error}
          </Alert>
        )}

        <Card sx={{ mb: 4 }}>
          <CardContent>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
              <Typography variant="h6">
                Users
              </Typography>
              <Button
                variant="contained"
                startIcon={<PersonAdd />}
                onClick={() => {
                  // This would open a user creation dialog in a real app
                  toast({
                    title: "Feature Not Implemented",
                    description: "User creation functionality would be implemented here.",
                    variant: "default",
                  })
                }}
              >
                Add User
              </Button>
            </Box>
            
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  placeholder="Search by name, email, CRN, or student ID"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  InputProps={{
                    startAdornment: (
                      <InputAdornment position="start">
                        <Search />
                      </InputAdornment>
                    ),
                  }}
                />
              </Grid>
              <Grid item xs={12} md={3}>
                <TextField
                  select
                  fullWidth
                  label="Role"
                  value={roleFilter}
                  onChange={(e) => setRoleFilter(e.target.value)}
                >
                  <MenuItem value="">All Roles</MenuItem>
                  <MenuItem value="STUDENT">Student</MenuItem>
                  <MenuItem value="ADMIN">Admin</MenuItem>
                  <MenuItem value="SUPER_ADMIN">Super Admin</MenuItem>
                </TextField>
              </Grid>
              <Grid item xs={12} md={3}>
                <TextField
                  select
                  fullWidth
                  label="Status"
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                >
                  <MenuItem value="">All Statuses</MenuItem>
                  <MenuItem value="APPROVED">Approved</MenuItem>
                  <MenuItem value="PENDING">Pending Approval</MenuItem>
                  <MenuItem value="ACTIVE">Active</MenuItem>
                  <MenuItem value="INACTIVE">Inactive</MenuItem>
                </TextField>
              </Grid>
            </Grid>
            
            <Box sx={{ height: 600, width: '100%' }}>
              {isLoading ? (
                <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%' }}>
                  <LoadingSpinner size="lg" />
                </Box>
              ) : (
                <DataGrid
                  rows={filteredUsers}
                  columns={columns}
                  initialState={{
                    pagination: {
                      paginationModel: { page: 0, pageSize: 10 },
                    },
                    sorting: {
                      sortModel: [{ field: 'created_at', sort: 'desc' }],
                    },
                  }}
                  pageSizeOptions={[10, 25, 50]}
                  checkboxSelection
                  disableRowSelectionOnClick
                  components={{
                    Toolbar: GridToolbar,
                  }}
                />
              )}
            </Box>
          </CardContent>
        </Card>

        {/* View User Dialog */}
        <Dialog
          open={viewDialogOpen}
          onClose={() => setViewDialogOpen(false)}
          maxWidth="md"
          fullWidth
        >
          <DialogTitle>User Details</DialogTitle>
          <DialogContent dividers>
            {selectedUser && (
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle1" gutterBottom>
                    Personal Information
                  </Typography>
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="body2" color="text.secondary">
                      Full Name
                    </Typography>
                    <Typography variant="body1">
                      {selectedUser.full_name}
                    </Typography>
                  </Box>
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="body2" color="text.secondary">
                      Email
                    </Typography>
                    <Typography variant="body1">
                      {selectedUser.email}
                    </Typography>
                  </Box>
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="body2" color="text.secondary">
                      Phone Number
                    </Typography>
                    <Typography variant="body1">
                      {selectedUser.phone_number || 'Not specified'}
                    </Typography>
                  </Box>
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="body2" color="text.secondary">
                      Date of Birth
                    </Typography>
                    <Typography variant="body1">
                      {selectedUser.date_of_birth ? formatDate(selectedUser.date_of_birth) : 'Not specified'}
                    </Typography>
                  </Box>
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="body2" color="text.secondary">
                      Gender
                    </Typography>
                    <Typography variant="body1">
                      {selectedUser.gender === 'M' ? 'Male' :
                       selectedUser.gender === 'F' ? 'Female' :
                       selectedUser.gender === 'O' ? 'Other' :
                       'Not specified'}
                    </Typography>
                  </Box>
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="body2" color="text.secondary">
                      City
                    </Typography>
                    <Typography variant="body1">
                      {selectedUser.city || 'Not specified'}
                    </Typography>
                  </Box>
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="body2" color="text.secondary">
                      Address
                    </Typography>
                    <Typography variant="body1">
                      {selectedUser.address || 'Not specified'}
                    </Typography>
                  </Box>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle1" gutterBottom>
                    Account Information
                  </Typography>
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="body2" color="text.secondary">
                      Username
                    </Typography>
                    <Typography variant="body1">
                      {selectedUser.username}
                    </Typography>
                  </Box>
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="body2" color="text.secondary">
                      CRN
                    </Typography>
                    <Typography variant="body1">
                      {selectedUser.crn}
                    </Typography>
                  </Box>
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="body2" color="text.secondary">
                      Student ID
                    </Typography>
                    <Typography variant="body1">
                      {selectedUser.student_id}
                    </Typography>
                  </Box>
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="body2" color="text.secondary">
                      Role
                    </Typography>
                    <Typography variant="body1">
                      <Chip
                        label={selectedUser.role.replace('_', ' ')}
                        size="small"
                        className={getRoleColor(selectedUser.role)}
                      />
                    </Typography>
                  </Box>
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="body2" color="text.secondary">
                      Status
                    </Typography>
                    <Typography variant="body1">
                      <Box sx={{ display: 'flex', gap: 1 }}>
                        <Chip
                          label={selectedUser.is_approved ? 'Approved' : 'Pending Approval'}
                          size="small"
                          color={selectedUser.is_approved ? 'success' : 'warning'}
                          variant="outlined"
                        />
                        <Chip
                          label={selectedUser.is_active ? 'Active' : 'Inactive'}
                          size="small"
                          color={selectedUser.is_active ? 'success' : 'error'}
                          variant="outlined"
                        />
                      </Box>
                    </Typography>
                  </Box>
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="body2" color="text.secondary">
                      Registration Date
                    </Typography>
                    <Typography variant="body1">
                      {formatDate(selectedUser.created_at)}
                    </Typography>
                  </Box>
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="body2" color="text.secondary">
                      Last Login
                    </Typography>
                    <Typography variant="body1">
                      {selectedUser.last_login ? formatDate(selectedUser.last_login) : 'Never'}
                    </Typography>
                  </Box>
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="body2" color="text.secondary">
                      Login Count
                    </Typography>
                    <Typography variant="body1">
                      {selectedUser.login_count}
                    </Typography>
                  </Box>
                </Grid>
                {selectedUser.bio && (
                  <Grid item xs={12}>
                    <Typography variant="subtitle1" gutterBottom>
                      Bio
                    </Typography>
                    <Typography variant="body1">
                      {selectedUser.bio}
                    </Typography>
                  </Grid>
                )}
              </Grid>
            )}
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setViewDialogOpen(false)}>
              Close
            </Button>
            {selectedUser && !selectedUser.is_approved && (
              <Button
                variant="contained"
                color="success"
                onClick={() => {
                  setViewDialogOpen(false)
                  setApproveDialogOpen(true)
                }}
              >
                Approve
              </Button>
            )}
            {selectedUser && (
              <Button
                variant="contained"
                color={selectedUser.is_active ? 'error' : 'success'}
                onClick={() => {
                  setViewDialogOpen(false)
                  setDeactivateDialogOpen(true)
                }}
              >
                {selectedUser.is_active ? 'Deactivate' : 'Activate'}
              </Button>
            )}
          </DialogActions>
        </Dialog>

        {/* Approve User Dialog */}
        <Dialog
          open={approveDialogOpen}
          onClose={() => !isProcessing && setApproveDialogOpen(false)}
          maxWidth="xs"
          fullWidth
        >
          <DialogTitle>Approve User</DialogTitle>
          <DialogContent>
            <Typography variant="body1">
              Are you sure you want to approve {selectedUser?.full_name}?
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
              This will grant the user access to the system.
            </Typography>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setApproveDialogOpen(false)} disabled={isProcessing}>
              Cancel
            </Button>
            <Button
              variant="contained"
              color="success"
              onClick={handleApproveUser}
              disabled={isProcessing}
              startIcon={isProcessing ? <LoadingSpinner size="sm" /> : <CheckCircle />}
            >
              Approve
            </Button>
          </DialogActions>
        </Dialog>

        {/* Reject User Dialog */}
        <Dialog
          open={rejectDialogOpen}
          onClose={() => !isProcessing && setRejectDialogOpen(false)}
          maxWidth="xs"
          fullWidth
        >
          <DialogTitle>Reject User</DialogTitle>
          <DialogContent>
            <Typography variant="body1">
              Are you sure you want to reject {selectedUser?.full_name}?
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
              This will deny the user access to the system.
            </Typography>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setRejectDialogOpen(false)} disabled={isProcessing}>
              Cancel
            </Button>
            <Button
              variant="contained"
              color="error"
              onClick={handleRejectUser}
              disabled={isProcessing}
              startIcon={isProcessing ? <LoadingSpinner size="sm" /> : <Cancel />}
            >
              Reject
            </Button>
          </DialogActions>
        </Dialog>

        {/* Deactivate/Activate User Dialog */}
        <Dialog
          open={deactivateDialogOpen}
          onClose={() => !isProcessing && setDeactivateDialogOpen(false)}
          maxWidth="xs"
          fullWidth
        >
          <DialogTitle>
            {selectedUser?.is_active ? 'Deactivate User' : 'Activate User'}
          </DialogTitle>
          <DialogContent>
            <Typography variant="body1">
              Are you sure you want to {selectedUser?.is_active ? 'deactivate' : 'activate'} {selectedUser?.full_name}?
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
              {selectedUser?.is_active
                ? 'This will prevent the user from accessing the system.'
                : 'This will allow the user to access the system again.'}
            </Typography>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setDeactivateDialogOpen(false)} disabled={isProcessing}>
              Cancel
            </Button>
            <Button
              variant="contained"
              color={selectedUser?.is_active ? 'error' : 'success'}
              onClick={handleDeactivateUser}
              disabled={isProcessing}
              startIcon={isProcessing ? <LoadingSpinner size="sm" /> : <Block />}
            >
              {selectedUser?.is_active ? 'Deactivate' : 'Activate'}
            </Button>
          </DialogActions>
        </Dialog>
      </motion.div>
    </Box>
  )
}