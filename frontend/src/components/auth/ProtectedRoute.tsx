// frontend/src/components/auth/ProtectedRoute.tsx
import { Navigate, useLocation } from 'react-router-dom'
import { useAuthStore } from '../../stores/authStore'
import { LoadingSpinner } from '../ui/loading-spinner'

interface ProtectedRouteProps {
  children: React.ReactNode
  requiredRole?: 'STUDENT' | 'ADMIN' | 'SUPER_ADMIN'
}

export function ProtectedRoute({ children, requiredRole }: ProtectedRouteProps) {
  const { isAuthenticated, isLoading, user } = useAuthStore()
  const location = useLocation()

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  if (!isAuthenticated) {
    return <Navigate to="/auth/login" state={{ from: location }} replace />
  }

  // Check if user is active and approved - if not, redirect to library application page
  // Skip this check for the library application page itself to avoid infinite redirects
  if ((!user?.is_active || !user?.is_approved) && !location.pathname.includes('/apply-for-library')) {
    return <Navigate to="/apply-for-library" replace />
  }

  // Check if user has sufficient permissions for the route
  if (requiredRole) {
    // Role hierarchy
    const roleHierarchy = {
      'STUDENT': 0,
      'ADMIN': 1,
      'SUPER_ADMIN': 2
    }

    const userLevel = roleHierarchy[user?.role || 'STUDENT']
    const requiredLevel = roleHierarchy[requiredRole]

    if (userLevel < requiredLevel) {
      // Redirect to dashboard if user doesn't have required role
      return <Navigate to="/" replace />
    }
  }

  // Check if trying to access superadmin routes without super admin privileges
  if (location.pathname.startsWith('/superadmin') && user?.role !== 'SUPER_ADMIN') {
    return <Navigate to="/" replace />
  }

  // Check if trying to access admin routes without admin privileges
  if (location.pathname.startsWith('/admin') && user?.role !== 'ADMIN' && user?.role !== 'SUPER_ADMIN') {
    return <Navigate to="/" replace />
  }

  
  return <>{children}</>
}
