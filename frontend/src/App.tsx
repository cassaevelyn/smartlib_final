// frontend/src/App.tsx
import { Routes, Route, Navigate } from 'react-router-dom'
import { useAuthStore } from './stores/authStore'
import { Layout } from './components/layout/Layout'
import { AuthLayout } from './components/layout/AuthLayout'
import { ProtectedRoute } from './components/auth/ProtectedRoute'
import { LoadingSpinner } from './components/ui/loading-spinner'

// Auth pages
import { LoginPage } from './pages/auth/LoginPage'
import { RegisterPage } from './pages/auth/RegisterPage'
import { ForgotPasswordPage } from './pages/auth/ForgotPasswordPage'
import { VerifyEmailPage } from './pages/auth/VerifyEmailPage'

// Dashboard
import { DashboardPage } from './pages/dashboard/DashboardPage'

// Libraries
import { LibrariesPage } from './pages/libraries/LibrariesPage'
import { LibraryDetailPage } from './pages/libraries/LibraryDetailPage'
import { LibraryApplicationPage } from './pages/libraries/LibraryApplicationPage'
import { MyLibrariesPage } from './pages/libraries/MyLibrariesPage'

// Seats
import { SeatsPage } from './pages/seats/SeatsPage'
import { SeatBookingPage } from './pages/seats/SeatBookingPage'
import { MyBookingsPage } from './pages/seats/MyBookingsPage'

// Books
import { BooksPage } from './pages/books/BooksPage'
import { BookDetailPage } from './pages/books/BookDetailPage'
import { MyReservationsPage } from './pages/books/MyReservationsPage'

// Events
import { EventsPage } from './pages/events/EventsPage'
import { EventDetailPage } from './pages/events/EventDetailPage'
import { MyEventsPage } from './pages/events/MyEventsPage'

// Profile
import { ProfilePage } from './pages/profile/ProfilePage'
import { SettingsPage } from './pages/profile/SettingsPage'
import { SubscriptionsPage } from './pages/profile/SubscriptionsPage'

// Notifications
import { NotificationsPage } from './pages/notifications/NotificationsPage'

// SuperAdmin
import { SuperAdminDashboardPage } from './pages/superadmin/AdminDashboardPage'
import { SuperAdminUsersPage } from './pages/superadmin/AdminUsersPage'
import { SuperAdminLibrariesPage } from './pages/superadmin/AdminLibrariesPage'
import { SuperAdminLibraryDetailPage } from './pages/superadmin/AdminLibraryDetailPage'
import { SuperAdminSeatsPage } from './pages/superadmin/AdminSeatsPage'
import { SuperAdminBooksPage } from './pages/superadmin/AdminBooksPage'
import { SuperAdminEventsPage } from './pages/superadmin/AdminEventsPage'
import { SuperAdminAnalyticsPage } from './pages/superadmin/AdminAnalyticsPage'
import { SuperAdminAdminsPage } from './pages/superadmin/AdminAdminsPage'
import { SuperAdminLibraryApplicationsPage } from './pages/superadmin/SuperAdminLibraryApplicationsPage'

// Admin
import { AdminManagedLibraryPage } from './pages/admin/AdminManagedLibraryPage'
import { AdminUsersPage } from './pages/admin/AdminUsersPage'

function App() {
  const { isLoading, isAuthenticated } = useAuthStore()

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  return (
    <Routes>
      {/* Auth routes */}
      <Route path="/auth" element={<AuthLayout />}>
        <Route path="login" element={<LoginPage />} />
        <Route path="register" element={<RegisterPage />} />
        <Route path="forgot-password" element={<ForgotPasswordPage />} />
        <Route path="verify-email/:token" element={<VerifyEmailPage />} />
        <Route path="verify-email/manual" element={<VerifyEmailPage />} />
        <Route path="verify-email/success" element={<VerifyEmailPage />} />
        <Route path="verify-email/failed" element={<VerifyEmailPage />} />
      </Route>

      {/* Library Application Route - outside of main layout */}
      <Route 
        path="/apply-for-library" 
        element={
          <ProtectedRoute>
            <LibraryApplicationPage />
          </ProtectedRoute>
        } 
      />

      {/* Protected routes */}
      <Route
        path="/*"
        element={
          <ProtectedRoute>
            <Layout>
              <Routes>
                {/* Dashboard */}
                <Route path="/" element={<DashboardPage />} />
                <Route path="/dashboard" element={<DashboardPage />} />

                {/* Libraries */}
                <Route path="/libraries" element={<LibrariesPage />} />
                <Route path="/libraries/:id" element={<LibraryDetailPage />} />
                <Route path="/my-libraries" element={<MyLibrariesPage />} />

                {/* Seats */}
                <Route path="/seats" element={<SeatsPage />} />
                <Route path="/seats/book" element={<SeatBookingPage />} />
                <Route path="/my-bookings" element={<MyBookingsPage />} />

                {/* Books */}
                <Route path="/books" element={<BooksPage />} />
                <Route path="/books/:id" element={<BookDetailPage />} />
                <Route path="/my-reservations" element={<MyReservationsPage />} />

                {/* Events */}
                <Route path="/events" element={<EventsPage />} />
                <Route path="/events/:id" element={<EventDetailPage />} />
                <Route path="/my-events" element={<MyEventsPage />} />

                {/* Profile */}
                <Route path="/profile" element={<ProfilePage />} />
                <Route path="/settings" element={<SettingsPage />} />
                <Route path="/subscriptions" element={<SubscriptionsPage />} />
                
                {/* Notifications */}
                <Route path="/notifications" element={<NotificationsPage />} />

                {/* Admin routes */}
                <Route path="/admin" element={<Navigate to="/" replace />} />
                <Route path="/admin/managed-library" element={
                  <ProtectedRoute requiredRole="ADMIN">
                    <AdminManagedLibraryPage />
                  </ProtectedRoute>
                } />
                <Route path="/admin/users" element={
                  <ProtectedRoute requiredRole="ADMIN">
                    <AdminUsersPage />
                  </ProtectedRoute>
                } />

                {/* SuperAdmin routes */}
                <Route path="/superadmin" element={<SuperAdminDashboardPage />} />
                <Route path="/superadmin/users" element={<SuperAdminUsersPage />} />
                <Route path="/superadmin/admins" element={<SuperAdminAdminsPage />} />
                <Route path="/superadmin/libraries" element={<SuperAdminLibrariesPage />} />
                <Route path="/superadmin/libraries/create" element={<SuperAdminLibraryDetailPage />} />
                <Route path="/superadmin/libraries/:id" element={<SuperAdminLibraryDetailPage />} />
                <Route path="/superadmin/library-applications" element={<SuperAdminLibraryApplicationsPage />} />
                <Route path="/superadmin/seats" element={<SuperAdminSeatsPage />} />
                <Route path="/superadmin/books" element={<SuperAdminBooksPage />} />
                <Route path="/superadmin/events" element={<SuperAdminEventsPage />} />
                <Route path="/superadmin/analytics" element={<SuperAdminAnalyticsPage />} />

                {/* Fallback */}
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </Layout>
          </ProtectedRoute>
        }
      />

      {/* Redirect to dashboard if authenticated, otherwise to login */}
      <Route
        path="*"
        element={
          <Navigate to={isAuthenticated ? "/" : "/auth/login"} replace />
        }
      />
    </Routes>
  )
}

export default App