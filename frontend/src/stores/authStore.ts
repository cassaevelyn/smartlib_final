import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import { User, LoginForm, RegisterForm } from '../types'
import { authService } from '../services/authService'

interface AuthState {
  user: User | null
  token: string | null
  isAuthenticated: boolean
  isLoading: boolean
  error: string | null
}

interface AuthActions {
  login: (credentials: LoginForm) => Promise<void>
  register: (data: RegisterForm) => Promise<void>
  logout: () => void
  clearError: () => void
  setLoading: (loading: boolean) => void
  updateUser: (user: Partial<User>) => void
}

export const useAuthStore = create<AuthState & AuthActions>()(
  persist(
    (set, get) => ({
      // State
      user: null,
      token: null,
      isAuthenticated: false,
      isLoading: false,
      error: null,

      // Actions
      login: async (credentials: LoginForm) => {
        try {
          set({ isLoading: true, error: null })
          
          const response = await authService.login(credentials)
          
          set({
            user: response.user,
            token: response.access_token,
            isAuthenticated: true,
            isLoading: false,
            error: null,
          })
        } catch (error: any) {
          set({
            error: error.message || 'Login failed. Please check your credentials.',
            isLoading: false,
            isAuthenticated: false,
          })
          throw error // Re-throw the error with all details
        }
      },

      register: async (data: RegisterForm) => {
        try {
          set({ isLoading: true, error: null })
          
          await authService.register(data)
          
          set({
            isLoading: false,
            error: null,
          })
        } catch (error: any) {
          set({
            error: error.message || 'Registration failed. Please try again.',
            isLoading: false,
          })
          throw error
        }
      },

      logout: () => {
        // Call the logout API
        authService.logout().catch(console.error)
        
        set({
          user: null,
          token: null,
          isAuthenticated: false,
          error: null,
        })
      },

      clearError: () => {
        set({ error: null })
      },

      setLoading: (loading: boolean) => {
        set({ isLoading: loading })
      },

      updateUser: (userData: Partial<User>) => {
        const currentUser = get().user
        if (currentUser) {
          set({
            user: { ...currentUser, ...userData }
          })
        }
      },
    }),
    {
      name: 'auth-storage',
      partialize: (state) => ({
        user: state.user,
        token: state.token,
        isAuthenticated: state.isAuthenticated,
      }),
    }
  )
)