import { apiPost, apiGet, apiPatch, handleApiError, PaginatedResponse } from '../lib/api'
import { LoginForm, RegisterForm, User, UserProfile, UserLibraryAccess } from '../types'

export interface LoginResponse {
  access_token: string
  refresh_token: string
  user: User
  session_id: string
}

export interface RegisterResponse {
  message: string
  user_id: string
}

export interface OtpResponse {
  message: string
  attempts_remaining: number
  cooldown_minutes: number
  user_id: string
}

export interface VerifyOtpResponse {
  message: string
  user_id: string
}

export interface VerifyEmailResponse {
  message: string
  status: string
  error?: string
  reason?: string
}

export const authService = {
  login: async (credentials: LoginForm): Promise<LoginResponse> => {
    try {
      return await apiPost<LoginResponse>('/auth/login/', credentials)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  register: async (data: RegisterForm): Promise<RegisterResponse> => {
    try {
      return await apiPost<RegisterResponse>('/auth/register/', data)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  logout: async (): Promise<void> => {
    try {
      await apiPost('/auth/logout/')
    } catch (error) {
      throw handleApiError(error)
    }
  },

  forgotPassword: async (email: string): Promise<{ message: string }> => {
    try {
      return await apiPost<{ message: string }>('/auth/password/reset/', { email })
    } catch (error) {
      throw handleApiError(error)
    }
  },

  resetPassword: async (token: string, password: string): Promise<{ message: string }> => {
    try {
      return await apiPost<{ message: string }>('/auth/password/reset/confirm/', {
        token,
        new_password: password,
        new_password_confirm: password,
      })
    } catch (error) {
      throw handleApiError(error)
    }
  },

  getProfile: async (): Promise<User> => {
    try {
      return await apiGet<User>('/auth/profile/')
    } catch (error) {
      throw handleApiError(error)
    }
  },

  getUserProfile: async (): Promise<UserProfile> => {
    try {
      return await apiGet<UserProfile>('/auth/profile/detail/')
    } catch (error) {
      throw handleApiError(error)
    }
  },

  updateProfile: async (data: Partial<User>): Promise<User> => {
    try {
      return await apiPatch<User>('/auth/profile/', data)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  updateUserProfile: async (data: Partial<UserProfile>): Promise<UserProfile> => {
    try {
      return await apiPatch<UserProfile>('/auth/profile/detail/', data)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  getUserActivities: async (): Promise<any[]> => {
    try {
      const response = await apiGet<{ results: any[] }>('/auth/activities/')
      return response.results
    } catch (error) {
      throw handleApiError(error)
    }
  },

  changePassword: async (oldPassword: string, newPassword: string): Promise<{ message: string }> => {
    try {
      return await apiPost<{ message: string }>('/auth/password/change/', {
        old_password: oldPassword,
        new_password: newPassword,
        new_password_confirm: newPassword,
      })
    } catch (error) {
      throw handleApiError(error)
    }
  },

  sendOtp: async (email: string): Promise<OtpResponse> => {
    try {
      return await apiPost<OtpResponse>('/auth/send-otp/', { email })
    } catch (error) {
      throw handleApiError(error)
    }
  },

  verifyOtp: async (email: string, otp: string): Promise<VerifyOtpResponse> => {
    try {
      return await apiPost<VerifyOtpResponse>('/auth/verify-otp/', { email, otp })
    } catch (error) {
      throw handleApiError(error)
    }
  },

  verifyEmail: async (token: string): Promise<VerifyEmailResponse> => {
    try {
      return await apiGet<VerifyEmailResponse>(`/auth/verify-email/${token}/`)
    } catch (error) {
      const apiError = handleApiError(error)
      return {
        message: apiError.message,
        status: 'failed',
        error: apiError.message,
        reason: apiError.code || 'unknown'
      }
    }
  },

  applyForLibraryAccess: async (libraryId: string, notes?: string): Promise<any> => {
    try {
      return await apiPost('/auth/apply-library-access/', {
        library: libraryId,
        notes: notes || ''
      })
    } catch (error) {
      throw handleApiError(error)
    }
  },

  getUserLibraryAccess: async (): Promise<PaginatedResponse<UserLibraryAccess>> => {
    try {
      return await apiGet<PaginatedResponse<UserLibraryAccess>>('/auth/my-library-access/')
    } catch (error) {
      throw handleApiError(error)
    }
  }
}