import axios, { AxiosError, AxiosResponse } from 'axios'
import { useAuthStore } from '../stores/authStore'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1'

// Create axios instance
export const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Request interceptor to add auth token
api.interceptors.request.use(
  (config) => {
    const token = useAuthStore.getState().token
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Response interceptor to handle errors
api.interceptors.response.use(
  (response: AxiosResponse) => response,
  (error: AxiosError) => {
    console.error('API Error:', error.response?.data || error.message)
    
    if (error.response?.status === 401) {
      // Token expired or invalid
      useAuthStore.getState().logout()
      window.location.href = '/auth/login'
    }
    return Promise.reject(error)
  }
)

// API response types
export interface ApiResponse<T = any> {
  data: T
  message?: string
  status: number
}

export interface PaginatedResponse<T = any> {
  count: number
  next: string | null
  previous: string | null
  results: T[]
}

export interface ApiError {
  message: string
  errors?: Record<string, string[]>
  status: number
  code?: string
}

// Helper function to handle API errors
export const handleApiError = (error: any): ApiError => {
  console.error('Handling API error:', error)
  
  if (error.response?.data) {
    // Check for non_field_errors first (Django REST Framework format)
    if (error.response.data.non_field_errors && Array.isArray(error.response.data.non_field_errors) && error.response.data.non_field_errors.length > 0) {
      return {
        message: error.response.data.non_field_errors[0],
        errors: error.response.data,
        status: error.response.status,
        code: error.response.data.code
      }
    }
    
    // Check for detail field (another common DRF format)
    if (error.response.data.detail) {
      return {
        message: error.response.data.detail,
        errors: error.response.data,
        status: error.response.status,
        code: error.response.data.code
      }
    }
    
    // Then check for message or detail
    return {
      message: error.response.data.message || error.response.data.detail || 'An error occurred',
      errors: error.response.data,
      status: error.response.status,
      code: error.response.data.code
    }
  }
  
  if (error.message) {
    return {
      message: error.message,
      status: 500,
    }
  }
  
  return {
    message: 'Network error occurred',
    status: 0,
  }
}

// Generic API functions
export const apiGet = async <T>(url: string, params?: any): Promise<T> => {
  console.log(`Making GET request to ${url} with params:`, params)
  const response = await api.get(url, { params })
  console.log(`Response from ${url}:`, response.data)
  return response.data
}

export const apiPost = async <T>(url: string, data?: any): Promise<T> => {
  console.log(`Making POST request to ${url} with data:`, data)
  const response = await api.post(url, data)
  console.log(`Response from ${url}:`, response.data)
  return response.data
}

export const apiPut = async <T>(url: string, data?: any): Promise<T> => {
  const response = await api.put(url, data)
  return response.data
}

export const apiPatch = async <T>(url: string, data?: any): Promise<T> => {
  const response = await api.patch(url, data)
  return response.data
}

export const apiDelete = async <T>(url: string): Promise<T> => {
  const response = await api.delete(url)
  return response.data
}

// File upload helper
export const apiUpload = async <T>(url: string, file: File, onProgress?: (progress: number) => void): Promise<T> => {
  const formData = new FormData()
  formData.append('file', file)
  
  const response = await api.post(url, formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
    onUploadProgress: (progressEvent) => {
      if (onProgress && progressEvent.total) {
        const progress = Math.round((progressEvent.loaded * 100) / progressEvent.total)
        onProgress(progress)
      }
    },
  })
  
  return response.data
}