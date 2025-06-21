import { type ClassValue, clsx } from "clsx"
import { twMerge } from "tailwind-merge"
import { format, formatDistanceToNow, isToday, isYesterday, parseISO } from 'date-fns'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

// Date formatting utilities
export const formatDate = (date: string | Date, formatStr = 'MMM dd, yyyy') => {
  const dateObj = typeof date === 'string' ? parseISO(date) : date
  return format(dateObj, formatStr)
}

export const formatDateTime = (date: string | Date) => {
  const dateObj = typeof date === 'string' ? parseISO(date) : date
  return format(dateObj, 'MMM dd, yyyy HH:mm')
}

export const formatTime = (date: string | Date) => {
  const dateObj = typeof date === 'string' ? parseISO(date) : date
  return format(dateObj, 'HH:mm')
}

export const formatRelativeTime = (date: string | Date) => {
  const dateObj = typeof date === 'string' ? parseISO(date) : date
  
  if (isToday(dateObj)) {
    return `Today at ${format(dateObj, 'HH:mm')}`
  }
  
  if (isYesterday(dateObj)) {
    return `Yesterday at ${format(dateObj, 'HH:mm')}`
  }
  
  return formatDistanceToNow(dateObj, { addSuffix: true })
}

// String utilities
export const truncateText = (text: string, maxLength: number) => {
  if (text.length <= maxLength) return text
  return text.slice(0, maxLength) + '...'
}

export const capitalizeFirst = (str: string) => {
  return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase()
}

export const formatCurrency = (amount: number, currency = 'PKR') => {
  return new Intl.NumberFormat('en-PK', {
    style: 'currency',
    currency,
  }).format(amount)
}

// Number utilities
export const formatNumber = (num: number) => {
  return new Intl.NumberFormat().format(num)
}

export const formatPercentage = (value: number, decimals = 1) => {
  return `${value.toFixed(decimals)}%`
}

// Validation utilities
export const isValidEmail = (email: string) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  return emailRegex.test(email)
}

export const isValidPhone = (phone: string) => {
  const phoneRegex = /^\+?[\d\s-()]+$/
  return phoneRegex.test(phone) && phone.replace(/\D/g, '').length >= 10
}

export const isValidCRN = (crn: string) => {
  const crnRegex = /^ICAP-CA-\d{4}-\d{4}$/
  return crnRegex.test(crn)
}

// File utilities
export const formatFileSize = (bytes: number) => {
  if (bytes === 0) return '0 Bytes'
  
  const k = 1024
  const sizes = ['Bytes', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

export const getFileExtension = (filename: string) => {
  return filename.slice((filename.lastIndexOf('.') - 1 >>> 0) + 2)
}

// Color utilities
export const getStatusColor = (status: string) => {
  const statusColors: Record<string, string> = {
    // Seat booking statuses
    PENDING: 'text-yellow-600 bg-yellow-50',
    CONFIRMED: 'text-blue-600 bg-blue-50',
    CHECKED_IN: 'text-green-600 bg-green-50',
    COMPLETED: 'text-emerald-600 bg-emerald-50',
    CANCELLED: 'text-red-600 bg-red-50',
    NO_SHOW: 'text-red-700 bg-red-100',
    EXPIRED: 'text-gray-600 bg-gray-50',
    
    // Book reservation statuses
    RESERVED: 'text-blue-600 bg-blue-50',
    READY_FOR_PICKUP: 'text-green-600 bg-green-50',
    RETURNED: 'text-emerald-600 bg-emerald-50',
    OVERDUE: 'text-red-600 bg-red-50',
    
    // Event registration statuses
    ATTENDED: 'text-green-600 bg-green-50',
    WAITLISTED: 'text-purple-600 bg-purple-50',
    
    // General statuses
    ACTIVE: 'text-green-600 bg-green-50',
    INACTIVE: 'text-gray-600 bg-gray-50',
    AVAILABLE: 'text-green-600 bg-green-50',
    OCCUPIED: 'text-orange-600 bg-orange-50',
    MAINTENANCE: 'text-red-600 bg-red-50',
    OUT_OF_ORDER: 'text-red-700 bg-red-100',
  }
  
  return statusColors[status] || 'text-gray-600 bg-gray-50'
}

export const getRoleColor = (role: string) => {
  const roleColors: Record<string, string> = {
    STUDENT: 'text-blue-600 bg-blue-50',
    ADMIN: 'text-purple-600 bg-purple-50',
    SUPER_ADMIN: 'text-red-600 bg-red-50',
  }
  
  return roleColors[role] || 'text-gray-600 bg-gray-50'
}

// Array utilities
export const groupBy = <T>(array: T[], key: keyof T) => {
  return array.reduce((groups, item) => {
    const group = item[key] as string
    groups[group] = groups[group] || []
    groups[group].push(item)
    return groups
  }, {} as Record<string, T[]>)
}

export const sortBy = <T>(array: T[], key: keyof T, direction: 'asc' | 'desc' = 'asc') => {
  return [...array].sort((a, b) => {
    const aVal = a[key]
    const bVal = b[key]
    
    if (aVal < bVal) return direction === 'asc' ? -1 : 1
    if (aVal > bVal) return direction === 'asc' ? 1 : -1
    return 0
  })
}

// Local storage utilities
export const getStorageItem = (key: string, defaultValue: any = null) => {
  try {
    const item = localStorage.getItem(key)
    return item ? JSON.parse(item) : defaultValue
  } catch {
    return defaultValue
  }
}

export const setStorageItem = (key: string, value: any) => {
  try {
    localStorage.setItem(key, JSON.stringify(value))
  } catch (error) {
    console.error('Error saving to localStorage:', error)
  }
}

export const removeStorageItem = (key: string) => {
  try {
    localStorage.removeItem(key)
  } catch (error) {
    console.error('Error removing from localStorage:', error)
  }
}

// Debounce utility
export const debounce = <T extends (...args: any[]) => any>(
  func: T,
  wait: number
): ((...args: Parameters<T>) => void) => {
  let timeout: NodeJS.Timeout
  
  return (...args: Parameters<T>) => {
    clearTimeout(timeout)
    timeout = setTimeout(() => func(...args), wait)
  }
}

// Generate random ID
export const generateId = () => {
  return Math.random().toString(36).substr(2, 9)
}

// Deep clone utility
export const deepClone = <T>(obj: T): T => {
  return JSON.parse(JSON.stringify(obj))
}

// Check if object is empty
export const isEmpty = (obj: any): boolean => {
  if (obj == null) return true
  if (Array.isArray(obj) || typeof obj === 'string') return obj.length === 0
  if (typeof obj === 'object') return Object.keys(obj).length === 0
  return false
}