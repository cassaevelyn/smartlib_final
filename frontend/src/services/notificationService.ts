import { apiGet, apiPost, apiPatch, apiDelete, handleApiError, PaginatedResponse } from '../lib/api'
import { Notification } from '../types'

export const notificationService = {
  // Get all notifications for the current user
  getNotifications: async (params?: any): Promise<PaginatedResponse<Notification>> => {
    try {
      return await apiGet<PaginatedResponse<Notification>>('/notifications/', params)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get unread notifications count
  getUnreadCount: async (): Promise<{ count: number }> => {
    try {
      return await apiGet<{ count: number }>('/notifications/unread-count/')
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Mark a notification as read
  markAsRead: async (id: string): Promise<Notification> => {
    try {
      return await apiPost<Notification>(`/notifications/${id}/read/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Mark all notifications as read
  markAllAsRead: async (): Promise<{ message: string }> => {
    try {
      return await apiPost<{ message: string }>('/notifications/mark-all-read/')
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Delete a notification
  deleteNotification: async (id: string): Promise<void> => {
    try {
      await apiDelete(`/notifications/${id}/`)
    } catch (error) {
      throw handleApiError(error)
    }
  }
}