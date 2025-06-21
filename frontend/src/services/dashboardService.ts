import { apiGet, handleApiError } from '../lib/api'
import { DashboardStats, RecentActivity } from '../types'

export const dashboardService = {
  getDashboardStats: async (): Promise<DashboardStats> => {
    try {
      return await apiGet<DashboardStats>('/dashboard/stats/')
    } catch (error) {
      throw handleApiError(error)
    }
  },

  getRecentActivities: async (): Promise<RecentActivity[]> => {
    try {
      return await apiGet<RecentActivity[]>('/dashboard/activities/')
    } catch (error) {
      throw handleApiError(error)
    }
  },

  getSeatBookings: async () => {
    try {
      return await apiGet('/seats/bookings/')
    } catch (error) {
      throw handleApiError(error)
    }
  },

  getBookReservations: async () => {
    try {
      return await apiGet('/books/reservations/')
    } catch (error) {
      throw handleApiError(error)
    }
  },

  getEventRegistrations: async () => {
    try {
      return await apiGet('/events/registrations/')
    } catch (error) {
      throw handleApiError(error)
    }
  },

  getBookSummary: async () => {
    try {
      return await apiGet('/books/summary/')
    } catch (error) {
      throw handleApiError(error)
    }
  },

  getEventSummary: async () => {
    try {
      return await apiGet('/events/summary/')
    } catch (error) {
      throw handleApiError(error)
    }
  },

  getBookingSummary: async () => {
    try {
      return await apiGet('/seats/booking-summary/')
    } catch (error) {
      throw handleApiError(error)
    }
  },
}