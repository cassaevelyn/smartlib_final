import { apiGet, apiPost, apiDelete, handleApiError, PaginatedResponse } from '../lib/api'
import { Seat, SeatBooking, SeatReview } from '../types'

export const seatService = {
  // Get all seats with optional pagination and filters
  getSeats: async (params?: any): Promise<PaginatedResponse<Seat>> => {
    try {
      return await apiGet<PaginatedResponse<Seat>>('/seats/', params)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get seats for a specific library
  getLibrarySeats: async (libraryId: string, params?: any): Promise<PaginatedResponse<Seat>> => {
    try {
      return await apiGet<PaginatedResponse<Seat>>(`/seats/library/${libraryId}/`, params)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get seats for a specific floor
  getFloorSeats: async (floorId: string, params?: any): Promise<PaginatedResponse<Seat>> => {
    try {
      return await apiGet<PaginatedResponse<Seat>>(`/seats/floor/${floorId}/`, params)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get seats for a specific section
  getSectionSeats: async (sectionId: string, params?: any): Promise<PaginatedResponse<Seat>> => {
    try {
      return await apiGet<PaginatedResponse<Seat>>(`/seats/section/${sectionId}/`, params)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get a specific seat by ID
  getSeat: async (id: string): Promise<Seat> => {
    try {
      return await apiGet<Seat>(`/seats/${id}/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Search seats with advanced filters
  searchSeats: async (filters: any): Promise<PaginatedResponse<Seat>> => {
    try {
      return await apiPost<PaginatedResponse<Seat>>('/seats/search/', filters)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Check seat availability
  checkSeatAvailability: async (seatId: string, date: string, startTime?: string, endTime?: string): Promise<any> => {
    try {
      return await apiPost('/seats/availability/check/', {
        seat_id: seatId,
        date,
        start_time: startTime,
        end_time: endTime
      })
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get all bookings for the current user
  getBookings: async (params?: any): Promise<PaginatedResponse<SeatBooking>> => {
    try {
      return await apiGet<PaginatedResponse<SeatBooking>>('/seats/bookings/', params)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get a specific booking by ID
  getBooking: async (id: string): Promise<SeatBooking> => {
    try {
      return await apiGet<SeatBooking>(`/seats/bookings/${id}/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Create a new booking
  createBooking: async (bookingData: any): Promise<SeatBooking> => {
    try {
      return await apiPost<SeatBooking>('/seats/bookings/', bookingData)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Cancel a booking
  cancelBooking: async (id: string): Promise<any> => {
    try {
      return await apiDelete(`/seats/bookings/${id}/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Generate QR code for check-in
  generateQRCode: async (bookingId: string): Promise<any> => {
    try {
      return await apiPost(`/seats/bookings/${bookingId}/qr-code/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Check in to a seat
  checkIn: async (data: any): Promise<any> => {
    try {
      return await apiPost('/seats/check-in/', data)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Check out from a seat
  checkOut: async (data: any): Promise<any> => {
    try {
      return await apiPost('/seats/check-out/', data)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get user booking summary
  getBookingSummary: async (): Promise<any> => {
    try {
      return await apiGet('/seats/bookings/summary/')
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get reviews for a specific seat
  getSeatReviews: async (seatId: string): Promise<PaginatedResponse<SeatReview>> => {
    try {
      return await apiGet<PaginatedResponse<SeatReview>>(`/seats/${seatId}/reviews/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Submit a review for a seat
  submitSeatReview: async (seatId: string, reviewData: any): Promise<SeatReview> => {
    try {
      return await apiPost<SeatReview>(`/seats/${seatId}/reviews/`, reviewData)
    } catch (error) {
      throw handleApiError(error)
    }
  }
}