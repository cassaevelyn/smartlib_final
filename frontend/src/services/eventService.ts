import { apiGet, apiPost, apiDelete, handleApiError, PaginatedResponse } from '../lib/api'
import { Event, EventDetail, EventRegistration, EventFeedback, EventSearchFilters, EventSpeaker } from '../types'

export const eventService = {
  // Get all events with optional pagination and filters
  getEvents: async (params?: any): Promise<PaginatedResponse<Event>> => {
    try {
      return await apiGet<PaginatedResponse<Event>>('/events/', params)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get a specific event by ID
  getEvent: async (id: string): Promise<EventDetail> => {
    try {
      return await apiGet<EventDetail>(`/events/${id}/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Search events with advanced filters
  searchEvents: async (filters: EventSearchFilters): Promise<PaginatedResponse<Event>> => {
    try {
      return await apiPost<PaginatedResponse<Event>>('/events/search/', filters)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get event categories
  getCategories: async (): Promise<PaginatedResponse<any>> => {
    try {
      return await apiGet<PaginatedResponse<any>>('/events/categories/')
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get event speakers
  getSpeakers: async (): Promise<PaginatedResponse<EventSpeaker>> => {
    try {
      return await apiGet<PaginatedResponse<EventSpeaker>>('/events/speakers/')
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get all registrations for the current user
  getRegistrations: async (params?: any): Promise<PaginatedResponse<EventRegistration>> => {
    try {
      return await apiGet<PaginatedResponse<EventRegistration>>('/events/registrations/', params)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get a specific registration by ID
  getRegistration: async (id: string): Promise<EventRegistration> => {
    try {
      return await apiGet<EventRegistration>(`/events/registrations/${id}/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Create a new registration
  createRegistration: async (registrationData: any): Promise<EventRegistration> => {
    try {
      return await apiPost<EventRegistration>('/events/registrations/', registrationData)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Cancel a registration
  cancelRegistration: async (id: string): Promise<any> => {
    try {
      return await apiDelete(`/events/registrations/${id}/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Generate QR code for event check-in
  generateQRCode: async (registrationId: string): Promise<any> => {
    try {
      return await apiPost(`/events/registrations/${registrationId}/qr-code/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Check in to an event
  checkIn: async (data: any): Promise<any> => {
    try {
      return await apiPost('/events/check-in/', data)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Check out from an event
  checkOut: async (data: any): Promise<any> => {
    try {
      return await apiPost('/events/check-out/', data)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get feedback for a specific event
  getEventFeedback: async (eventId: string): Promise<PaginatedResponse<EventFeedback>> => {
    try {
      return await apiGet<PaginatedResponse<EventFeedback>>(`/events/${eventId}/feedback/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Submit feedback for an event
  submitEventFeedback: async (eventId: string, feedbackData: any): Promise<EventFeedback> => {
    try {
      return await apiPost<EventFeedback>(`/events/${eventId}/feedback/`, feedbackData)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get resources for a specific event
  getEventResources: async (eventId: string): Promise<PaginatedResponse<any>> => {
    try {
      return await apiGet<PaginatedResponse<any>>(`/events/${eventId}/resources/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get user event summary
  getEventSummary: async (): Promise<any> => {
    try {
      return await apiGet('/events/summary/')
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Join event waitlist
  joinWaitlist: async (eventId: string): Promise<any> => {
    try {
      return await apiPost('/events/waitlist/', { event: eventId })
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get event series
  getEventSeries: async (): Promise<PaginatedResponse<any>> => {
    try {
      return await apiGet<PaginatedResponse<any>>('/events/series/')
    } catch (error) {
      throw handleApiError(error)
    }
  }
}