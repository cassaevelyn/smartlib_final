import { apiGet, apiPost, handleApiError, PaginatedResponse } from '../lib/api'
import { Library, LibraryFloor, LibrarySection, LibraryReview } from '../types'

export const libraryService = {
  // Get all libraries with optional pagination and filters
  getLibraries: async (params?: any): Promise<PaginatedResponse<Library>> => {
    try {
      const response = await apiGet<PaginatedResponse<Library>>('/libraries/', params)
      console.log('Libraries API response:', response)
      return response
    } catch (error) {
      console.error('Error fetching libraries:', error)
      throw handleApiError(error)
    }
  },

  // Get a specific library by ID
  getLibrary: async (id: string): Promise<Library> => {
    try {
      return await apiGet<Library>(`/libraries/${id}/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Search libraries with advanced filters
  searchLibraries: async (filters: any): Promise<PaginatedResponse<Library>> => {
    try {
      return await apiPost<PaginatedResponse<Library>>('/libraries/search/', filters)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get floors for a specific library
  getLibraryFloors: async (libraryId: string): Promise<LibraryFloor[]> => {
    try {
      const response = await apiGet<PaginatedResponse<LibraryFloor>>(`/libraries/${libraryId}/floors/`)
      return response.results
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get sections for a specific floor
  getFloorSections: async (floorId: string): Promise<LibrarySection[]> => {
    try {
      const response = await apiGet<PaginatedResponse<LibrarySection>>(`/floors/${floorId}/sections/`)
      return response.results
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get reviews for a specific library
  getLibraryReviews: async (libraryId: string): Promise<PaginatedResponse<LibraryReview>> => {
    try {
      return await apiGet<PaginatedResponse<LibraryReview>>(`/libraries/${libraryId}/reviews/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Submit a review for a library
  submitLibraryReview: async (libraryId: string, reviewData: any): Promise<LibraryReview> => {
    try {
      return await apiPost<LibraryReview>(`/libraries/${libraryId}/reviews/`, reviewData)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get library notifications
  getLibraryNotifications: async (libraryId: string): Promise<any[]> => {
    try {
      const response = await apiGet<PaginatedResponse<any>>(`/libraries/${libraryId}/notifications/`)
      return response.results
    } catch (error) {
      throw handleApiError(error)
    }
  }
}