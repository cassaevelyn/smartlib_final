import { apiGet, apiPost, apiPatch, apiDelete, handleApiError, PaginatedResponse } from '../lib/api'
import { User, Library, Seat, Book, Event, AdminProfile, UserLibraryAccess } from '../types'

export const adminService = {
  // User Management
  getUsers: async (params?: any): Promise<PaginatedResponse<User>> => {
    try {
      return await apiGet<PaginatedResponse<User>>('/auth/users/', params)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  getUserDetails: async (userId: string): Promise<User> => {
    try {
      return await apiGet<User>(`/auth/users/${userId}/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  createUser: async (userData: Partial<User>): Promise<User> => {
    try {
      return await apiPost<User>('/auth/users/', userData)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  updateUser: async (userId: string, data: Partial<User>): Promise<User> => {
    try {
      return await apiPatch<User>(`/auth/users/${userId}/`, data)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  deleteUser: async (userId: string): Promise<void> => {
    try {
      await apiDelete(`/auth/users/${userId}/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  approveUser: async (userId: string): Promise<{ message: string }> => {
    try {
      return await apiPost<{ message: string }>(`/auth/users/${userId}/approve/`, { action: 'approve' })
    } catch (error) {
      throw handleApiError(error)
    }
  },

  rejectUser: async (userId: string): Promise<{ message: string }> => {
    try {
      return await apiPost<{ message: string }>(`/auth/users/${userId}/approve/`, { action: 'reject' })
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Library Access Management
  getUserLibraryAccess: async (params?: any): Promise<PaginatedResponse<UserLibraryAccess>> => {
    try {
      return await apiGet<PaginatedResponse<UserLibraryAccess>>('/auth/library-access/', params)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  createUserLibraryAccess: async (data: any): Promise<UserLibraryAccess> => {
    try {
      return await apiPost<UserLibraryAccess>('/auth/library-access/', data)
    } catch (error) {
      throw handleApiError(error)
    }
  },
  
  approveLibraryAccess: async (accessId: string): Promise<UserLibraryAccess> => {
    try {
      return await apiPost<UserLibraryAccess>(`/auth/library-access/${accessId}/approve/`, {})
    } catch (error) {
      throw handleApiError(error)
    }
  },
  
  rejectLibraryAccess: async (accessId: string, reason?: string): Promise<UserLibraryAccess> => {
    try {
      return await apiPost<UserLibraryAccess>(`/auth/library-access/${accessId}/reject/`, {
        reason: reason || ''
      })
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Admin Profiles
  getAdminProfiles: async (params?: any): Promise<PaginatedResponse<AdminProfile>> => {
    try {
      return await apiGet<PaginatedResponse<AdminProfile>>('/auth/admin-profiles/', params)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  getAdminProfile: async (id: string): Promise<AdminProfile> => {
    try {
      return await apiGet<AdminProfile>(`/auth/admin-profiles/${id}/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  createAdminProfile: async (data: Partial<AdminProfile>): Promise<AdminProfile> => {
    try {
      return await apiPost<AdminProfile>('/auth/admin-profiles/create/', data)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  updateAdminProfile: async (id: string, data: Partial<AdminProfile>): Promise<AdminProfile> => {
    try {
      return await apiPatch<AdminProfile>(`/auth/admin-profiles/${id}/`, data)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  deleteAdminProfile: async (id: string): Promise<void> => {
    try {
      await apiDelete(`/auth/admin-profiles/${id}/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  getUsersForAdminAssignment: async (): Promise<PaginatedResponse<User>> => {
    try {
      return await apiGet<PaginatedResponse<User>>('/auth/eligible-admin-users/')
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Library Management
  getAdminLibraries: async (params?: any): Promise<PaginatedResponse<Library>> => {
    try {
      return await apiGet<PaginatedResponse<Library>>('/libraries/admin/manage/', params)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  getLibraryDetails: async (libraryId: string): Promise<Library> => {
    try {
      return await apiGet<Library>(`/libraries/admin/${libraryId}/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  createLibrary: async (data: Partial<Library>): Promise<Library> => {
    try {
      return await apiPost<Library>('/libraries/admin/manage/', data)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  updateLibrary: async (libraryId: string, data: Partial<Library>): Promise<Library> => {
    try {
      return await apiPatch<Library>(`/libraries/admin/${libraryId}/`, data)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  deleteLibrary: async (libraryId: string): Promise<void> => {
    try {
      await apiDelete(`/libraries/admin/${libraryId}/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Library Floor Management
  getLibraryFloors: async (libraryId: string, params?: any): Promise<PaginatedResponse<any>> => {
    try {
      return await apiGet<PaginatedResponse<any>>(`/libraries/admin/${libraryId}/floors/`, params)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  getFloorDetails: async (floorId: string): Promise<any> => {
    try {
      return await apiGet<any>(`/libraries/admin/floors/${floorId}/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  createFloor: async (libraryId: string, data: any): Promise<any> => {
    try {
      return await apiPost<any>(`/libraries/admin/${libraryId}/floors/`, data)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  updateFloor: async (floorId: string, data: any): Promise<any> => {
    try {
      return await apiPatch<any>(`/libraries/admin/floors/${floorId}/`, data)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  deleteFloor: async (floorId: string): Promise<void> => {
    try {
      await apiDelete(`/libraries/admin/floors/${floorId}/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Library Section Management
  getFloorSections: async (floorId: string, params?: any): Promise<PaginatedResponse<any>> => {
    try {
      return await apiGet<PaginatedResponse<any>>(`/libraries/admin/floors/${floorId}/sections/`, params)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  getSectionDetails: async (sectionId: string): Promise<any> => {
    try {
      return await apiGet<any>(`/libraries/admin/sections/${sectionId}/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  createSection: async (floorId: string, data: any): Promise<any> => {
    try {
      return await apiPost<any>(`/libraries/admin/floors/${floorId}/sections/`, data)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  updateSection: async (sectionId: string, data: any): Promise<any> => {
    try {
      return await apiPatch<any>(`/libraries/admin/sections/${sectionId}/`, data)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  deleteSection: async (sectionId: string): Promise<void> => {
    try {
      await apiDelete(`/libraries/admin/sections/${sectionId}/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Library Amenity Management
  getLibraryAmenities: async (libraryId: string, params?: any): Promise<PaginatedResponse<any>> => {
    try {
      return await apiGet<PaginatedResponse<any>>(`/libraries/admin/${libraryId}/amenities/`, params)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  getAmenityDetails: async (amenityId: string): Promise<any> => {
    try {
      return await apiGet<any>(`/libraries/admin/amenities/${amenityId}/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  createAmenity: async (libraryId: string, data: any): Promise<any> => {
    try {
      return await apiPost<any>(`/libraries/admin/${libraryId}/amenities/`, data)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  updateAmenity: async (amenityId: string, data: any): Promise<any> => {
    try {
      return await apiPatch<any>(`/libraries/admin/amenities/${amenityId}/`, data)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  deleteAmenity: async (amenityId: string): Promise<void> => {
    try {
      await apiDelete(`/libraries/admin/amenities/${amenityId}/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Library Operating Hours Management
  getLibraryOperatingHours: async (libraryId: string, params?: any): Promise<PaginatedResponse<any>> => {
    try {
      return await apiGet<PaginatedResponse<any>>(`/libraries/admin/${libraryId}/operating-hours/`, params)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  getOperatingHoursDetails: async (hoursId: string): Promise<any> => {
    try {
      return await apiGet<any>(`/libraries/admin/operating-hours/${hoursId}/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  createOperatingHours: async (libraryId: string, data: any): Promise<any> => {
    try {
      return await apiPost<any>(`/libraries/admin/${libraryId}/operating-hours/`, data)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  updateOperatingHours: async (hoursId: string, data: any): Promise<any> => {
    try {
      return await apiPatch<any>(`/libraries/admin/operating-hours/${hoursId}/`, data)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  deleteOperatingHours: async (hoursId: string): Promise<void> => {
    try {
      await apiDelete(`/libraries/admin/operating-hours/${hoursId}/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Library Holiday Management
  getLibraryHolidays: async (libraryId: string, params?: any): Promise<PaginatedResponse<any>> => {
    try {
      return await apiGet<PaginatedResponse<any>>(`/libraries/admin/${libraryId}/holidays/`, params)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  getHolidayDetails: async (holidayId: string): Promise<any> => {
    try {
      return await apiGet<any>(`/libraries/admin/holidays/${holidayId}/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  createHoliday: async (libraryId: string, data: any): Promise<any> => {
    try {
      return await apiPost<any>(`/libraries/admin/${libraryId}/holidays/`, data)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  updateHoliday: async (holidayId: string, data: any): Promise<any> => {
    try {
      return await apiPatch<any>(`/libraries/admin/holidays/${holidayId}/`, data)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  deleteHoliday: async (holidayId: string): Promise<void> => {
    try {
      await apiDelete(`/libraries/admin/holidays/${holidayId}/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Library Configuration
  getLibraryConfiguration: async (libraryId: string): Promise<any> => {
    try {
      return await apiGet<any>(`/libraries/admin/${libraryId}/configuration/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  updateLibraryConfiguration: async (libraryId: string, data: any): Promise<any> => {
    try {
      return await apiPatch<any>(`/libraries/admin/${libraryId}/configuration/`, data)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Seat Management
  getAdminSeats: async (params?: any): Promise<PaginatedResponse<Seat>> => {
    try {
      return await apiGet<PaginatedResponse<Seat>>('/seats/admin/manage/', params)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  createSeat: async (data: Partial<Seat>): Promise<Seat> => {
    try {
      return await apiPost<Seat>('/seats/admin/manage/', data)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  updateSeat: async (seatId: string, data: Partial<Seat>): Promise<Seat> => {
    try {
      return await apiPatch<Seat>(`/seats/admin/${seatId}/`, data)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  deleteSeat: async (seatId: string): Promise<void> => {
    try {
      await apiDelete(`/seats/admin/${seatId}/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Book Management
  getAdminBooks: async (params?: any): Promise<PaginatedResponse<Book>> => {
    try {
      return await apiGet<PaginatedResponse<Book>>('/books/admin/manage/', params)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  createBook: async (data: Partial<Book>): Promise<Book> => {
    try {
      return await apiPost<Book>('/books/admin/manage/', data)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  updateBook: async (bookId: string, data: Partial<Book>): Promise<Book> => {
    try {
      return await apiPatch<Book>(`/books/admin/${bookId}/`, data)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  deleteBook: async (bookId: string): Promise<void> => {
    try {
      await apiDelete(`/books/admin/${bookId}/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Event Management
  getAdminEvents: async (params?: any): Promise<PaginatedResponse<Event>> => {
    try {
      return await apiGet<PaginatedResponse<Event>>('/events/admin/manage/', params)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  createEvent: async (data: Partial<Event>): Promise<Event> => {
    try {
      return await apiPost<Event>('/events/admin/manage/', data)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  updateEvent: async (eventId: string, data: Partial<Event>): Promise<Event> => {
    try {
      return await apiPatch<Event>(`/events/admin/${eventId}/`, data)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  deleteEvent: async (eventId: string): Promise<void> => {
    try {
      await apiDelete(`/events/admin/${eventId}/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Analytics
  getDashboardAnalytics: async (params?: any): Promise<any> => {
    try {
      return await apiGet('/analytics/dashboard/', params)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  getUserAnalytics: async (params?: any): Promise<any> => {
    try {
      return await apiGet('/analytics/users/', params)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  getBookAnalytics: async (params?: any): Promise<any> => {
    try {
      return await apiGet('/analytics/books/', params)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  getSeatAnalytics: async (params?: any): Promise<any> => {
    try {
      return await apiGet('/analytics/seats/', params)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  getEventAnalytics: async (params?: any): Promise<any> => {
    try {
      return await apiGet('/analytics/events/', params)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  getLibraryAnalytics: async (params?: any): Promise<any> => {
    try {
      return await apiGet('/analytics/libraries/', params)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  getSubscriptionAnalytics: async (params?: any): Promise<any> => {
    try {
      return await apiGet('/analytics/subscriptions/', params)
    } catch (error) {
      throw handleApiError(error)
    }
  }
}
