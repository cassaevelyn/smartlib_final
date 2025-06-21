import { apiGet, apiPost, apiPatch, apiDelete, handleApiError, PaginatedResponse } from '../lib/api'
import { Book, BookDetail, BookReservation, BookReview, BookSearchFilters } from '../types'

export const bookService = {
  // Get all books with optional pagination and filters
  getBooks: async (params?: any): Promise<PaginatedResponse<Book>> => {
    try {
      return await apiGet<PaginatedResponse<Book>>('/books/', params)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get a specific book by ID
  getBook: async (id: string): Promise<BookDetail> => {
    try {
      return await apiGet<BookDetail>(`/books/${id}/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Search books with advanced filters
  searchBooks: async (filters: BookSearchFilters): Promise<PaginatedResponse<Book>> => {
    try {
      return await apiPost<PaginatedResponse<Book>>('/books/search/', filters)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get book categories
  getCategories: async (): Promise<PaginatedResponse<any>> => {
    try {
      return await apiGet<PaginatedResponse<any>>('/books/categories/')
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get book authors
  getAuthors: async (): Promise<PaginatedResponse<any>> => {
    try {
      return await apiGet<PaginatedResponse<any>>('/books/authors/')
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get book publishers
  getPublishers: async (): Promise<PaginatedResponse<any>> => {
    try {
      return await apiGet<PaginatedResponse<any>>('/books/publishers/')
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get all reservations for the current user
  getReservations: async (params?: any): Promise<PaginatedResponse<BookReservation>> => {
    try {
      return await apiGet<PaginatedResponse<BookReservation>>('/books/reservations/', params)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get a specific reservation by ID
  getReservation: async (id: string): Promise<BookReservation> => {
    try {
      return await apiGet<BookReservation>(`/books/reservations/${id}/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Create a new reservation
  createReservation: async (reservationData: any): Promise<BookReservation> => {
    try {
      return await apiPost<BookReservation>('/books/reservations/', reservationData)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Cancel a reservation
  cancelReservation: async (id: string): Promise<any> => {
    try {
      return await apiDelete(`/books/reservations/${id}/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Renew a book reservation
  renewReservation: async (reservationId: string): Promise<any> => {
    try {
      return await apiPost(`/books/reservations/${reservationId}/renew/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get reviews for a specific book
  getBookReviews: async (bookId: string): Promise<PaginatedResponse<BookReview>> => {
    try {
      return await apiGet<PaginatedResponse<BookReview>>(`/books/${bookId}/reviews/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Submit a review for a book
  submitBookReview: async (bookId: string, reviewData: any): Promise<BookReview> => {
    try {
      return await apiPost<BookReview>(`/books/${bookId}/reviews/`, reviewData)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get user book summary
  getBookSummary: async (): Promise<any> => {
    try {
      return await apiGet('/books/summary/')
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Add book to wishlist
  addToWishlist: async (bookId: string, priority: number = 1, notes: string = ''): Promise<any> => {
    try {
      return await apiPost('/books/wishlist/', {
        book_id: bookId,
        priority,
        notes
      })
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get user's wishlist
  getWishlist: async (): Promise<PaginatedResponse<any>> => {
    try {
      return await apiGet<PaginatedResponse<any>>('/books/wishlist/')
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Remove book from wishlist
  removeFromWishlist: async (wishlistId: string): Promise<any> => {
    try {
      return await apiDelete(`/books/wishlist/${wishlistId}/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get digital access to a book
  getDigitalAccess: async (reservationId: string, accessPassword: string): Promise<any> => {
    try {
      return await apiPost('/books/digital/access/', {
        reservation_id: reservationId,
        access_password: accessPassword
      })
    } catch (error) {
      throw handleApiError(error)
    }
  }
}