import { apiGet, handleApiError } from '../lib/api'
import { Book, Event, Seat, SubscriptionPlan } from '../types'

export const recommendationService = {
  // Get personalized book recommendations
  getBooksRecommendations: async (): Promise<{
    category_based: Book[];
    author_based: Book[];
    popular: Book[];
    new_arrivals: Book[];
    premium: Book[];
  }> => {
    try {
      return await apiGet('/recommendations/books/')
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get personalized event recommendations
  getEventsRecommendations: async (): Promise<{
    category_based: Event[];
    popular: Event[];
    free: Event[];
    premium: Event[];
  }> => {
    try {
      return await apiGet('/recommendations/events/')
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get personalized seat recommendations
  getSeatsRecommendations: async (): Promise<{
    type_based: Seat[];
    library_based: Seat[];
    highly_rated: Seat[];
    premium: Seat[];
  }> => {
    try {
      return await apiGet('/recommendations/seats/')
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get subscription plan recommendations
  getSubscriptionsRecommendations: async (): Promise<{
    has_subscription: boolean;
    current_plan?: SubscriptionPlan;
    upgrade_options?: SubscriptionPlan[];
    featured_plan?: SubscriptionPlan;
    basic_plan?: SubscriptionPlan;
    student_plan?: SubscriptionPlan;
    all_plans?: SubscriptionPlan[];
  }> => {
    try {
      return await apiGet('/recommendations/subscriptions/')
    } catch (error) {
      throw handleApiError(error)
    }
  }
}