import { apiGet, apiPost, apiPatch, handleApiError, PaginatedResponse } from '../lib/api'
import { 
  SubscriptionPlan, 
  UserSubscription, 
  SubscriptionTransaction, 
  SubscriptionBenefit,
  SubscriptionPurchaseForm,
  SubscriptionCancelForm,
  SubscriptionRenewForm
} from '../types'

export const subscriptionService = {
  // Get all subscription plans
  getPlans: async (): Promise<PaginatedResponse<SubscriptionPlan>> => {
    try {
      return await apiGet<PaginatedResponse<SubscriptionPlan>>('/subscriptions/plans/')
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get a specific subscription plan by ID
  getPlan: async (id: string): Promise<SubscriptionPlan> => {
    try {
      return await apiGet<SubscriptionPlan>(`/subscriptions/plans/${id}/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get all user subscriptions
  getUserSubscriptions: async (): Promise<PaginatedResponse<UserSubscription>> => {
    try {
      return await apiGet<PaginatedResponse<UserSubscription>>('/subscriptions/my-subscriptions/')
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get a specific user subscription by ID
  getUserSubscription: async (id: string): Promise<UserSubscription> => {
    try {
      return await apiGet<UserSubscription>(`/subscriptions/my-subscriptions/${id}/`)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get current active subscription
  getCurrentSubscription: async (): Promise<UserSubscription> => {
    try {
      return await apiGet<UserSubscription>('/subscriptions/current/')
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Purchase a subscription
  purchaseSubscription: async (data: SubscriptionPurchaseForm): Promise<UserSubscription> => {
    try {
      return await apiPost<UserSubscription>('/subscriptions/purchase/', data)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Cancel a subscription
  cancelSubscription: async (data: SubscriptionCancelForm): Promise<{ message: string }> => {
    try {
      return await apiPost<{ message: string }>('/subscriptions/cancel/', data)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Renew a subscription
  renewSubscription: async (data: SubscriptionRenewForm): Promise<UserSubscription> => {
    try {
      return await apiPost<UserSubscription>('/subscriptions/renew/', data)
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get subscription transactions
  getTransactions: async (): Promise<PaginatedResponse<SubscriptionTransaction>> => {
    try {
      return await apiGet<PaginatedResponse<SubscriptionTransaction>>('/subscriptions/transactions/')
    } catch (error) {
      throw handleApiError(error)
    }
  },

  // Get subscription benefits
  getBenefits: async (): Promise<PaginatedResponse<SubscriptionBenefit>> => {
    try {
      return await apiGet<PaginatedResponse<SubscriptionBenefit>>('/subscriptions/benefits/')
    } catch (error) {
      throw handleApiError(error)
    }
  }
}