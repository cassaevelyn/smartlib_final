// Base types
export interface BaseEntity {
  id: string
  created_at: string
  updated_at: string
}

export interface User extends BaseEntity {
  username: string
  email: string
  first_name: string
  last_name: string
  full_name: string
  crn: string
  student_id: string
  phone_number?: string
  date_of_birth?: string
  gender?: 'M' | 'F' | 'O'
  address?: string
  city?: string
  role: 'STUDENT' | 'ADMIN' | 'SUPER_ADMIN'
  is_approved: boolean
  is_verified: boolean  // Email verification status
  is_active: boolean
  avatar?: string
  bio?: string
  preferred_language: string
  last_login?: string
  login_count: number
  has_active_subscription?: boolean
  current_subscription?: UserSubscription
  managed_library_id?: string  // ID of the library managed by this admin
  has_admin_profile?: boolean  // Whether the user has an admin profile
}

export interface UserProfile extends BaseEntity {
  user: string
  education_level?: 'FOUNDATION' | 'INTERMEDIATE' | 'ADVANCED' | 'FINAL'
  enrollment_year?: number
  expected_completion_year?: number
  emergency_contact_name?: string
  emergency_contact_phone?: string
  emergency_contact_relation?: string
  preferred_study_time?: string
  preferred_seat_type?: string
  study_subjects: string[]
  total_study_hours: number
  books_read: number
  events_attended: number
  loyalty_points: number
}

export interface AdminProfile extends BaseEntity {
  id: string
  user: string
  user_display: string
  managed_library?: string
  managed_library_display?: string
  permissions: Record<string, any>
  can_approve_users: boolean
  can_manage_events: boolean
  can_manage_books: boolean
  can_view_analytics: boolean
  created_at: string
  updated_at: string
}

export interface Library extends BaseEntity {
  name: string
  code: string
  library_type: 'MAIN' | 'BRANCH' | 'STUDY_CENTER' | 'DIGITAL_HUB'
  status: 'ACTIVE' | 'MAINTENANCE' | 'CLOSED' | 'RENOVATION'
  description?: string
  address: string
  city: string
  postal_code?: string
  latitude?: number
  longitude?: number
  phone_number?: string
  email?: string
  website?: string
  opening_time: string
  closing_time: string
  is_24_hours: boolean
  total_capacity: number
  total_seats: number
  available_seats: number
  occupied_seats: number
  total_study_rooms: number
  has_wifi: boolean
  has_printing: boolean
  has_scanning: boolean
  has_cafeteria: boolean
  has_parking: boolean
  main_image?: string
  gallery_images: string[]
  floor_plan?: string
  allow_booking: boolean
  booking_advance_days: number
  max_booking_duration_hours: number
  auto_cancel_minutes: number
  total_visits: number
  average_rating: number
  total_reviews: number
  amenities: string[]
  rules: string[]
  is_open: boolean
  occupancy_rate: number
}

export interface LibraryFloor extends BaseEntity {
  library: string
  floor_number: number
  floor_name: string
  description?: string
  total_seats: number
  available_seats: number
  study_rooms: number
  has_silent_zone: boolean
  has_group_study: boolean
  has_computer_lab: boolean
  has_printer: boolean
  has_restroom: boolean
  floor_plan_image?: string
  layout_data: any
  occupancy_rate: number
}

export interface LibrarySection extends BaseEntity {
  floor: string
  name: string
  section_type: 'SILENT' | 'GROUP' | 'COMPUTER' | 'READING' | 'DISCUSSION' | 'PRIVATE' | 'GENERAL'
  description?: string
  total_seats: number
  available_seats: number
  max_occupancy: number
  has_power_outlets: boolean
  has_ethernet: boolean
  has_whiteboard: boolean
  has_projector: boolean
  noise_level: 'SILENT' | 'LOW' | 'MODERATE'
  requires_booking: boolean
  advance_booking_hours: number
  max_booking_duration: number
  layout_coordinates: any
  is_section_full: boolean
}

export interface Seat extends BaseEntity {
  library: string
  library_name: string
  floor: string
  floor_name: string
  section: string
  section_name: string
  seat_number: string
  seat_code: string
  seat_type: 'INDIVIDUAL' | 'GROUP' | 'COMPUTER' | 'SILENT' | 'DISCUSSION' | 'PREMIUM' | 'ACCESSIBLE'
  seat_type_display: string
  status: 'AVAILABLE' | 'OCCUPIED' | 'RESERVED' | 'MAINTENANCE' | 'OUT_OF_ORDER'
  status_display: string
  is_available: boolean
  has_power_outlet: boolean
  has_ethernet: boolean
  has_monitor: boolean
  has_whiteboard: boolean
  is_near_window: boolean
  is_accessible: boolean
  x_coordinate?: number
  y_coordinate?: number
  rotation: number
  is_bookable: boolean
  requires_approval: boolean
  is_premium: boolean
  max_booking_duration_hours: number
  total_bookings: number
  total_usage_hours: number
  average_rating: number
  description?: string
  features: string[]
  current_booking?: {
    id: string
    booking_code: string
    user: string
    start_time: string
    end_time: string
    status: string
  }
}

export interface SeatBooking extends BaseEntity {
  user: string
  user_display: string
  seat: string
  seat_display: string
  library_name: string
  booking_code: string
  booking_type: 'REGULAR' | 'RECURRING' | 'GROUP' | 'PRIORITY'
  booking_type_display: string
  booking_date: string
  start_time: string
  end_time: string
  status: 'PENDING' | 'CONFIRMED' | 'CHECKED_IN' | 'COMPLETED' | 'CANCELLED' | 'NO_SHOW' | 'EXPIRED'
  status_display: string
  duration_hours: number
  actual_start_time?: string
  actual_end_time?: string
  actual_duration_hours: number
  checked_in_at?: string
  checked_out_at?: string
  is_active: boolean
  can_check_in: boolean
  can_check_out: boolean
  auto_cancel_at?: string
  reminder_sent: boolean
  late_cancellation: boolean
  purpose?: string
  special_requirements?: string
  notes?: string
  penalty_points: number
  loyalty_points_earned: number
}

export interface Book extends BaseEntity {
  title: string
  subtitle?: string
  book_code: string
  isbn?: string
  isbn13?: string
  category_name: string
  authors_list: string
  publisher_name: string
  library_name: string
  book_type: 'PHYSICAL' | 'DIGITAL' | 'BOTH'
  book_type_display: string
  status: 'AVAILABLE' | 'RESERVED' | 'CHECKED_OUT' | 'MAINTENANCE' | 'LOST' | 'DAMAGED' | 'RETIRED'
  status_display: string
  is_available: boolean
  physical_copies: number
  available_copies: number
  cover_image?: string
  thumbnail?: string
  average_rating: number
  total_reviews: number
  is_featured: boolean
  is_new_arrival: boolean
  is_popular: boolean
  is_premium: boolean
  estimated_availability?: string
}

export interface BookDetail extends Book {
  description?: string
  table_of_contents?: string
  summary?: string
  keywords: string[]
  tags: string[]
  publication_date?: string
  edition?: string
  pages?: number
  language: string
  language_display: string
  current_reservations: number
  max_concurrent_digital_access: number
  digital_access_duration_hours: number
  shelf_location?: string
  call_number?: string
  requires_approval: boolean
  rental_price_per_day: number
  total_reservations: number
  total_checkouts: number
  view_count: number
  user_can_reserve: boolean
  user_has_reserved: boolean
  user_has_reviewed: boolean
  similar_books: Book[]
  recent_reviews: BookReview[]
}

export interface BookReservation extends BaseEntity {
  user: string
  user_display: string
  book: string
  book_title: string
  book_cover?: string
  reservation_code: string
  reservation_type: 'PHYSICAL' | 'DIGITAL'
  reservation_type_display: string
  status: 'PENDING' | 'CONFIRMED' | 'READY_FOR_PICKUP' | 'CHECKED_OUT' | 'RETURNED' | 'CANCELLED' | 'EXPIRED' | 'OVERDUE'
  status_display: string
  reservation_date: string
  pickup_deadline?: string
  pickup_date?: string
  due_date?: string
  return_date?: string
  is_overdue: boolean
  days_until_due?: number
  can_renew: boolean
  digital_access_granted_at?: string
  digital_access_expires_at?: string
  access_count: number
  max_access_count: number
  pickup_library?: string
  library_name?: string
  return_library?: string
  issued_by?: string
  returned_to?: string
  reminder_sent: boolean
  overdue_notices_sent: number
  late_fee: number
  damage_fee: number
  penalty_points: number
  purpose?: string
  notes?: string
  renewal_count: number
  max_renewals: number
}

export interface BookReview extends BaseEntity {
  user_display: string
  user_avatar?: string
  book_title: string
  overall_rating: number
  content_rating?: number
  readability_rating?: number
  usefulness_rating?: number
  title?: string
  review_text: string
  pros?: string
  cons?: string
  would_recommend: boolean
  target_audience?: string
  is_approved: boolean
  helpful_count: number
  not_helpful_count: number
  helpfulness_ratio: number
}

export interface Event extends BaseEntity {
  title: string
  slug: string
  event_code: string
  category_name: string
  event_type: 'WORKSHOP' | 'SEMINAR' | 'LECTURE' | 'CONFERENCE' | 'TRAINING' | 'BOOK_CLUB' | 'STUDY_GROUP' | 'EXAM_PREP' | 'NETWORKING' | 'CULTURAL' | 'COMPETITION' | 'ORIENTATION'
  event_type_display: string
  status: 'DRAFT' | 'PUBLISHED' | 'REGISTRATION_OPEN' | 'REGISTRATION_CLOSED' | 'IN_PROGRESS' | 'COMPLETED' | 'CANCELLED' | 'POSTPONED'
  status_display: string
  start_date: string
  end_date: string
  start_time: string
  end_time: string
  library_name: string
  organizer_name: string
  speakers_list: string
  registration_type: 'FREE' | 'PAID' | 'INVITATION_ONLY' | 'FIRST_COME_FIRST_SERVE' | 'APPROVAL_REQUIRED'
  registration_type_display: string
  registration_fee: number
  max_participants: number
  total_registrations: number
  is_registration_open: boolean
  is_full: boolean
  available_spots: number
  registration_deadline: string
  duration_hours: number
  is_online: boolean
  banner_image?: string
  thumbnail?: string
  average_rating: number
  total_feedback: number
}

export interface EventDetail extends Event {
  description: string
  agenda?: string
  learning_objectives: string[]
  prerequisites?: string
  materials_provided: string[]
  speakers: EventSpeaker[]
  co_organizers_names: string[]
  timezone: string
  is_recurring: boolean
  recurrence_pattern: any
  venue_details?: string
  online_meeting_link?: string
  min_participants: number
  early_bird_deadline?: string
  early_bird_discount: number
  target_audience: string[]
  required_role?: string
  required_subscription: boolean
  gallery_images: string[]
  attachments: string[]
  has_certificate: boolean
  has_feedback_form: boolean
  requires_attendance_tracking: boolean
  send_reminders: boolean
  reminder_hours: number[]
  tags: string[]
  external_links: any
  additional_info: any
  user_can_register: boolean
  user_registration_status?: string
  user_registration_fee: number
  similar_events: Event[]
}

export interface EventSpeaker extends BaseEntity {
  first_name: string
  last_name: string
  full_name: string
  title?: string
  organization?: string
  bio?: string
  expertise: string[]
  email?: string
  phone?: string
  website?: string
  linkedin?: string
  photo?: string
  total_events: number
  average_rating: number
}

export interface EventRegistration extends BaseEntity {
  user: string
  user_display: string
  event: string
  event_title: string
  event_banner?: string
  registration_code: string
  status: 'PENDING' | 'CONFIRMED' | 'WAITLISTED' | 'CANCELLED' | 'ATTENDED' | 'NO_SHOW' | 'REFUNDED'
  status_display: string
  registration_date: string
  registration_fee_paid: number
  payment_status: 'PENDING' | 'COMPLETED' | 'FAILED' | 'REFUNDED' | 'NOT_REQUIRED'
  payment_status_display: string
  payment_reference?: string
  can_check_in: boolean
  can_check_out: boolean
  check_in_time?: string
  check_out_time?: string
  attendance_duration?: string
  qr_code_expires_at?: string
  dietary_requirements?: string
  special_needs?: string
  emergency_contact?: string
  how_did_you_hear?: string
  expectations?: string
  certificate_issued: boolean
  certificate_file?: string
  feedback_submitted: boolean
}

export interface EventFeedback extends BaseEntity {
  user_display: string
  user_avatar?: string
  event_title: string
  overall_rating: number
  content_rating?: number
  speaker_rating?: number
  organization_rating?: number
  venue_rating?: number
  what_you_liked?: string
  what_could_improve?: string
  additional_comments?: string
  would_recommend: boolean
  would_attend_similar: boolean
  future_topics?: string
  preferred_format?: string
  preferred_duration?: string
}

export interface Notification {
  id: string
  title: string
  message: string
  type: 'SUCCESS' | 'INFO' | 'WARNING' | 'ERROR'
  is_read: boolean
  created_at: string
  action_url?: string
}

// Subscription types
export interface SubscriptionPlan extends BaseEntity {
  name: string
  code: string
  plan_type: 'BASIC' | 'STANDARD' | 'PREMIUM' | 'STUDENT' | 'FACULTY'
  plan_type_display: string
  description: string
  features: string[]
  price: number
  discount_percentage: number
  discounted_price: number
  billing_period: 'MONTHLY' | 'QUARTERLY' | 'SEMI_ANNUAL' | 'ANNUAL'
  billing_period_display: string
  billing_period_days: number
  max_book_reservations: number
  max_seat_bookings: number
  max_event_registrations: number
  max_concurrent_digital_access: number
  has_premium_seat_access: boolean
  has_premium_book_access: boolean
  has_premium_event_access: boolean
  is_active: boolean
  is_featured: boolean
  color: string
  icon: string
  benefits: PlanBenefit[]
}

export interface PlanBenefit extends BaseEntity {
  benefit: SubscriptionBenefit
  value: string
  is_available: boolean
}

export interface SubscriptionBenefit extends BaseEntity {
  name: string
  description: string
  benefit_type: 'FEATURE' | 'DISCOUNT' | 'LIMIT_INCREASE' | 'PRIORITY' | 'REWARD'
  benefit_type_display: string
  icon: string
  is_highlighted: boolean
  sort_order: number
}

export interface UserSubscription extends BaseEntity {
  user: string
  user_display: string
  plan: string
  plan_display: string
  subscription_code: string
  start_date: string
  end_date: string
  cancelled_at?: string
  status: 'ACTIVE' | 'EXPIRED' | 'CANCELLED' | 'PENDING' | 'TRIAL'
  status_display: string
  is_auto_renew: boolean
  amount_paid: number
  payment_status: 'PENDING' | 'COMPLETED' | 'FAILED' | 'REFUNDED'
  payment_status_display: string
  payment_method: string
  payment_reference: string
  notes: string
  metadata: any
  is_active: boolean
  days_remaining: number
  percentage_remaining: number
}

export interface SubscriptionTransaction extends BaseEntity {
  user: string
  user_display: string
  subscription: string
  transaction_code: string
  transaction_type: 'PURCHASE' | 'RENEWAL' | 'REFUND' | 'UPGRADE' | 'DOWNGRADE'
  transaction_type_display: string
  amount: number
  currency: string
  status: 'PENDING' | 'COMPLETED' | 'FAILED' | 'REFUNDED'
  status_display: string
  payment_method: string
  payment_reference: string
  payment_gateway: string
  notes: string
  metadata: any
}

// API Response types
export interface PaginatedResponse<T> {
  count: number
  next: string | null
  previous: string | null
  results: T[]
}

export interface ApiError {
  message: string
  errors?: Record<string, string[]>
  status: number
  code?: string
}

// Form types
export interface LoginForm {
  email: string
  password: string
}

export interface RegisterForm {
  id?: string  // Added for OTP verification flow
  username: string
  email: string
  password: string
  password_confirm: string
  first_name: string
  last_name: string
  crn: string
  phone_number?: string
  date_of_birth?: string
  gender?: 'M' | 'F' | 'O'
  address?: string
  city?: string
}

export interface SeatBookingForm {
  seat: string
  booking_date: string
  start_time: string
  end_time: string
  booking_type?: 'REGULAR' | 'RECURRING' | 'GROUP' | 'PRIORITY'
  purpose?: string
  special_requirements?: string
  notes?: string
}

export interface BookReservationForm {
  book: string
  reservation_type: 'PHYSICAL' | 'DIGITAL'
  pickup_library?: string
  purpose?: string
  notes?: string
}

export interface EventRegistrationForm {
  event: string
  dietary_requirements?: string
  special_needs?: string
  emergency_contact?: string
  how_did_you_hear?: string
  expectations?: string
}

export interface SubscriptionPurchaseForm {
  plan_id: string
  payment_method: string
  payment_reference?: string
  start_date?: string
  is_auto_renew?: boolean
}

export interface SubscriptionCancelForm {
  subscription_id: string
  cancellation_reason?: string
}

export interface SubscriptionRenewForm {
  subscription_id: string
  payment_method: string
  payment_reference?: string
}

// Search and filter types
export interface SeatSearchFilters {
  library_id?: string
  floor_id?: string
  section_id?: string
  seat_type?: string
  date?: string
  start_time?: string
  end_time?: string
  has_power_outlet?: boolean
  has_ethernet?: boolean
  has_monitor?: boolean
  is_near_window?: boolean
  is_accessible?: boolean
  is_premium?: boolean
  min_rating?: number
  sort_by?: 'seat_number' | 'rating' | 'availability' | 'features'
}

export interface BookSearchFilters {
  query?: string
  category_id?: string
  author_id?: string
  publisher_id?: string
  library_id?: string
  book_type?: string
  language?: string
  is_available?: boolean
  is_featured?: boolean
  is_new_arrival?: boolean
  is_popular?: boolean
  is_premium?: boolean
  min_rating?: number
  publication_year_from?: number
  publication_year_to?: number
  sort_by?: 'title' | 'author' | 'publication_date' | 'rating' | 'popularity' | 'newest'
}

export interface EventSearchFilters {
  query?: string
  category_id?: string
  event_type?: string
  library_id?: string
  start_date_from?: string
  start_date_to?: string
  is_online?: boolean
  is_free?: boolean
  has_certificate?: boolean
  registration_open?: boolean
  sort_by?: 'start_date' | 'title' | 'registration_deadline' | 'popularity' | 'rating'
}

// Dashboard types
export interface DashboardStats {
  current_bookings: number
  upcoming_events: number
  active_reservations: number
  loyalty_points: number
  total_study_hours: number
  books_read: number
  events_attended: number
  completion_rate: number
}

export interface RecentActivity {
  id: string
  type: 'SEAT_BOOKING' | 'BOOK_RESERVATION' | 'EVENT_REGISTRATION' | 'REVIEW_SUBMISSION'
  title: string
  description: string
  timestamp: string
  status: string
}