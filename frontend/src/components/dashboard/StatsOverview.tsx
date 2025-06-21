import { Grid } from '@mui/material'
import { 
  EventSeat, 
  MenuBook, 
  Event, 
  EmojiEvents,
  AccessTime,
  School,
  CalendarToday,
} from '@mui/icons-material'
import { DashboardStats } from '../../types'
import { StatCard } from './StatCard'

interface StatsOverviewProps {
  stats: DashboardStats
}

export function StatsOverview({ stats }: StatsOverviewProps) {
  return (
    <Grid container spacing={3} sx={{ mb: 4 }}>
      <Grid item xs={12} sm={6} md={3}>
        <StatCard
          title="Seat Bookings"
          value={stats.current_bookings}
          icon={<EventSeat />}
          description="Active bookings today"
          color="primary.main"
        />
      </Grid>

      <Grid item xs={12} sm={6} md={3}>
        <StatCard
          title="Book Reservations"
          value={stats.active_reservations}
          icon={<MenuBook />}
          description="Active reservations"
          color="secondary.main"
        />
      </Grid>

      <Grid item xs={12} sm={6} md={3}>
        <StatCard
          title="Upcoming Events"
          value={stats.upcoming_events}
          icon={<Event />}
          description="Events you're registered for"
          color="success.main"
        />
      </Grid>

      <Grid item xs={12} sm={6} md={3}>
        <StatCard
          title="Loyalty Points"
          value={stats.loyalty_points}
          icon={<EmojiEvents />}
          description="Total points earned"
          color="warning.main"
        />
      </Grid>

      <Grid item xs={12} sm={6} md={3}>
        <StatCard
          title="Study Hours"
          value={`${stats.total_study_hours}h`}
          icon={<AccessTime />}
          description="Total time spent studying"
          color="info.main"
        />
      </Grid>

      <Grid item xs={12} sm={6} md={3}>
        <StatCard
          title="Books Read"
          value={stats.books_read}
          icon={<School />}
          description="Books completed"
          color="error.main"
        />
      </Grid>

      <Grid item xs={12} sm={6} md={3}>
        <StatCard
          title="Events Attended"
          value={stats.events_attended}
          icon={<CalendarToday />}
          description="Total events participated in"
          color="success.dark"
        />
      </Grid>

      <Grid item xs={12} sm={6} md={3}>
        <StatCard
          title="Completion Rate"
          value={`${stats.completion_rate}%`}
          icon={<EmojiEvents />}
          description="Booking completion rate"
          color="primary.dark"
        />
      </Grid>
    </Grid>
  )
}