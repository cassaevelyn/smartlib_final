import { Box, Card, CardContent, CardMedia, Typography, Chip, Button, Rating } from '@mui/material'
import { LocationOn, AccessTime, ChevronRight } from '@mui/icons-material'
import { motion } from 'framer-motion'
import { useNavigate } from 'react-router-dom'
import { Library } from '../../types'
import { truncateText } from '../../lib/utils'

interface LibraryCardProps {
  library: Library
}

export function LibraryCard({ library }: LibraryCardProps) {
  const navigate = useNavigate()

  return (
    <motion.div
      whileHover={{ y: -5, transition: { duration: 0.2 } }}
      whileTap={{ scale: 0.98 }}
    >
      <Card sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
        <CardMedia
          component="img"
          height="160"
          image={library.main_image || 'https://images.pexels.com/photos/590493/pexels-photo-590493.jpeg'}
          alt={library.name}
        />
        <CardContent sx={{ flexGrow: 1 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 1 }}>
            <Typography variant="h6" component="div">
              {library.name}
            </Typography>
            <Chip
              label={library.status}
              size="small"
              color={
                library.status === 'ACTIVE'
                  ? 'success'
                  : library.status === 'MAINTENANCE'
                  ? 'warning'
                  : 'error'
              }
            />
          </Box>

          <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
            <LocationOn fontSize="small" color="action" sx={{ mr: 0.5 }} />
            <Typography variant="body2" color="text.secondary">
              {truncateText(`${library.city}, ${library.address}`, 40)}
            </Typography>
          </Box>

          <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
            <AccessTime fontSize="small" color="action" sx={{ mr: 0.5 }} />
            <Typography variant="body2" color="text.secondary">
              {library.is_24_hours
                ? '24 Hours'
                : `${library.opening_time} - ${library.closing_time}`}
            </Typography>
          </Box>

          <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
            <Rating
              value={library.average_rating}
              precision={0.5}
              size="small"
              readOnly
            />
            <Typography variant="body2" color="text.secondary" sx={{ ml: 1 }}>
              ({library.total_reviews})
            </Typography>
          </Box>

          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <Chip
              label={`${library.available_seats}/${library.total_seats} seats`}
              size="small"
              color={
                library.occupancy_rate < 50
                  ? 'success'
                  : library.occupancy_rate < 80
                  ? 'warning'
                  : 'error'
              }
            />
            <Button
              size="small"
              endIcon={<ChevronRight />}
              onClick={() => navigate(`/libraries/${library.id}`)}
            >
              Details
            </Button>
          </Box>
        </CardContent>
      </Card>
    </motion.div>
  )
}