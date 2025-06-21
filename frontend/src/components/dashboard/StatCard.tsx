import { ReactNode } from 'react'
import { Card, CardContent, Typography, Box, Avatar, SxProps, Theme } from '@mui/material'
import { motion } from 'framer-motion'

interface StatCardProps {
  title: string
  value: string | number
  icon: ReactNode
  description?: string
  color?: string
  sx?: SxProps<Theme>
}

export function StatCard({ title, value, icon, description, color = 'primary.main', sx }: StatCardProps) {
  return (
    <motion.div
      whileHover={{ y: -5, transition: { duration: 0.2 } }}
      whileTap={{ scale: 0.98 }}
    >
      <Card sx={{ height: '100%', ...sx }}>
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
            <Avatar sx={{ bgcolor: color, mr: 2 }}>
              {icon}
            </Avatar>
            <Typography variant="h6" component="div">
              {title}
            </Typography>
          </Box>
          <Typography variant="h3" component="div" sx={{ mb: 1 }}>
            {value}
          </Typography>
          {description && (
            <Typography variant="body2" color="text.secondary">
              {description}
            </Typography>
          )}
        </CardContent>
      </Card>
    </motion.div>
  )
}