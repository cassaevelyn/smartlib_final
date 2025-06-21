import { useState } from 'react'
import { 
  TextField, 
  InputAdornment, 
  IconButton,
  FormHelperText,
} from '@mui/material'
import { Visibility, VisibilityOff, Lock } from '@mui/icons-material'
import { UseFormRegisterReturn } from 'react-hook-form'

interface PasswordFieldProps {
  registration: UseFormRegisterReturn
  label?: string
  error?: string
  placeholder?: string
  autoComplete?: string
  showStartAdornment?: boolean
  fullWidth?: boolean
  className?: string
}

export function PasswordField({
  registration,
  label = 'Password',
  error,
  placeholder,
  autoComplete = 'current-password',
  showStartAdornment = false,
  fullWidth = true,
  className,
}: PasswordFieldProps) {
  const [showPassword, setShowPassword] = useState(false)

  return (
    <div className={className}>
      <TextField
        {...registration}
        fullWidth={fullWidth}
        label={label}
        type={showPassword ? 'text' : 'password'}
        autoComplete={autoComplete}
        placeholder={placeholder}
        error={!!error}
        InputProps={{
          startAdornment: showStartAdornment ? (
            <InputAdornment position="start">
              <Lock color="action" />
            </InputAdornment>
          ) : undefined,
          endAdornment: (
            <InputAdornment position="end">
              <IconButton
                aria-label="toggle password visibility"
                onClick={() => setShowPassword(!showPassword)}
                edge="end"
              >
                {showPassword ? <VisibilityOff /> : <Visibility />}
              </IconButton>
            </InputAdornment>
          ),
        }}
      />
      {error && <FormHelperText error>{error}</FormHelperText>}
    </div>
  )
}