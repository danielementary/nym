import React, { useContext, useState } from 'react'
import { Alert, Button, Stack, TextField } from '@mui/material'
import { Subtitle } from '../components'
import { ClientContext } from '../../../context/main'

export const ExistingAccount: React.FC<{ page: 'existing account'; onPrev: () => void }> = ({ onPrev }) => {
  const [mnemonic, setMnemonic] = useState<string>('')

  const { logIn, error } = useContext(ClientContext)
  const handleSignIn = async (e: React.MouseEvent<HTMLElement>) => {
    e.preventDefault()
    logIn(mnemonic)
  }

  return (
    <Stack spacing={2} sx={{ width: 400 }} alignItems="center">
      <Subtitle subtitle="Enter your mnemonic from existing wallet" />
      <TextField value={mnemonic} onChange={(e) => setMnemonic(e.target.value)} multiline rows={5} fullWidth />
      {error && (
        <Alert severity="error" variant="outlined" data-testid="error" sx={{ color: 'error.light', width: '100%' }}>
          {error}
        </Alert>
      )}

      <Button variant="contained" size="large" fullWidth onClick={handleSignIn}>
        Sign in
      </Button>
      <Button
        variant="outlined"
        disableElevation
        size="large"
        onClick={onPrev}
        fullWidth
        sx={{ color: 'common.white', border: '1px solid white', '&:hover': { border: '1px solid white' } }}
      >
        Back
      </Button>
    </Stack>
  )
}