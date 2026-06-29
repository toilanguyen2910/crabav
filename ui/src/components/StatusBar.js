import React from 'react';
import { Box, Typography, Paper, keyframes } from '@mui/material';

const pulse = keyframes`
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
`;

function StatusBar({ systemStatus, agentsActive }) {
  const getStatusIndicator = () => {
    switch (systemStatus) {
      case 'protected': return '🟢';
      case 'warning': return '🟡';
      case 'danger':
      case 'error': return '🔴';
      default: return '⚪';
    }
  };

  return (
    <Paper
      sx={{
        position: 'fixed', bottom: 0, left: 0, right: 0, height: 32,
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        px: 2.5, zIndex: 1200,
        background: 'linear-gradient(90deg, #0d0d1a 0%, #141428 100%)',
        borderTop: '1px solid rgba(255,255,255,0.06)',
      }}
      elevation={0}
    >
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.6)', fontWeight: 500 }}>
            {getStatusIndicator()} {systemStatus || 'unknown'}
          </Typography>
        </Box>
        <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.2)' }}>|</Typography>
        <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.5)' }}>
          Agents: <Box component="span" sx={{ color: agentsActive > 0 ? '#00d4ff' : 'rgba(255,255,255,0.4)', fontWeight: 600 }}>{agentsActive ?? '?'}</Box> active
        </Typography>
        {systemStatus === 'error' && (
          <Typography variant="caption" sx={{ color: '#ff4444', animation: `${pulse} 1.5s ease-in-out infinite` }}>
            Backend disconnected — check server
          </Typography>
        )}
      </Box>
      <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.3)', fontFamily: 'monospace' }}>
        {new Date().toLocaleTimeString()}
      </Typography>
    </Paper>
  );
}

export default StatusBar;
