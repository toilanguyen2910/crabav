import React from 'react';
import { Box, Typography, Paper } from '@mui/material';

function StatusBar({ systemStatus }) {
  const getStatusIndicator = () => {
    switch (systemStatus) {
      case 'protected':
        return '🟢';
      case 'warning':
        return '🟡';
      case 'danger':
        return '🔴';
      default:
        return '⚪';
    }
  };

  return (
    <Paper
      sx={{
        position: 'fixed',
        bottom: 0,
        left: 0,
        right: 0,
        height: 32,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        px: 2,
        backgroundColor: '#1a1a1a',
        borderTop: '1px solid',
        borderColor: 'divider',
        zIndex: 1200,
      }}
      elevation={0}
    >
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
        <Typography variant="caption">
          {getStatusIndicator()} Status: {systemStatus || 'Unknown'}
        </Typography>
        <Typography variant="caption" color="text.secondary">
          | Agents: 7/7 Active
        </Typography>
      </Box>
      <Typography variant="caption" color="text.secondary">
        Last Updated: {new Date().toLocaleTimeString()}
      </Typography>
    </Paper>
  );
}

export default StatusBar;
