import React from 'react';
import {
  Box,
  Button,
  Card,
  CardContent,
  Typography,
  Chip,
} from '@mui/material';
import {
  PlayArrow as PlayIcon,
  Search as SearchIcon,
  FolderOpen as FolderIcon,
} from '@mui/icons-material';

function Header({ systemStatus, onStartScan }) {
  const getStatusColor = (status) => {
    switch (status) {
      case 'protected':
        return 'success';
      case 'warning':
        return 'warning';
      case 'danger':
        return 'error';
      default:
        return 'default';
    }
  };

  const getStatusText = (status) => {
    switch (status) {
      case 'protected':
        return '🛡️ Protected';
      case 'warning':
        return '⚠️ Attention Needed';
      case 'danger':
        return '🚨 At Risk';
      case 'loading':
        return '⏳ Loading...';
      default:
        return '❓ Unknown';
    }
  };

  return (
    <Box sx={{ mb: 4 }}>
      {/* Status Banner */}
      <Card
        sx={{
          mb: 3,
          background: 'linear-gradient(135deg, #1e1e1e 0%, #252525 100%)',
          border: '1px solid',
          borderColor: 'divider',
        }}
      >
        <CardContent>
          <Box
            sx={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: 2,
            }}
          >
            <Box>
              <Typography variant="h5" gutterBottom>
                System Status
              </Typography>
              <Chip
                label={getStatusText(systemStatus)}
                color={getStatusColor(systemStatus)}
                variant="outlined"
                sx={{ fontSize: '1rem', py: 2, px: 1 }}
              />
            </Box>

            <Box sx={{ display: 'flex', gap: 1 }}>
              <Button
                variant="contained"
                color="primary"
                size="large"
                startIcon={<PlayIcon />}
                onClick={() => onStartScan('quick')}
              >
                Quick Scan
              </Button>
              <Button
                variant="outlined"
                size="large"
                startIcon={<SearchIcon />}
                onClick={() => onStartScan('full')}
              >
                Full Scan
              </Button>
              <Button
                variant="outlined"
                size="large"
                startIcon={<FolderIcon />}
                onClick={() => onStartScan('custom')}
              >
                Custom Scan
              </Button>
            </Box>
          </Box>
        </CardContent>
      </Card>
    </Box>
  );
}

export default Header;
