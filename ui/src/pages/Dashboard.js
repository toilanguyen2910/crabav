import React from 'react';
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography,
  Stack,
  Chip,
} from '@mui/material';
import {
  Security as SecurityIcon,
  Scan as ScanIcon,
  ListAlt as ListIcon,
  CheckCircle as CheckIcon,
} from '@mui/icons-material';

function Dashboard() {
  const stats = [
    {
      title: 'Total Scanned',
      value: '1,234',
      change: '+12%',
      icon: <ScanIcon />,
      color: 'primary',
    },
    {
      title: 'Threats Found',
      value: '3',
      change: '-2',
      icon: <SecurityIcon />,
      color: 'error',
    },
    {
      title: 'Quarantined',
      value: '3',
      change: '0',
      icon: <ListIcon />,
      color: 'warning',
    },
    {
      title: 'Whitelisted',
      value: '0',
      change: '0',
      icon: <CheckIcon />,
      color: 'success',
    },
  ];

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 4, fontWeight: 'bold' }}>
        Dashboard
      </Typography>

      {/* Stats Grid */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        {stats.map((stat, index) => (
          <Grid item xs={12} sm={6} md={3} key={index}>
            <Card
              sx={{
                background: 'linear-gradient(135deg, #1e1e1e 0%, #252525 100%)',
                border: '1px solid',
                borderColor: 'divider',
              }}
            >
              <CardContent>
                <Stack
                  direction="row"
                  alignItems="center"
                  spacing={2}
                  sx={{ mb: 2 }}
                >
                  <Box
                    sx={{
                      p: 1.5,
                      borderRadius: 1,
                      backgroundColor: `${stat.color}.light`,
                      color: `${stat.color}.main`,
                    }}
                  >
                    {React.cloneElement(stat.icon, { fontSize: 'medium' })}
                  </Box>
                  <Typography variant="subtitle1" color="text.secondary">
                    {stat.title}
                  </Typography>
                </Stack>
                <Typography variant="h3" sx={{ fontWeight: 'bold' }}>
                  {stat.value}
                </Typography>
                <Typography variant="caption" color="success.main">
                  {stat.change} from last scan
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>

      {/* Quick Actions */}
      <Typography variant="h5" sx={{ mb: 2, fontWeight: 'bold' }}>
        Quick Actions
      </Typography>
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Choose a scan type to protect your system
          </Typography>
          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
            <Chip label="Quick Scan" color="primary" />
            <Chip label="Full Scan" color="secondary" />
            <Chip label="Custom Scan" color="warning" />
            <Chip label="Real-time Scan" color="success" />
          </Box>
        </CardContent>
      </Card>

      {/* System Status */}
      <Typography variant="h5" sx={{ mb: 2, fontWeight: 'bold' }}>
        Agent Status
      </Typography>
      <Card>
        <CardContent>
          <Typography variant="body2" color="success.main" sx={{ mb: 1 }}>
            🟢 File Scanner - Active
          </Typography>
          <Typography variant="body2" color="success.main" sx={{ mb: 1 }}>
            🟢 Registry Scanner - Active
          </Typography>
          <Typography variant="body2" color="success.main" sx={{ mb: 1 }}>
            🟢 Memory Scanner - Active
          </Typography>
          <Typography variant="body2" color="success.main" sx={{ mb: 1 }}>
            🟢 File Monitor - Active
          </Typography>
          <Typography variant="body2" color="success.main" sx={{ mb: 1 }}>
            🟢 Process Monitor - Active
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
            🟡 Threat Intelligence - Loading
          </Typography>
          <Typography variant="body2" color="text.secondary">
            🟡 ML Classifier - Not Available
          </Typography>
        </CardContent>
      </Card>
    </Box>
  );
}

export default Dashboard;
