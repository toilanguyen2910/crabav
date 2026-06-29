import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  Box, Grid, Card, CardContent, Typography, Stack, Chip, Button,
  keyframes,
} from '@mui/material';
import {
  Security as SecurityIcon,
  Science as ScanIcon,
  BugReport as BugIcon,
  Archive as ArchiveIcon,
  PlayArrow,
  Radar,
} from '@mui/icons-material';
import api from '../api';

// ── Animations ──
const pulse = keyframes`
  0% { box-shadow: 0 0 0 0 rgba(255, 107, 53, 0.4); }
  70% { box-shadow: 0 0 0 15px rgba(255, 107, 53, 0); }
  100% { box-shadow: 0 0 0 0 rgba(255, 107, 53, 0); }
`;

const float = keyframes`
  0%, 100% { transform: translateY(0px); }
  50% { transform: translateY(-6px); }
`;

const shimmer = keyframes`
  0% { background-position: -200% center; }
  100% { background-position: 200% center; }
`;

function Dashboard() {
  const [data, setData] = useState({
    scans_total: 0, threats_total: 0, threats_pending: 0,
    quarantine_size: 0, agents: [],
  });
  const [scanning, setScanning] = useState(false);

  const loadData = useCallback(async () => {
    try {
      const [status, agents] = await Promise.all([
        api.getSystemStatus(), api.getAgents(),
      ]);
      setData({
        scans_total: 0,
        threats_total: status.threats_total || 0,
        threats_pending: status.threats_pending || 0,
        quarantine_size: status.quarantine_size || 0,
        agents: agents || [],
      });
    } catch (e) {
      console.error('Dashboard: failed to load', e);
    }
  }, []);

  useEffect(() => { loadData(); const iv = setInterval(loadData, 5000); return () => clearInterval(iv); }, [loadData]);

  const quickScan = async () => {
    setScanning(true);
    try {
      const result = await api.startScan('quick');
      if (result.success) {
        const poll = setInterval(async () => {
          const s = await api.getScanStatus(result.scan_id);
          if (s.status !== 'running') { clearInterval(poll); setScanning(false); loadData(); }
        }, 1000);
      }
    } catch { setScanning(false); }
  };

  const stats = [
    { title: 'Threats Found', value: data.threats_total, sub: `${data.threats_pending} pending`, icon: <BugIcon />, color: '#ff6b35', bg: 'rgba(255,107,53,0.10)' },
    { title: 'Pending Review', value: data.threats_pending, sub: data.threats_pending > 0 ? 'Needs action' : 'All clear', icon: <Radar />, color: '#ffc107', bg: 'rgba(255,193,7,0.10)' },
    { title: 'Agents Active', value: data.agents.filter(a => a.status === 'running').length, sub: `${data.agents.length} registered`, icon: <ScanIcon />, color: '#00d4ff', bg: 'rgba(0,212,255,0.10)' },
    { title: 'Quarantine', value: (data.quarantine_size / 1024).toFixed(1) + ' KB', sub: 'Isolated files', icon: <ArchiveIcon />, color: '#a78bfa', bg: 'rgba(167,139,250,0.10)' },
  ];

  return (
    <Box>
      {/* Hero Banner */}
      <Card sx={{
        mb: 4, borderRadius: 4,
        background: 'linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%)',
        border: '1px solid rgba(255,255,255,0.08)',
        overflow: 'hidden', position: 'relative',
      }}>
        <Box sx={{
          position: 'absolute', top: -60, right: -40,
          width: 200, height: 200, borderRadius: '50%',
          background: 'radial-gradient(circle, rgba(255,107,53,0.3) 0%, transparent 70%)',
        }} />
        <CardContent sx={{ p: 4, position: 'relative', zIndex: 1 }}>
          <Stack direction={{ xs: 'column', md: 'row' }} justifyContent="space-between" alignItems="center" spacing={2}>
            <Box>
              <Typography variant="h4" sx={{ fontWeight: 800, color: '#fff', mb: 1 }}>
                🦀 CrabAV Security Center
              </Typography>
              <Typography variant="body1" sx={{ color: 'rgba(255,255,255,0.6)' }}>
                Real-time protection active • Monitoring your system
              </Typography>
            </Box>
            <Button
              variant="contained"
              size="large"
              onClick={quickScan}
              disabled={scanning}
              startIcon={<PlayArrow />}
              sx={{
                px: 4, py: 1.5, borderRadius: 3,
                background: 'linear-gradient(135deg, #ff6b35 0%, #ff8c42 100%)',
                fontWeight: 700, fontSize: '1rem',
                animation: scanning ? `${pulse} 2s infinite` : 'none',
                '&:hover': { background: 'linear-gradient(135deg, #ff8c42 0%, #ff6b35 100%)' },
              }}
            >
              {scanning ? 'Scanning...' : 'Quick Scan'}
            </Button>
          </Stack>
        </CardContent>
      </Card>

      {/* Stats Grid */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        {stats.map((stat, index) => (
          <Grid item xs={12} sm={6} md={3} key={index}>
            <Card sx={{
              borderRadius: 3,
              background: 'linear-gradient(135deg, rgba(30,30,30,0.9) 0%, rgba(40,40,40,0.9) 100%)',
              border: '1px solid rgba(255,255,255,0.06)',
              backdropFilter: 'blur(10px)',
              transition: 'all 0.3s ease',
              '&:hover': { transform: 'translateY(-4px)', borderColor: stat.color, boxShadow: `0 8px 32px ${stat.bg}` },
              animation: `${float} ${3 + index * 0.3}s ease-in-out infinite`,
              animationDelay: `${index * 0.2}s`,
            }}>
              <CardContent sx={{ p: 3 }}>
                <Stack direction="row" alignItems="center" spacing={2} sx={{ mb: 2 }}>
                  <Box sx={{
                    p: 1.5, borderRadius: 2, background: stat.bg, color: stat.color,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                  }}>
                    {React.cloneElement(stat.icon, { sx: { fontSize: 28 } })}
                  </Box>
                  <Typography variant="subtitle2" sx={{ color: 'rgba(255,255,255,0.5)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: 1 }}>
                    {stat.title}
                  </Typography>
                </Stack>
                <Typography variant="h3" sx={{ fontWeight: 800, color: '#fff', mb: 0.5 }}>
                  {stat.value}
                </Typography>
                <Typography variant="caption" sx={{ color: stat.color, fontWeight: 500 }}>
                  {stat.sub}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>

      {/* Agent Status */}
      <Typography variant="h6" sx={{ mb: 2, fontWeight: 700, color: '#fff' }}>Active Agents</Typography>
      <Card sx={{ borderRadius: 3, background: 'rgba(20,20,20,0.8)', border: '1px solid rgba(255,255,255,0.06)' }}>
        <CardContent sx={{ p: 3 }}>
          {data.agents.length === 0 ? (
            <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.4)' }}>Connecting to engine...</Typography>
          ) : (
            <Stack spacing={1.5}>
              {data.agents.map((agent) => (
                <Stack key={agent.id} direction="row" alignItems="center" spacing={2}
                  sx={{
                    p: 1.5, borderRadius: 2,
                    background: agent.status === 'running' ? 'rgba(0,212,255,0.08)' : 'rgba(255,255,255,0.03)',
                  }}>
                  <Box sx={{
                    width: 10, height: 10, borderRadius: '50%',
                    background: agent.status === 'running' ? '#00d4ff' : '#666',
                    animation: agent.status === 'running' ? `${pulse} 2s infinite` : 'none',
                  }} />
                  <Typography variant="body2" sx={{ color: '#fff', fontWeight: 600, flex: 1 }}>
                    {agent.id}
                  </Typography>
                  <Chip label={agent.type} size="small" sx={{ background: 'rgba(255,255,255,0.08)', color: 'rgba(255,255,255,0.6)', borderRadius: 1 }} />
                  <Chip
                    label={agent.status}
                    size="small"
                    sx={{
                      borderRadius: 1,
                      background: agent.status === 'running' ? 'rgba(0,212,255,0.2)' : 'rgba(255,255,255,0.05)',
                      color: agent.status === 'running' ? '#00d4ff' : 'rgba(255,255,255,0.5)',
                    }}
                  />
                </Stack>
              ))}
            </Stack>
          )}
        </CardContent>
      </Card>
    </Box>
  );
}

export default Dashboard;
