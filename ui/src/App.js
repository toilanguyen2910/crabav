import React, { useState, useEffect, useCallback } from 'react';
import { Routes, Route } from 'react-router-dom';
import {
  Box,
  CssBaseline,
  Drawer,
  AppBar,
  Toolbar,
  Typography,
  IconButton,
  useTheme,
  useMediaQuery,
  Tooltip,
  Alert,
  LinearProgress,
} from '@mui/material';
import {
  Menu as MenuIcon,
  Security as SecurityIcon,
  Dashboard as DashboardIcon,
  ListAlt as ListIcon,
  Settings as SettingsIcon,
  Help as HelpIcon,
  Shield as ShieldIcon,
  Notifications as NotificationsIcon,
} from '@mui/icons-material';

import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import Threats from './pages/Threats';
import Scans from './pages/Scans';
import Settings from './pages/Settings';
import StatusBar from './components/StatusBar';
import Header from './components/Header';
import api from './api';

function App() {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  const [drawerOpen, setDrawerOpen] = useState(!isMobile);
  const [systemStatus, setSystemStatus] = useState('loading');
  const [scanInProgress, setScanInProgress] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [pendingThreats, setPendingThreats] = useState(0);
  const [agentsActive, setAgentsActive] = useState(0);

  // ── Poll system status ──
  const loadSystemStatus = useCallback(async () => {
    try {
      const status = await api.getSystemStatus();
      setSystemStatus(status.status);
      setPendingThreats(status.threats_pending || 0);
      setAgentsActive(status.agents_active || 0);
      if (status.scan_running) {
        setScanInProgress(true);
        setScanProgress(status.progress || 0);
      }
    } catch (error) {
      console.error('Failed to load system status:', error);
      setSystemStatus('error');
    }
  }, []);

  useEffect(() => {
    loadSystemStatus();
    const interval = setInterval(loadSystemStatus, 3000);
    return () => clearInterval(interval);
  }, [loadSystemStatus]);

  // ── Scan progress polling ──
  useEffect(() => {
    if (!scanInProgress) return;
    const poll = setInterval(async () => {
      try {
        const s = await api.getScanStatus();
        if (s.status === 'running') {
          setScanProgress(s.progress || 0);
        } else {
          setScanInProgress(false);
          setScanProgress(0);
          loadSystemStatus(); // refresh stats
        }
      } catch (e) { /* ignore */ }
    }, 2000);
    return () => clearInterval(poll);
  }, [scanInProgress, loadSystemStatus]);

  const handleDrawerToggle = () => {
    setDrawerOpen(!drawerOpen);
  };

  const startScan = async (scanType) => {
    try {
      setScanInProgress(true);
      setScanProgress(0);
      const result = await api.startScan(scanType);
      if (result.success) {
        console.log('Scan started:', result.scan_id);
      }
    } catch (error) {
      console.error('Failed to start scan:', error);
      setScanInProgress(false);
      alert('Failed to start scan. Is the backend running?\n\nStart it with: python -m src.api_server');
    }
  };

  const drawerWidth = 240;

  return (
    <Box sx={{ display: 'flex', height: '100vh', overflow: 'hidden', background: '#0a0a14' }}>
      <CssBaseline />
      
      {/* App Bar */}
      <AppBar
        position="fixed"
        sx={{
          zIndex: theme.zIndex.drawer + 1,
          background: 'linear-gradient(90deg, #0d0d1a 0%, #141428 100%)',
          borderBottom: '1px solid rgba(255,255,255,0.06)',
          backdropFilter: 'blur(20px)',
        }}
      >
        <Toolbar>
          <IconButton color="inherit" edge="start" onClick={handleDrawerToggle} sx={{ mr: 2 }}>
            <MenuIcon />
          </IconButton>
          <Box sx={{
            p: 0.8, borderRadius: 1.5, mr: 2,
            background: 'linear-gradient(135deg, #ff6b35, #ff8c42)',
            display: 'flex', alignItems: 'center',
          }}>
            <ShieldIcon sx={{ color: '#fff', fontSize: 22 }} />
          </Box>
          <Typography variant="h6" component="div" sx={{ flexGrow: 1, fontWeight: 700, letterSpacing: 0.5 }}>
            CrabAV
            <Box component="span" sx={{ color: 'rgba(255,255,255,0.3)', fontWeight: 400, ml: 1, fontSize: '0.8rem' }}>
              Free Antivirus
            </Box>
          </Typography>
          
          {pendingThreats > 0 && (
            <Tooltip title={`${pendingThreats} threats pending approval`}>
              <Alert
                severity="warning"
                sx={{
                  mr: 2,
                  py: 0,
                  '& .MuiAlert-message': { padding: '8px 0' },
                }}
              >
                {pendingThreats}
              </Alert>
            </Tooltip>
          )}
          
          {scanInProgress && (
            <Box sx={{ width: 200, mr: 2 }}>
              <LinearProgress variant="determinate" value={scanProgress} />
            </Box>
          )}
        </Toolbar>
      </AppBar>
      
      {/* Sidebar */}
      <Sidebar
        drawerWidth={drawerWidth}
        drawerOpen={drawerOpen}
        isMobile={isMobile}
        pendingThreats={pendingThreats}
        onDrawerToggle={handleDrawerToggle}
      />
      
      {/* Main Content */}
      <Box
        component="main"
        sx={{
          flexGrow: 1,
          p: 3,
          width: { md: `calc(100% - ${drawerOpen ? drawerWidth : 0}px)` },
          ml: { md: drawerOpen ? 0 : `-${drawerWidth}px` },
          transition: theme.transitions.create(['width', 'margin'], {
            easing: theme.transitions.easing.sharp,
            duration: theme.transitions.duration.leavingScreen,
          }),
          height: '100vh',
          overflow: 'auto',
          pt: '64px',
          pb: '68px',
        }}
      >
        <Header systemStatus={systemStatus} onStartScan={startScan} />
        
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/threats" element={<Threats />} />
          <Route path="/scans" element={<Scans />} />
          <Route path="/settings" element={<Settings />} />
        </Routes>
      </Box>
      
      {/* Status Bar */}
      <StatusBar systemStatus={systemStatus} agentsActive={agentsActive} />
    </Box>
  );
}

export default App;
