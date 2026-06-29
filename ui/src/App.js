import React, { useState, useEffect } from 'react';
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

function App() {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  const [drawerOpen, setDrawerOpen] = useState(!isMobile);
  const [systemStatus, setSystemStatus] = useState('loading');
  const [scanInProgress, setScanInProgress] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [pendingThreats, setPendingThreats] = useState(0);

  useEffect(() => {
    // Load initial data
    loadSystemStatus();
    loadPendingThreats();
    
    // Setup IPC listeners
    if (window.electronAPI) {
      window.electronAPI.onScanProgress((data) => {
        setScanProgress(data.progress);
      });
      
      window.electronAPI.onThreatDetected((data) => {
        setPendingThreats(prev => prev + 1);
      });
      
      window.electronAPI.onScanComplete(() => {
        setScanInProgress(false);
        setScanProgress(0);
      });
    }
    
    return () => {
      if (window.electronAPI) {
        window.electronAPI.removeAllListeners('scan-progress');
        window.electronAPI.removeAllListeners('threat-detected');
        window.electronAPI.removeAllListeners('scan-complete');
      }
    };
  }, []);

  const loadSystemStatus = async () => {
    try {
      if (window.electronAPI) {
        const status = await window.electronAPI.getSystemStatus();
        setSystemStatus(status);
      }
    } catch (error) {
      console.error('Failed to load system status:', error);
    }
  };

  const loadPendingThreats = async () => {
    try {
      if (window.electronAPI) {
        const threats = await window.electronAPI.getThreats();
        const pending = threats.filter(t => t.status === 'pending').length;
        setPendingThreats(pending);
      }
    } catch (error) {
      console.error('Failed to load threats:', error);
    }
  };

  const handleDrawerToggle = () => {
    setDrawerOpen(!drawerOpen);
  };

  const startScan = async (scanType) => {
    try {
      if (window.electronAPI) {
        setScanInProgress(true);
        const result = await window.electronAPI.startScan(scanType);
        if (result.success) {
          // Scan started successfully
        }
      }
    } catch (error) {
      console.error('Failed to start scan:', error);
      setScanInProgress(false);
    }
  };

  const drawerWidth = 240;

  return (
    <Box sx={{ display: 'flex', height: '100vh', overflow: 'hidden' }}>
      <CssBaseline />
      
      {/* App Bar */}
      <AppBar
        position="fixed"
        sx={{
          zIndex: theme.zIndex.drawer + 1,
          backgroundColor: '#1a1a1a',
          borderBottom: `1px solid ${theme.palette.divider}`,
        }}
      >
        <Toolbar>
          <IconButton
            color="inherit"
            edge="start"
            onClick={handleDrawerToggle}
            sx={{ mr: 2 }}
          >
            <MenuIcon />
          </IconButton>
          
          <ShieldIcon sx={{ mr: 2, color: theme.palette.primary.main }} />
          
          <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
            CrabAV - Free Antivirus
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
          width: `calc(100% - ${drawerOpen ? drawerWidth : 0}px)`,
          transition: theme.transitions.create(['width', 'margin'], {
            easing: theme.transitions.easing.sharp,
            duration: theme.transitions.duration.leavingScreen,
          }),
          marginLeft: drawerOpen ? 0 : `-${drawerWidth}px`,
          height: '100vh',
          overflow: 'auto',
          pt: '64px', // AppBar height
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
      <StatusBar systemStatus={systemStatus} />
    </Box>
  );
}

export default App;
