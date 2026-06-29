import React from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  Drawer, List, ListItem, ListItemButton, ListItemIcon, ListItemText,
  Box, Divider, Typography, Chip,
} from '@mui/material';
import {
  Dashboard as DashboardIcon,
  BugReport as ThreatsIcon,
  Search as ScansIcon,
  Settings as SettingsIcon,
  Shield as ShieldIcon,
} from '@mui/icons-material';

const menuItems = [
  { text: 'Dashboard', icon: <DashboardIcon />, path: '/' },
  { text: 'Threats', icon: <ThreatsIcon />, path: '/threats' },
  { text: 'Scans', icon: <ScansIcon />, path: '/scans' },
  { text: 'Settings', icon: <SettingsIcon />, path: '/settings' },
];

function Sidebar({ drawerWidth, drawerOpen, isMobile, pendingThreats, onDrawerToggle }) {
  const navigate = useNavigate();
  const location = useLocation();

  const handleNavigation = (path) => {
    navigate(path);
    if (isMobile) onDrawerToggle();
  };

  const drawerContent = (
    <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <Box sx={{ p: 3, display: 'flex', alignItems: 'center', gap: 2 }}>
        <Box sx={{
          p: 1.2, borderRadius: 2,
          background: 'linear-gradient(135deg, #ff6b35, #ff8c42)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          <ShieldIcon sx={{ fontSize: 28, color: '#fff' }} />
        </Box>
        <Box>
          <Typography variant="h6" sx={{ fontWeight: 800, color: '#fff', letterSpacing: 1 }}>
            CrabAV
          </Typography>
          <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.4)', fontWeight: 600 }}>
            v0.1.0
          </Typography>
        </Box>
      </Box>

      <Divider sx={{ borderColor: 'rgba(255,255,255,0.06)' }} />

      <List sx={{ px: 2, pt: 2 }}>
        {menuItems.map((item) => {
          const isActive = location.pathname === item.path;
          const showBadge = item.text === 'Threats' && pendingThreats > 0;

          return (
            <ListItem key={item.text} disablePadding sx={{ mb: 0.8 }}>
              <ListItemButton
                onClick={() => handleNavigation(item.path)}
                sx={{
                  borderRadius: 2.5, py: 1.3,
                  background: isActive ? 'linear-gradient(135deg, rgba(0,212,255,0.2), rgba(0,150,255,0.1))' : 'transparent',
                  border: isActive ? '1px solid rgba(0,212,255,0.25)' : '1px solid transparent',
                  transition: 'all 0.2s ease',
                  '&:hover': {
                    background: isActive
                      ? 'linear-gradient(135deg, rgba(0,212,255,0.25), rgba(0,150,255,0.15))'
                      : 'rgba(255,255,255,0.04)',
                  },
                }}
              >
                <ListItemIcon sx={{
                  minWidth: 40,
                  color: isActive ? '#00d4ff' : 'rgba(255,255,255,0.4)',
                }}>
                  {item.icon}
                </ListItemIcon>
                <ListItemText
                  primary={item.text}
                  primaryTypographyProps={{
                    fontWeight: isActive ? 700 : 500,
                    fontSize: '0.95rem',
                    color: isActive ? '#fff' : 'rgba(255,255,255,0.6)',
                  }}
                />
                {showBadge && (
                  <Chip label={pendingThreats} color="warning" size="small"
                    sx={{ fontWeight: 700, borderRadius: 1.5 }} />
                )}
              </ListItemButton>
            </ListItem>
          );
        })}
      </List>

      <Box sx={{ flexGrow: 1 }} />

      <Divider sx={{ borderColor: 'rgba(255,255,255,0.06)' }} />
      <Box sx={{ p: 2.5 }}>
        <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.25)', fontStyle: 'italic' }}>
          🦀 Powered by Súp Cua AI
        </Typography>
      </Box>
    </Box>
  );

  return (
    <Drawer
      variant={isMobile ? 'temporary' : 'persistent'}
      open={drawerOpen}
      onClose={onDrawerToggle}
      sx={{
        width: drawerWidth, flexShrink: 0,
        '& .MuiDrawer-paper': {
          width: drawerWidth, boxSizing: 'border-box',
          background: 'linear-gradient(180deg, #0d0d1a 0%, #12122a 100%)',
          borderRight: '1px solid rgba(255,255,255,0.06)',
        },
      }}
      ModalProps={{ keepMounted: true }}
    >
      {drawerContent}
    </Drawer>
  );
}

export default Sidebar;
