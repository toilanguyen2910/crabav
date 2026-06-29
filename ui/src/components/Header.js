import React from 'react';
import { Box, Button, Card, CardContent, Typography, Chip, keyframes } from '@mui/material';
import { PlayArrow, Search, FolderOpen, Shield } from '@mui/icons-material';

const glow = keyframes`
  0%, 100% { box-shadow: 0 0 5px rgba(0,212,255,0.3); }
  50% { box-shadow: 0 0 20px rgba(0,212,255,0.6); }
`;

function Header({ systemStatus, onStartScan }) {
  const getStatusConfig = (status) => {
    switch (status) {
      case 'protected': return { icon: '🛡️', text: 'Protected', color: '#00ff88', bg: 'rgba(0,255,136,0.08)', border: 'rgba(0,255,136,0.2)' };
      case 'warning': return { icon: '⚠️', text: 'Attention Needed', color: '#ffc107', bg: 'rgba(255,193,7,0.08)', border: 'rgba(255,193,7,0.2)' };
      case 'danger': return { icon: '🚨', text: 'At Risk', color: '#ff4444', bg: 'rgba(255,68,68,0.08)', border: 'rgba(255,68,68,0.2)' };
      case 'loading': return { icon: '⏳', text: 'Loading...', color: '#00d4ff', bg: 'rgba(0,212,255,0.08)', border: 'rgba(0,212,255,0.2)' };
      default: return { icon: '❓', text: 'Unknown', color: '#888', bg: 'rgba(255,255,255,0.04)', border: 'rgba(255,255,255,0.1)' };
    }
  };

  const sc = getStatusConfig(systemStatus);

  return (
    <Box sx={{ mb: 4 }}>
      <Card sx={{
        mb: 3, borderRadius: 3,
        background: 'linear-gradient(135deg, rgba(15,12,41,0.9) 0%, rgba(48,43,99,0.8) 50%, rgba(36,36,62,0.9) 100%)',
        border: '1px solid rgba(255,255,255,0.08)', backdropFilter: 'blur(20px)',
      }}>
        <CardContent sx={{ p: 3 }}>
          <Box sx={{
            display: 'flex', justifyContent: 'space-between', alignItems: 'center',
            flexWrap: 'wrap', gap: 2,
          }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
              <Box sx={{
                p: 1.2, borderRadius: 2, background: sc.bg, border: `1px solid ${sc.border}`,
                animation: systemStatus === 'protected' ? `${glow} 3s ease-in-out infinite` : 'none',
              }}>
                <Shield sx={{ color: sc.color, fontSize: 28 }} />
              </Box>
              <Box>
                <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.4)', textTransform: 'uppercase', letterSpacing: 1, fontSize: '0.7rem', fontWeight: 600 }}>
                  System Status
                </Typography>
                <Typography variant="h6" sx={{ color: '#fff', fontWeight: 700 }}>
                  {sc.icon} {sc.text}
                </Typography>
              </Box>
            </Box>

            <Box sx={{ display: 'flex', gap: 1.5 }}>
              <Button
                variant="contained" size="large" startIcon={<PlayArrow />}
                onClick={() => onStartScan('quick')}
                sx={{
                  borderRadius: 2.5, px: 3, fontWeight: 700,
                  background: 'linear-gradient(135deg, #ff6b35, #ff8c42)',
                  '&:hover': { background: 'linear-gradient(135deg, #ff8c42, #ff6b35)' },
                }}>
                Quick Scan
              </Button>
              <Button
                variant="outlined" size="large" startIcon={<Search />}
                onClick={() => onStartScan('full')}
                sx={{
                  borderRadius: 2.5, px: 3, fontWeight: 600,
                  borderColor: 'rgba(255,255,255,0.15)', color: 'rgba(255,255,255,0.7)',
                  '&:hover': { borderColor: 'rgba(255,255,255,0.3)', background: 'rgba(255,255,255,0.04)' },
                }}>
                Full Scan
              </Button>
              <Button
                variant="outlined" size="large" startIcon={<FolderOpen />}
                onClick={() => onStartScan('custom')}
                sx={{
                  borderRadius: 2.5, px: 3, fontWeight: 600,
                  borderColor: 'rgba(255,255,255,0.15)', color: 'rgba(255,255,255,0.7)',
                  '&:hover': { borderColor: 'rgba(255,255,255,0.3)', background: 'rgba(255,255,255,0.04)' },
                }}>
                Custom
              </Button>
            </Box>
          </Box>
        </CardContent>
      </Card>
    </Box>
  );
}

export default Header;
