import React, { useState, useEffect, useCallback } from 'react';
import {
  Box, Button, Typography, Card, CardContent, Stack, Chip, Grid,
  TableContainer, Table, TableHead, TableBody, TableRow, TableCell,
  Paper, LinearProgress, keyframes,
} from '@mui/material';
import {
  PlayArrow, Stop, FolderOpen, Speed, Shield, Search,
} from '@mui/icons-material';
import api from '../api';

const pulse = keyframes`
  0% { box-shadow: 0 0 0 0 rgba(0,212,255,0.4); }
  70% { box-shadow: 0 0 0 15px rgba(0,212,255,0); }
  100% { box-shadow: 0 0 0 0 rgba(0,212,255,0); }
`;

const progressShimmer = keyframes`
  0% { background-position: -200% center; }
  100% { background-position: 200% center; }
`;

function Scans() {
  const [scanHistory, setScanHistory] = useState([]);
  const [currentScan, setCurrentScan] = useState(null);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanStatus, setScanStatus] = useState('idle');

  const loadHistory = useCallback(async () => {
    try {
      const history = await api.getScanHistory();
      setScanHistory(history || []);
    } catch (e) {
      console.error('Failed to load scan history:', e);
    }
  }, []);

  useEffect(() => { loadHistory(); }, [loadHistory]);

  const startScan = async (scanType) => {
    try {
      setScanStatus('running');
      setScanProgress(0);
      const result = await api.startScan(scanType);
      if (result.success) {
        setCurrentScan({ id: result.scan_id, type: scanType });
        const poll = setInterval(async () => {
          try {
            const s = await api.getScanStatus(result.scan_id);
            if (s.status === 'running') {
              setScanProgress(s.progress || Math.min(scanProgress + 5, 90));
            } else {
              clearInterval(poll);
              setScanStatus('completed');
              setScanProgress(100);
              setCurrentScan(null);
              setTimeout(() => { setScanStatus('idle'); setScanProgress(0); }, 2000);
              loadHistory();
            }
          } catch { clearInterval(poll); }
        }, 800);
      }
    } catch (error) {
      console.error('Failed to start scan:', error);
      setScanStatus('idle');
      alert('Failed to start scan. Is the backend running?\nStart it: python -m uvicorn src.api_server:app --host 127.0.0.1 --port 19527');
    }
  };

  const stopScan = async () => {
    try {
      await api.stopScan();
      setScanStatus('stopped');
      setCurrentScan(null);
      loadHistory();
    } catch (e) {
      console.error('Failed to stop scan:', e);
    }
  };

  const scanTypes = [
    { id: 'quick', name: 'Quick Scan', desc: 'Scans common threat locations (Downloads, Desktop, Temp)', duration: '1-3 min', icon: <Speed />, color: '#00d4ff', gradient: 'linear-gradient(135deg, #00d4ff 0%, #0099cc 100%)' },
    { id: 'full', name: 'Full Scan', desc: 'Deep scan of entire user directory', duration: '5-15 min', icon: <Shield />, color: '#ff6b35', gradient: 'linear-gradient(135deg, #ff6b35 0%, #cc4400 100%)' },
    { id: 'custom', name: 'Custom Scan', desc: 'Select specific files or folders to scan', duration: 'Varies', icon: <FolderOpen />, color: '#a78bfa', gradient: 'linear-gradient(135deg, #a78bfa 0%, #7c3aed 100%)' },
  ];

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 1, fontWeight: 800, color: '#fff' }}>
        Scan Center
      </Typography>
      <Typography variant="body2" sx={{ mb: 4, color: 'rgba(255,255,255,0.5)' }}>
        Run security scans to detect threats on your system
      </Typography>

      {/* Current Scan Progress */}
      {currentScan && scanStatus === 'running' && (
        <Card sx={{
          mb: 4, borderRadius: 3, border: '2px solid rgba(0,212,255,0.3)',
          background: 'linear-gradient(135deg, rgba(0,212,255,0.08) 0%, rgba(0,0,0,0.4) 100%)',
          animation: `${pulse} 2s infinite`,
        }}>
          <CardContent sx={{ p: 4 }}>
            <Stack direction="row" alignItems="center" spacing={3} sx={{ mb: 3 }}>
              <Box sx={{
                p: 2, borderRadius: '50%', background: 'rgba(0,212,255,0.15)',
                animation: `${pulse} 1.5s infinite`,
              }}>
                <Search sx={{ fontSize: 32, color: '#00d4ff' }} />
              </Box>
              <Box flex={1}>
                <Typography variant="h5" sx={{ fontWeight: 700, color: '#fff' }}>
                  Scanning in progress...
                </Typography>
                <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.5)' }}>
                  {currentScan.type} scan • Please wait
                </Typography>
              </Box>
              <Button variant="outlined" color="error" size="large" startIcon={<Stop />}
                onClick={stopScan}
                sx={{ borderRadius: 2, borderColor: 'rgba(255,0,0,0.3)' }}>
                Stop
              </Button>
            </Stack>
            <LinearProgress
              variant="determinate" value={scanProgress}
              sx={{
                height: 8, borderRadius: 4,
                background: 'rgba(255,255,255,0.05)',
                '& .MuiLinearProgress-bar': {
                  borderRadius: 4,
                  background: 'linear-gradient(90deg, #00d4ff, #00ff88, #00d4ff)',
                  backgroundSize: '200% 100%',
                  animation: `${progressShimmer} 2s linear infinite`,
                },
              }}
            />
            <Typography variant="body2" sx={{ mt: 1, color: '#00d4ff', fontWeight: 600, textAlign: 'right' }}>
              {Math.round(scanProgress)}%
            </Typography>
          </CardContent>
        </Card>
      )}

      {/* Scan Buttons */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        {scanTypes.map((st) => (
          <Grid item xs={12} md={4} key={st.id}>
            <Card sx={{
              borderRadius: 3, background: 'rgba(20,20,20,0.8)',
              border: '1px solid rgba(255,255,255,0.06)',
              transition: 'all 0.3s ease',
              '&:hover': { borderColor: st.color, transform: 'translateY(-2px)' },
            }}>
              <CardContent sx={{ p: 3 }}>
                <Stack spacing={2}>
                  <Box sx={{ p: 1.5, borderRadius: 2, background: `${st.color}20`, color: st.color, width: 'fit-content' }}>
                    {React.cloneElement(st.icon, { sx: { fontSize: 32 } })}
                  </Box>
                  <Box>
                    <Typography variant="h6" sx={{ fontWeight: 700, color: '#fff' }}>{st.name}</Typography>
                    <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.5)', mb: 1 }}>{st.desc}</Typography>
                    <Chip label={st.duration} size="small" sx={{
                      background: `${st.color}15`, color: st.color, borderRadius: 1, fontWeight: 600,
                    }} />
                  </Box>
                  <Button
                    variant="contained" fullWidth size="large"
                    startIcon={<PlayArrow />}
                    onClick={() => startScan(st.id)}
                    disabled={scanStatus === 'running'}
                    sx={{
                      mt: 'auto !important', borderRadius: 2, py: 1.2,
                      background: st.gradient, fontWeight: 700,
                      '&:disabled': { background: 'rgba(255,255,255,0.08)', color: 'rgba(255,255,255,0.2)' },
                    }}>
                    Start {st.name}
                  </Button>
                </Stack>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>

      {/* Scan History */}
      <Typography variant="h6" sx={{ mb: 2, mt: 4, fontWeight: 700, color: '#fff' }}>Recent Scans</Typography>
      <Card sx={{ borderRadius: 3, background: 'rgba(20,20,20,0.8)', border: '1px solid rgba(255,255,255,0.06)' }}>
        <CardContent sx={{ p: 0 }}>
          {scanHistory.length === 0 ? (
            <Box sx={{ p: 4, textAlign: 'center' }}>
              <Search sx={{ fontSize: 48, color: 'rgba(255,255,255,0.1)', mb: 2 }} />
              <Typography variant="body1" sx={{ color: 'rgba(255,255,255,0.3)' }}>
                No scan history yet. Run your first scan!
              </Typography>
            </Box>
          ) : (
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ '& th': { color: 'rgba(255,255,255,0.4)', borderColor: 'rgba(255,255,255,0.06)', fontWeight: 600, fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: 1 } }}>
                    <TableCell>Time</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Files</TableCell>
                    <TableCell>Threats</TableCell>
                    <TableCell>Status</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {scanHistory.map((scan) => (
                    <TableRow key={scan.id}
                      sx={{
                        '& td': { color: '#fff', borderColor: 'rgba(255,255,255,0.04)' },
                        transition: 'background 0.2s',
                        '&:hover': { background: 'rgba(255,255,255,0.02)' },
                      }}>
                      <TableCell sx={{ color: 'rgba(255,255,255,0.6) !important', fontSize: '0.8rem' }}>
                        {new Date(scan.started_at).toLocaleString()}
                      </TableCell>
                      <TableCell>
                        <Chip label={scan.scan_type} size="small" sx={{
                          textTransform: 'capitalize', borderRadius: 1,
                          background: 'rgba(0,212,255,0.1)', color: '#00d4ff', fontWeight: 600,
                        }} />
                      </TableCell>
                      <TableCell sx={{ fontWeight: 600 }}>{scan.files_scanned}</TableCell>
                      <TableCell>
                        <Chip label={scan.threats_found} size="small" sx={{
                          borderRadius: 1, fontWeight: 700,
                          background: scan.threats_found > 0 ? 'rgba(255,107,53,0.15)' : 'rgba(0,255,136,0.1)',
                          color: scan.threats_found > 0 ? '#ff6b35' : '#00ff88',
                        }} />
                      </TableCell>
                      <TableCell>
                        <Chip size="small" label={scan.status}
                          sx={{
                            borderRadius: 1, fontWeight: 600, fontSize: '0.7rem',
                            background: scan.status === 'completed' ? 'rgba(0,255,136,0.12)' :
                              scan.status === 'failed' ? 'rgba(255,0,0,0.12)' : 'rgba(255,193,7,0.12)',
                            color: scan.status === 'completed' ? '#00ff88' :
                              scan.status === 'failed' ? '#ff4444' : '#ffc107',
                          }}
                        />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </CardContent>
      </Card>
    </Box>
  );
}

export default Scans;
