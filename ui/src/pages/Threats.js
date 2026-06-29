import React, { useState, useEffect, useCallback } from 'react';
import {
  Box, Table, TableBody, TableCell, TableContainer, TableHead,
  TableRow, Paper, Chip, Button, Dialog, DialogTitle, DialogContent,
  DialogActions, Typography, Stack, Alert,
} from '@mui/material';
import {
  Delete as DeleteIcon,
  CheckCircle as CheckIcon,
  Visibility as VisibilityIcon,
  Shield as ShieldIcon,
  BugReport,
} from '@mui/icons-material';
import api from '../api';

function Threats() {
  const [threats, setThreats] = useState([]);
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [dialogOpen, setDialogOpen] = useState(false);

  const loadThreats = useCallback(async () => {
    try {
      const data = await api.getThreats();
      setThreats(data || []);
    } catch (e) { console.error('Failed to load threats:', e); }
  }, []);

  useEffect(() => { loadThreats(); }, [loadThreats]);

  const getStatusColor = (status) => {
    switch (status) {
      case 'pending': return 'warning';
      case 'quarantined': return 'primary';
      case 'deleted': return 'error';
      case 'whitelisted': return 'success';
      default: return 'default';
    }
  };

  const handleViewDetail = (threat) => { setSelectedThreat(threat); setDialogOpen(true); };

  const handleApproveAction = async (action) => {
    if (!selectedThreat) return;
    try {
      await api.approveAction(selectedThreat.id, action);
      setDialogOpen(false);
      loadThreats();
    } catch (e) {
      alert('Failed to execute action: ' + e.message);
    }
  };

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 1, fontWeight: 800, color: '#fff' }}>Threat Center</Typography>
      <Typography variant="body2" sx={{ mb: 4, color: 'rgba(255,255,255,0.5)' }}>
        Review and manage detected threats
      </Typography>

      {threats.length === 0 ? (
        <Box sx={{
          p: 6, textAlign: 'center', borderRadius: 3,
          background: 'rgba(0,255,136,0.05)', border: '1px solid rgba(0,255,136,0.15)',
        }}>
          <ShieldIcon sx={{ fontSize: 64, color: '#00ff88', mb: 2, opacity: 0.6 }} />
          <Typography variant="h5" sx={{ color: '#00ff88', fontWeight: 700, mb: 1 }}>
            All Clear!
          </Typography>
          <Typography variant="body1" sx={{ color: 'rgba(255,255,255,0.4)' }}>
            No threats detected. Run a scan to check your system.
          </Typography>
        </Box>
      ) : (
        <TableContainer component={Paper} sx={{
          borderRadius: 3, background: 'rgba(20,20,20,0.8)',
          border: '1px solid rgba(255,255,255,0.06)',
        }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ '& th': { color: 'rgba(255,255,255,0.4)', borderColor: 'rgba(255,255,255,0.06)', fontWeight: 600, fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: 1 } }}>
                <TableCell>Threat Name</TableCell>
                <TableCell>File Path</TableCell>
                <TableCell>Risk</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {threats.map((threat) => (
                <TableRow key={threat.id}
                  sx={{
                    '& td': { color: '#fff', borderColor: 'rgba(255,255,255,0.04)' },
                    transition: 'background 0.2s',
                    '&:hover': { background: 'rgba(255,255,255,0.02)' },
                    background: threat.status === 'pending' ? 'rgba(255,152,0,0.05)' : 'transparent',
                  }}>
                  <TableCell sx={{ fontWeight: 600 }}>
                    <Stack direction="row" spacing={1} alignItems="center">
                      <BugReport sx={{ fontSize: 18, color: '#ff6b35' }} />
                      {threat.threat_name}
                    </Stack>
                  </TableCell>
                  <TableCell sx={{ maxWidth: 250, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'rgba(255,255,255,0.6) !important', fontSize: '0.8rem' }}>
                    {threat.file_path}
                  </TableCell>
                  <TableCell>
                    <Chip size="small" label={`${threat.risk_score}%`}
                      sx={{
                        borderRadius: 1, fontWeight: 700,
                        background: threat.risk_score > 70 ? 'rgba(255,0,0,0.12)' : threat.risk_score > 40 ? 'rgba(255,193,7,0.12)' : 'rgba(0,212,255,0.1)',
                        color: threat.risk_score > 70 ? '#ff4444' : threat.risk_score > 40 ? '#ffc107' : '#00d4ff',
                      }}
                    />
                  </TableCell>
                  <TableCell>
                    <Chip size="small" label={threat.status}
                      sx={{
                        borderRadius: 1, fontWeight: 600, textTransform: 'capitalize',
                        background: threat.status === 'pending' ? 'rgba(255,193,7,0.12)' :
                          threat.status === 'quarantined' ? 'rgba(0,212,255,0.12)' :
                          threat.status === 'deleted' ? 'rgba(255,0,0,0.12)' : 'rgba(0,255,136,0.12)',
                        color: threat.status === 'pending' ? '#ffc107' :
                          threat.status === 'quarantined' ? '#00d4ff' :
                          threat.status === 'deleted' ? '#ff4444' : '#00ff88',
                      }}
                    />
                  </TableCell>
                  <TableCell>
                    <Button size="small" startIcon={<VisibilityIcon />}
                      onClick={() => handleViewDetail(threat)}
                      sx={{ color: '#00d4ff', '&:hover': { background: 'rgba(0,212,255,0.08)' } }}>
                      View
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      <Dialog open={dialogOpen} onClose={() => setDialogOpen(false)} maxWidth="md" fullWidth
        PaperProps={{ sx: { borderRadius: 3, background: '#1a1a2e', border: '1px solid rgba(255,255,255,0.08)' } }}>
        {selectedThreat && (
          <>
            <DialogTitle sx={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
              <Stack direction="row" alignItems="center" gap={2}>
                <ShieldIcon sx={{ color: '#ff6b35', fontSize: 32 }} />
                <Typography variant="h5" sx={{ color: '#fff', fontWeight: 700 }}>{selectedThreat.threat_name}</Typography>
              </Stack>
            </DialogTitle>
            <DialogContent sx={{ pt: 3 }}>
              <Stack spacing={2}>
                <Box>
                  <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.4)', textTransform: 'uppercase', letterSpacing: 1 }}>File Path</Typography>
                  <Typography sx={{ color: '#fff', fontWeight: 500, wordBreak: 'break-all' }}>{selectedThreat.file_path}</Typography>
                </Box>
                <Box>
                  <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.4)', textTransform: 'uppercase', letterSpacing: 1 }}>Risk Score</Typography>
                  <Chip label={`${selectedThreat.risk_score}/100`}
                    sx={{
                      mt: 0.5, fontWeight: 700,
                      background: selectedThreat.risk_score > 70 ? 'rgba(255,0,0,0.12)' : 'rgba(255,193,7,0.12)',
                      color: selectedThreat.risk_score > 70 ? '#ff4444' : '#ffc107',
                    }}
                  />
                </Box>
                <Box>
                  <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.4)', textTransform: 'uppercase', letterSpacing: 1 }}>Detected By</Typography>
                  <Typography sx={{ color: '#fff' }}>
                    {(() => { try { return JSON.parse(selectedThreat.detected_by).join(', '); } catch { return selectedThreat.detected_by; } })()}
                  </Typography>
                </Box>
                <Alert severity="warning" sx={{ borderRadius: 2, background: 'rgba(255,152,0,0.08)', color: '#ffc107', border: '1px solid rgba(255,152,0,0.2)' }}>
                  This file has been flagged by multiple agents. Proceed with caution.
                </Alert>
              </Stack>
            </DialogContent>
            <DialogActions sx={{ p: 2, borderTop: '1px solid rgba(255,255,255,0.06)' }}>
              <Button onClick={() => setDialogOpen(false)} sx={{ color: 'rgba(255,255,255,0.5)' }}>Close</Button>
              <Button onClick={() => handleApproveAction('quarantine')}
                variant="contained" startIcon={<ShieldIcon />}
                sx={{ borderRadius: 2, background: 'linear-gradient(135deg, #00d4ff, #0099cc)' }}>
                Quarantine
              </Button>
              <Button onClick={() => handleApproveAction('delete')}
                variant="contained" startIcon={<DeleteIcon />}
                sx={{ borderRadius: 2, background: 'linear-gradient(135deg, #ff4444, #cc0000)' }}>
                Delete
              </Button>
              <Button onClick={() => handleApproveAction('whitelist')}
                variant="outlined" startIcon={<CheckIcon />}
                sx={{ borderRadius: 2, borderColor: '#00ff88', color: '#00ff88' }}>
                Whitelist
              </Button>
            </DialogActions>
          </>
        )}
      </Dialog>
    </Box>
  );
}

export default Threats;
