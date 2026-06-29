import React, { useState, useEffect } from 'react';
import {
  Box,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Typography,
  Stack,
  Alert,
} from '@mui/material';
import {
  PlayArrow as PlayIcon,
  Delete as DeleteIcon,
  CheckCircle as CheckIcon,
  Visibility as VisibilityIcon,
  Shield as ShieldIcon,
} from '@mui/icons-material';

function Threats() {
  const [threats, setThreats] = useState([]);
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [dialogOpen, setDialogOpen] = useState(false);

  useEffect(() => {
    // Load threats
    if (window.electronAPI) {
      window.electronAPI.getThreats().then((data) => {
        setThreats(data);
      });
    }
  }, []);

  const getStatusColor = (status) => {
    switch (status) {
      case 'pending':
        return 'warning';
      case 'quarantined':
        return 'primary';
      case 'deleted':
        return 'error';
      case 'whitelisted':
        return 'success';
      default:
        return 'default';
    }
  };

  const handleViewDetail = (threat) => {
    setSelectedThreat(threat);
    setDialogOpen(true);
  };

  const handleApproveAction = (action) => {
    if (window.electronAPI && selectedThreat) {
      window.electronAPI
        .approveAction(selectedThreat.id, action)
        .then(() => {
          // Refresh threats list
          window.electronAPI.getThreats().then((data) => {
            setThreats(data);
            setDialogOpen(false);
          });
        });
    }
  };

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 4, fontWeight: 'bold' }}>
        Threats
      </Typography>

      {threats.length === 0 ? (
        <Alert severity="success">
          No threats found! Your system is clean.
        </Alert>
      ) : (
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Threat Name</TableCell>
                <TableCell>File Path</TableCell>
                <TableCell>Risk</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {threats.map((threat) => (
                <TableRow
                  key={threat.id}
                  sx={{
                    backgroundColor: threat.status === 'pending' ? '#333' : 'transparent',
                  }}
                >
                  <TableCell>{threat.name}</TableCell>
                  <TableCell>{threat.path}</TableCell>
                  <TableCell>
                    <Chip
                      label={`${threat.risk}%`}
                      color={threat.risk > 70 ? 'error' : threat.risk > 40 ? 'warning' : 'info'}
                    />
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={threat.status}
                      color={getStatusColor(threat.status)}
                    />
                  </TableCell>
                  <TableCell>
                    <Button
                      size="small"
                      startIcon={<VisibilityIcon />}
                      onClick={() => handleViewDetail(threat)}
                    >
                      View
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      {/* Threat Detail Dialog */}
      <Dialog
        open={dialogOpen}
        onClose={() => setDialogOpen(false)}
        maxWidth="md"
        fullWidth
      >
        {selectedThreat && (
          <>
            <DialogTitle>
              <Stack direction="row" alignItems="center" gap={2}>
                <ShieldIcon sx={{ color: 'error.main' }} />
                <Typography variant="h5">{selectedThreat.name}</Typography>
              </Stack>
            </DialogTitle>
            <DialogContent>
              <Typography sx={{ mb: 2 }}>
                <strong>File Path:</strong> {selectedThreat.path}
              </Typography>
              <Typography sx={{ mb: 2 }}>
                <strong>Risk Score:</strong> {selectedThreat.risk}/100
              </Typography>
              <Typography sx={{ mb: 2 }}>
                <strong>Detected by:</strong> {selectedThreat.detectedBy.join(', ')}
              </Typography>
              <Typography sx={{ mb: 2 }}>
                <strong>Confidence:</strong> {selectedThreat.confidence * 100}%
              </Typography>
              <Typography sx={{ mb: 2 }}>
                <strong>Evidence:</strong>
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ ml: 2, mb: 2 }}>
                {selectedThreat.evidence}
              </Typography>
              <Alert severity="warning" sx={{ mt: 2 }}>
                This file has been flagged by multiple agents. Proceed with caution.
              </Alert>
            </DialogContent>
            <DialogActions>
              <Button onClick={() => setDialogOpen(false)}>Close</Button>
              <Button
                onClick={() => handleApproveAction('quarantine')}
                variant="contained"
                startIcon={<ShieldIcon />}
                color="primary"
              >
                Quarantine
              </Button>
              <Button
                onClick={() => handleApproveAction('delete')}
                variant="contained"
                startIcon={<DeleteIcon />}
                color="error"
              >
                Delete
              </Button>
              <Button
                onClick={() => handleApproveAction('whitelist')}
                variant="outlined"
                startIcon={<CheckIcon />}
                color="success"
              >
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
