import React, { useState, useEffect } from 'react';
import {
  Box,
  Button,
  Typography,
  Card,
  CardContent,
  Stack,
  Chip,
  Paper,
  LinearProgress,
  Divider,
  TableContainer,
  Table,
  TableHead,
  TableBody,
  TableRow,
  TableCell,
} from '@mui/material';
import {
  PlayArrow as PlayIcon,
  Stop as StopIcon,
  History as HistoryIcon,
  FolderOpen as FolderIcon,
} from '@mui/icons-material';

function Scans() {
  const [scanHistory, setScanHistory] = useState([]);
  const [currentScan, setCurrentScan] = useState(null);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanStatus, setScanStatus] = useState('idle');

  useEffect(() => {
    if (window.electronAPI) {
      // Load scan history
      // window.electronAPI.getScanHistory().then(setScanHistory);

      // Setup listeners
      window.electronAPI.onScanProgress((data) => {
        setScanProgress(data.progress);
      });

      window.electronAPI.onScanComplete((data) => {
        setScanStatus('completed');
        setCurrentScan(null);
        // window.electronAPI.getScanHistory().then(setScanHistory);
      });
    }
  }, []);

  const startScan = async (scanType) => {
    if (window.electronAPI) {
      setScanStatus('running');
      setScanProgress(0);
      const result = await window.electronAPI.startScan(scanType);
      if (result.success) {
        setCurrentScan({
          type: scanType,
          startTime: new Date(),
          status: 'running',
        });
      }
    }
  };

  const stopScan = async () => {
    if (window.electronAPI && currentScan) {
      await window.electronAPI.stopScan(currentScan.id);
      setScanStatus('stopped');
      setCurrentScan(null);
    }
  };

  const scanTypes = [
    { id: 'quick', name: 'Quick Scan', desc: 'Scans common threat locations', duration: '2-5 min' },
    { id: 'full', name: 'Full Scan', desc: 'Scans entire system', duration: '15-30 min' },
    { id: 'custom', name: 'Custom Scan', desc: 'Select files/folders to scan', duration: 'Varies' },
  ];

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 4, fontWeight: 'bold' }}>
        Scans
      </Typography>

      {/* Scan Types */}
      <Stack direction="row" spacing={2} sx={{ mb: 4 }}>
        <Button
          variant="contained"
          color="primary"
          size="large"
          startIcon={<PlayIcon />}
          onClick={() => startScan('quick')}
          disabled={scanStatus === 'running'}
        >
          Quick Scan
        </Button>
        <Button
          variant="contained"
          color="secondary"
          size="large"
          startIcon={<PlayIcon />}
          onClick={() => startScan('full')}
          disabled={scanStatus === 'running'}
        >
          Full Scan
        </Button>
        <Button
          variant="contained"
          color="warning"
          size="large"
          startIcon={<PlayIcon />}
          onClick={() => startScan('custom')}
          disabled={scanStatus === 'running'}
        >
          Custom Scan
        </Button>
      </Stack>

      {/* Current Scan Status */}
      {currentScan && scanStatus === 'running' && (
        <Card sx={{ mb: 4, border: '2px solid', borderColor: 'primary.main' }}>
          <CardContent>
            <Stack direction="row" alignItems="center" spacing={2} sx={{ mb: 2 }}>
              <PlayIcon color="primary" />
              <Typography variant="h5">Scanning in progress...</Typography>
            </Stack>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
              {currentScan.type} scan is running
            </Typography>
            <LinearProgress variant="determinate" value={scanProgress} sx={{ mb: 2 }} />
            <Stack direction="row" spacing={2} alignItems="center">
              <Typography variant="body2" color="text.secondary">
                {Math.round(scanProgress)}% completed
              </Typography>
              <Button
                variant="outlined"
                color="error"
                size="small"
                startIcon={<StopIcon />}
                onClick={stopScan}
              >
                Stop
              </Button>
            </Stack>
          </CardContent>
        </Card>
      )}

      {/* Scan Types Info */}
      <Typography variant="h5" sx={{ mb: 2, fontWeight: 'bold' }}>
        Available Scan Types
      </Typography>
      <Stack spacing={2}>
        {scanTypes.map((scanType) => (
          <Card key={scanType.id}>
            <CardContent>
              <Stack direction="row" alignItems="center" spacing={2}>
                <FolderIcon color="primary" />
                <Box sx={{ flex: 1 }}>
                  <Typography variant="h6">{scanType.name}</Typography>
                  <Typography variant="body2" color="text.secondary">
                    {scanType.desc}
                  </Typography>
                </Box>
                <Chip label={scanType.duration} size="small" color="info" />
              </Stack>
            </CardContent>
          </Card>
        ))}
      </Stack>

      {/* Scan History */}
      <Typography variant="h5" sx={{ mb: 2, fontWeight: 'bold', mt: 4 }}>
        Recent Scans
      </Typography>
      <Card>
        <CardContent>
          {scanHistory.length === 0 ? (
            <Typography variant="body2" color="text.secondary">
              No scan history yet. Run a scan to see results.
            </Typography>
          ) : (
            <TableContainer component={Paper}>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Time</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Files Scanned</TableCell>
                    <TableCell>Threats</TableCell>
                    <TableCell>Status</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {scanHistory.map((scan) => (
                    <TableRow key={scan.id}>
                      <TableCell>{new Date(scan.startTime).toLocaleString()}</TableCell>
                      <TableCell>{scan.type}</TableCell>
                      <TableCell>{scan.filesScanned}</TableCell>
                      <TableCell>{scan.threatsFound}</TableCell>
                      <TableCell>
                        <Chip
                          label={scan.status}
                          color={scan.status === 'completed' ? 'success' : 'warning'}
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
