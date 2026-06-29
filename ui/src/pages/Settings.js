import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Card,
  CardContent,
  Switch,
  FormGroup,
  FormControlLabel,
  Stack,
  TextField,
  Button,
  Divider,
  Alert,
} from '@mui/material';
import {
  Save as SaveIcon,
  Refresh as RefreshIcon,
  Shield as ShieldIcon,
} from '@mui/icons-material';

function Settings() {
  const [settings, setSettings] = useState({
    realTimeScan: true,
    autoUpdate: true,
    emailNotifications: false,
    quietHours: false,
    excludeDownloads: false,
    backupBeforeDelete: true,
  });
  const [showSaveAlert, setShowSaveAlert] = useState(false);

  useEffect(() => {
    // Load settings
    if (window.electronAPI) {
      window.electronAPI.getSettings().then((data) => {
        setSettings(data);
      });
    }
  }, []);

  const handleChange = (setting, value) => {
    setSettings((prev) => ({
      ...prev,
      [setting]: value,
    }));
  };

  const handleSave = async () => {
    if (window.electronAPI) {
      await window.electronAPI.updateSettings(settings);
      setShowSaveAlert(true);
      setTimeout(() => setShowSaveAlert(false), 3000);
    }
  };

  const handleResetDefaults = () => {
    setSettings({
      realTimeScan: true,
      autoUpdate: true,
      emailNotifications: false,
      quietHours: false,
      excludeDownloads: false,
      backupBeforeDelete: true,
    });
  };

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 4, fontWeight: 'bold' }}>
        Settings
      </Typography>

      {showSaveAlert && (
        <Alert severity="success" sx={{ mb: 2 }}>
          Settings saved successfully!
        </Alert>
      )}

      {/* Real-time Protection */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" sx={{ fontWeight: 'bold', mb: 2 }}>
            Real-time Protection
          </Typography>
          <Stack spacing={2}>
            <FormControlLabel
              control={
                <Switch
                  checked={settings.realTimeScan}
                  onChange={(e) => handleChange('realTimeScan', e.target.checked)}
                  color="primary"
                />
              }
              label="Enable real-time file scanning"
            />
            <FormControlLabel
              control={
                <Switch
                  checked={settings.autoUpdate}
                  onChange={(e) => handleChange('autoUpdate', e.target.checked)}
                  color="primary"
                />
              }
              label="Auto-update virus definitions (every 6 hours)"
            />
            <FormControlLabel
              control={
                <Switch
                  checked={settings.excludeDownloads}
                  onChange={(e) => handleChange('excludeDownloads', e.target.checked)}
                  color="primary"
                />
              }
              label="Exclude Downloads folder from real-time scanning"
            />
          </Stack>
        </CardContent>
      </Card>

      {/* Notifications */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" sx={{ fontWeight: 'bold', mb: 2 }}>
            Notifications
          </Typography>
          <Stack spacing={2}>
            <FormControlLabel
              control={
                <Switch
                  checked={settings.emailNotifications}
                  onChange={(e) => handleChange('emailNotifications', e.target.checked)}
                  color="primary"
                />
              }
              label="Email notifications for critical threats"
            />
            <FormControlLabel
              control={
                <Switch
                  checked={settings.quietHours}
                  onChange={(e) => handleChange('quietHours', e.target.checked)}
                  color="primary"
                />
              }
              label="Quiet hours (no notifications between 23:00-08:00)"
            />
          </Stack>
        </CardContent>
      </Card>

      {/* Quarantine Settings */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" sx={{ fontWeight: 'bold', mb: 2 }}>
            Quarantine & Backup
          </Typography>
          <Stack spacing={2}>
            <FormControlLabel
              control={
                <Switch
                  checked={settings.backupBeforeDelete}
                  onChange={(e) => handleChange('backupBeforeDelete', e.target.checked)}
                  color="primary"
                />
              }
              label="Create backup before deleting files"
            />
            <TextField
              label="Max quarantine size (MB)"
              type="number"
              value={settings.maxQuarantineSize || 1024}
              onChange={(e) => handleChange('maxQuarantineSize', parseInt(e.target.value))}
              fullWidth
              sx={{ mt: 2 }}
            />
            <TextField
              label="Auto-delete after (days)"
              type="number"
              value={settings.autoDeleteAfter || 30}
              onChange={(e) => handleChange('autoDeleteAfter', parseInt(e.target.value))}
              fullWidth
              sx={{ mt: 2 }}
            />
          </Stack>
        </CardContent>
      </Card>

      {/* Actions */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" sx={{ fontWeight: 'bold', mb: 2 }}>
            Actions
          </Typography>
          <Stack direction="row" spacing={2}>
            <Button
              variant="contained"
              startIcon={<SaveIcon />}
              onClick={handleSave}
            >
              Save Settings
            </Button>
            <Button
              variant="outlined"
              startIcon={<RefreshIcon />}
              onClick={handleResetDefaults}
            >
              Reset to Defaults
            </Button>
          </Stack>
        </CardContent>
      </Card>
    </Box>
  );
}

export default Settings;
