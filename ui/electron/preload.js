const { contextBridge, ipcRenderer } = require('electron');

// Expose protected methods to renderer process
contextBridge.exposeInMainWorld('electronAPI', {
  // Scan operations
  startScan: (scanType) => ipcRenderer.invoke('start-scan', scanType),
  getScanStatus: (scanId) => ipcRenderer.invoke('get-scan-status', scanId),
  stopScan: (scanId) => ipcRenderer.invoke('stop-scan', scanId),
  
  // Threat operations
  getThreats: () => ipcRenderer.invoke('get-threats'),
  getThreatDetail: (threatId) => ipcRenderer.invoke('get-threat-detail', threatId),
  approveAction: (threatId, action) => ipcRenderer.invoke('approve-action', threatId, action),
  
  // System operations
  getSystemStatus: () => ipcRenderer.invoke('get-system-status'),
  getAgentStatus: () => ipcRenderer.invoke('get-agent-status'),
  
  // Settings
  getSettings: () => ipcRenderer.invoke('get-settings'),
  updateSettings: (settings) => ipcRenderer.invoke('update-settings', settings),
  
  // Event listeners
  onScanProgress: (callback) => {
    ipcRenderer.on('scan-progress', (event, data) => callback(data));
  },
  onThreatDetected: (callback) => {
    ipcRenderer.on('threat-detected', (event, data) => callback(data));
  },
  onScanComplete: (callback) => {
    ipcRenderer.on('scan-complete', (event, data) => callback(data));
  },
  
  // Remove listeners
  removeAllListeners: (channel) => {
    ipcRenderer.removeAllListeners(channel);
  }
});
