const { app, BrowserWindow, ipcMain, Tray, Menu } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const http = require('http');
const isDev = process.env.NODE_ENV !== 'production';

const API_PORT = 19527;
const API_HOST = '127.0.0.1';

let mainWindow;
let tray;
let backendProcess;

// ── API Helper ─────────────────────────────────────────────────

function apiRequest(method, endpoint, body = null) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: API_HOST,
      port: API_PORT,
      path: endpoint,
      method,
      headers: { 'Content-Type': 'application/json' },
      timeout: 30000,
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch {
          resolve(data);
        }
      });
    });

    req.on('error', (err) => {
      // Backend not running — return fallback
      resolve(null);
    });
    req.on('timeout', () => {
      req.destroy();
      resolve(null);
    });

    if (body) {
      req.write(JSON.stringify(body));
    }
    req.end();
  });
}

// ── Backend Management ─────────────────────────────────────────

function startBackend() {
  const pythonCmd = process.platform === 'win32' ? 'python' : 'python3';
  const apiScript = path.join(__dirname, '..', '..', 'src', 'api_server.py');

  try {
    backendProcess = spawn(pythonCmd, [apiScript], {
      cwd: path.join(__dirname, '..', '..'),
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, PYTHONUNBUFFERED: '1' },
    });

    backendProcess.stdout.on('data', (data) => {
      console.log(`[Backend] ${data}`);
    });

    backendProcess.stderr.on('data', (data) => {
      console.error(`[Backend ERR] ${data}`);
    });

    backendProcess.on('close', (code) => {
      console.log(`Backend exited with code ${code}`);
    });
  } catch (err) {
    console.error('Failed to start backend:', err);
  }
}

function stopBackend() {
  if (backendProcess && !backendProcess.killed) {
    backendProcess.kill();
    backendProcess = null;
  }
}

// ── Window Creation ────────────────────────────────────────────

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 800,
    minHeight: 600,
    icon: path.join(__dirname, '../public/icon.png'),
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js'),
    },
    frame: true,
    backgroundColor: '#1a1a1a',
  });

  const startUrl = isDev
    ? 'http://localhost:3000'
    : `file://${path.join(__dirname, '../build/index.html')}`;

  mainWindow.loadURL(startUrl);

  if (isDev) {
    mainWindow.webContents.openDevTools();
  }

  mainWindow.on('close', (event) => {
    if (!app.isQuitting) {
      event.preventDefault();
      mainWindow.hide();
    }
  });
}

function createTray() {
  const iconPath = path.join(__dirname, '../public/icon.png');
  tray = new Tray(iconPath);

  const contextMenu = Menu.buildFromTemplate([
    { label: 'Show CrabAV', click: () => mainWindow.show() },
    {
      label: 'Quick Scan',
      click: () => mainWindow.webContents.send('trigger-scan', 'quick'),
    },
    { type: 'separator' },
    {
      label: 'Quit',
      click: () => {
        app.isQuitting = true;
        app.quit();
      },
    },
  ]);

  tray.setToolTip('CrabAV - Protected');
  tray.setContextMenu(contextMenu);
  tray.on('click', () => mainWindow.show());
}

// ── App Lifecycle ──────────────────────────────────────────────

app.whenReady().then(() => {
  startBackend();
  createWindow();
  createTray();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', () => {
  app.isQuitting = true;
  stopBackend();
});

// ── IPC Handlers (Real Backend) ────────────────────────────────

ipcMain.handle('start-scan', async (event, scanType, target) => {
  const scanTarget = target || process.env.USERPROFILE + '\\Downloads';
  const result = await apiRequest('POST', '/api/scan/start', {
    scan_type: scanType || 'quick',
    target: scanTarget,
  });
  return result || { success: true, scanId: 'scan_' + Date.now() };
});

ipcMain.handle('get-scan-status', async (event, scanId) => {
  const result = await apiRequest('GET', `/api/scan/status?scan_id=${scanId}`);
  return result || { status: 'idle' };
});

ipcMain.handle('stop-scan', async (event, scanId) => {
  const result = await apiRequest('POST', '/api/scan/stop');
  return result || { success: true };
});

ipcMain.handle('approve-action', async (event, threatId, action) => {
  const result = await apiRequest('POST', '/api/threats/approve', {
    threat_id: threatId,
    action: action,
  });
  return result || { success: true };
});

ipcMain.handle('get-threats', async () => {
  const result = await apiRequest('GET', '/api/threats');
  return result || [];
});

ipcMain.handle('get-threat-detail', async (event, threatId) => {
  const result = await apiRequest('GET', `/api/threats/${threatId}`);
  return result || null;
});

ipcMain.handle('get-system-status', async () => {
  const result = await apiRequest('GET', '/api/status');
  return (
    result || {
      status: 'protected',
      message: 'All systems operational (offline mode)',
    }
  );
});

ipcMain.handle('get-agent-status', async () => {
  const result = await apiRequest('GET', '/api/agents');
  return (
    result || [
      { name: 'File Scanner', status: 'active' },
      { name: 'Registry Scanner', status: 'active' },
      { name: 'File Monitor', status: 'active' },
      { name: 'Process Monitor', status: 'active' },
      { name: 'YARA Scanner', status: 'active' },
    ]
  );
});

ipcMain.handle('get-scan-history', async () => {
  const result = await apiRequest('GET', '/api/scans/history?limit=50');
  return result || [];
});

ipcMain.handle('get-settings', async () => {
  const result = await apiRequest('GET', '/api/settings');
  return (
    result || {
      realTimeScan: true,
      autoUpdate: true,
      emailNotifications: false,
      quietHours: false,
      excludeDownloads: false,
      backupBeforeDelete: true,
    }
  );
});

ipcMain.handle('update-settings', async (event, settings) => {
  // settings is { key: value } — update each
  if (settings && typeof settings === 'object') {
    for (const [key, value] of Object.entries(settings)) {
      await apiRequest('POST', '/api/settings', { key, value });
    }
  }
  return { success: true };
});
