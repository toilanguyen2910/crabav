const { app, BrowserWindow, ipcMain, Tray, Menu } = require('electron');
const path = require('path');
const isDev = process.env.NODE_ENV !== 'production';

let mainWindow;
let tray;

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
      preload: path.join(__dirname, 'preload.js')
    },
    frame: true,
    backgroundColor: '#1a1a1a'
  });

  // Load app
  const startUrl = isDev
    ? 'http://localhost:3000'
    : `file://${path.join(__dirname, '../build/index.html')}`;

  mainWindow.loadURL(startUrl);

  // Open DevTools in development
  if (isDev) {
    mainWindow.webContents.openDevTools();
  }

  // Minimize to tray instead of closing
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
    {
      label: 'Show CrabAV',
      click: () => {
        mainWindow.show();
      }
    },
    {
      label: 'Quick Scan',
      click: () => {
        // Trigger quick scan
        mainWindow.webContents.send('trigger-scan', 'quick');
      }
    },
    { type: 'separator' },
    {
      label: 'Quit',
      click: () => {
        app.isQuitting = true;
        app.quit();
      }
    }
  ]);

  tray.setToolTip('CrabAV - Protected');
  tray.setContextMenu(contextMenu);

  tray.on('click', () => {
    mainWindow.show();
  });
}

app.whenReady().then(() => {
  createWindow();
  createTray();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// IPC handlers
ipcMain.handle('start-scan', async (event, scanType) => {
  // Call Python backend
  return { success: true, scanId: 'scan_' + Date.now() };
});

ipcMain.handle('get-scan-status', async (event, scanId) => {
  // Get scan status from backend
  return { status: 'running', progress: 45 };
});

ipcMain.handle('stop-scan', async (event, scanId) => {
  return { success: true };
});

ipcMain.handle('approve-action', async (event, threatId, action) => {
  // Send approval to backend
  return { success: true };
});

ipcMain.handle('get-threats', async () => {
  return [];
});

ipcMain.handle('get-threat-detail', async (event, threatId) => {
  return null;
});

ipcMain.handle('get-system-status', async () => {
  return { status: 'protected', message: 'All systems operational' };
});

ipcMain.handle('get-agent-status', async () => {
  return [
    { name: 'File Scanner', status: 'active' },
    { name: 'Registry Scanner', status: 'active' },
    { name: 'Memory Scanner', status: 'active' },
    { name: 'File Monitor', status: 'active' },
    { name: 'Process Monitor', status: 'active' }
  ];
});

ipcMain.handle('get-settings', async () => {
  return {
    realTimeScan: true,
    autoUpdate: true,
    emailNotifications: false,
    quietHours: false,
    excludeDownloads: false,
    backupBeforeDelete: true
  };
});

ipcMain.handle('update-settings', async (event, settings) => {
  return { success: true };
});
