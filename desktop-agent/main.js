const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const isDev = require('electron-is-dev');
const fs = require('fs');

let mainWindow;
let pythonProcess;

// 1. SINGLE INSTANCE LOCK
const gotTheLock = app.requestSingleInstanceLock();

if (!gotTheLock) {
  app.quit();
} else {
  app.on('second-instance', (event, commandLine, workingDirectory) => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.show();
      mainWindow.focus();
    }
  });

  app.whenReady().then(() => {
    if (!isDev) {
        app.setLoginItemSettings({
            openAtLogin: true,
            path: process.execPath,
            args: []
        });
    }
    createWindow();
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 900, 
    height: 700, 
    frame: false, 
    resizable: false,
    webPreferences: { 
      nodeIntegration: true, 
      contextIsolation: false, 
      devTools: isDev 
    },
    backgroundColor: '#0f172a',
    // icon: path.join(__dirname, 'resources/icon.ico')
  });
  
  const startURL = isDev 
    ? 'http://localhost:5173' 
    : `file://${path.join(__dirname, 'dist/index.html')}`;
    
  mainWindow.loadURL(startURL);
  
  if (!isDev) {
    mainWindow.on('close', (e) => { 
        e.preventDefault(); 
        mainWindow.hide(); 
    });
  }
  
  // Wait for window to load before starting python so it can receive logs
  mainWindow.webContents.once('did-finish-load', () => {
    startPythonAgent();
  });
}

function startPythonAgent() {
  let executable;
  let args = [];
  let cwd = process.resourcesPath; // Default cwd for prod

  if (isDev) {
     executable = 'python';
     // Point to the service folder for execution context to help relative paths
     const servicePath = path.join(__dirname, 'service');
     cwd = servicePath;
     args = ['-u', 'agent.py'];
  } else {
     // Production: Look for compiled EXE in resources
     executable = path.join(process.resourcesPath, 'orgwatch_daemon.exe');
     args = [];
  }

  // DEBUG: Check if file exists in prod
  if (!isDev && !fs.existsSync(executable)) {
      console.error(`CRITICAL: Python executable not found at ${executable}`);
      if(mainWindow) mainWindow.webContents.send('agent-log', `CRITICAL ERROR: Core Executable Missing at ${executable}`);
      return;
  }

  console.log(`Launching Core Service: ${executable} in ${cwd}`);
  if(mainWindow) mainWindow.webContents.send('agent-log', `Initializing Core Service...`);

  try {
      pythonProcess = spawn(executable, args, { 
        detached: false, 
        cwd: cwd, // Set working directory explicitly
        stdio: ['pipe', 'pipe', 'pipe'] 
      });
      
      pythonProcess.stdout.on('data', (data) => {
        const str = data.toString();
        // Console log for dev terminal
        console.log('[PY]', str);
        if(mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('agent-log', str);
      });
      
      pythonProcess.stderr.on('data', (data) => {
        const str = data.toString();
        console.error('[PY ERR]', str);
        if(mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('agent-log', `ERROR: ${str}`);
      });
      
      pythonProcess.on('close', (code) => {
          console.log(`Core Service exited with code ${code}`);
          if(mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('agent-log', `CORE STOPPED: Exit Code ${code}`);
      });
      
      pythonProcess.on('error', (err) => {
          console.error('Failed to start python process.', err);
          if(mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('agent-log', `FATAL: Failed to spawn process. ${err.message}`);
      });

  } catch (e) {
      console.error('Exception spawning process:', e);
      if(mainWindow) mainWindow.webContents.send('agent-log', `EXCEPTION: ${e.message}`);
  }
}

ipcMain.on('minimize-window', () => mainWindow.minimize());
ipcMain.on('close-window', () => {
    if (isDev) mainWindow.close(); 
    else mainWindow.hide();
});

ipcMain.on('enroll-agent', (e, id) => {
    console.log("Enrollment Requested:", id);
    if(pythonProcess && pythonProcess.stdin) {
        pythonProcess.stdin.write(JSON.stringify({ type: 'enroll', emp_id: id }) + "\n");
    } else {
        if(mainWindow) mainWindow.webContents.send('agent-log', "ERROR: Cannot enroll, core service not running.");
    }
});

ipcMain.on('trigger-scan', () => {
    if(pythonProcess && pythonProcess.stdin) {
        pythonProcess.stdin.write(JSON.stringify({ type: 'scan' }) + "\n");
    }
});

app.on('will-quit', () => { 
    if (pythonProcess) pythonProcess.kill(); 
});