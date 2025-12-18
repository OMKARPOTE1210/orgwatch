const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const isDev = require('electron-is-dev');

let mainWindow;
let pythonProcess;

function createWindow() {
  // 1. Configure Startup (Persistence)
  // This ensures the app launches automatically when the user logs in
  if (!isDev) {
    const appFolder = path.dirname(process.execPath);
    const updateExe = path.resolve(appFolder, '..', 'Update.exe');
    const exeName = path.basename(process.execPath);

    app.setLoginItemSettings({
      openAtLogin: true,
      path: updateExe,
      args: [
        '--processStart', `"${exeName}"`,
        '--process-start-args', `"--hidden"`
      ]
    });
  }

  // 2. Create the Browser Window
  mainWindow = new BrowserWindow({
    width: 950,
    height: 720,
    frame: false,       // Security: Remove OS chrome (minimize/close buttons)
    resizable: false,   // Fixed size for the agent UI
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
      devTools: isDev,  // Disable DevTools in production
    },
    backgroundColor: '#0f172a',
    icon: path.join(__dirname, 'resources/icon.png')
  });

  // Load UI
  const startURL = isDev 
    ? 'http://localhost:5173' 
    : `file://${path.join(__dirname, 'dist/index.html')}`;

  mainWindow.loadURL(startURL);

  // Security: Prevent closure via standard shortcuts in Production
  if (!isDev) {
    mainWindow.on('close', (e) => {
      e.preventDefault();
      mainWindow.hide(); // Stealth Mode: Hide instead of close
    });
  }

  // Start the background logic
  startPythonAgent();
}

function startPythonAgent() {
  let executable;
  let args = [];

  if (isDev) {
    // DEV MODE: Run python script directly
    // '-u' forces unbuffered output so logs appear instantly
    executable = 'python';
    args = ['-u', path.join(__dirname, 'service', 'agent.py')];
  } else {
    // PROD MODE: Run compiled EXE
    // In production, the exe is unpacked into the resources folder by electron-builder
    executable = path.join(process.resourcesPath, 'orgwatch_daemon.exe');
    args = []; // The EXE contains its own arguments and entry point
  }

  console.log("Launching Agent Core:", executable);

  // Spawn the process detached from the shell but piping IO
  pythonProcess = spawn(executable, args, {
    detached: true, 
    windowsHide: true, // Stealth: No terminal window
    stdio: ['pipe', 'pipe', 'pipe']
  });

  // Handle Standard Output (Logs & Heartbeats)
  pythonProcess.stdout.on('data', (data) => {
    const message = data.toString();
    console.log(`[CORE]: ${message}`); // Log to Electron console
    
    // Forward to React UI
    if(mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('agent-log', message);
    }
  });

  // Handle Errors
  pythonProcess.stderr.on('data', (data) => {
    const errorMsg = data.toString();
    console.error(`[CORE ERROR]: ${errorMsg}`);
    if(mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('agent-log', `ERROR: ${errorMsg}`);
    }
  });

  // Handle Exit
  pythonProcess.on('close', (code) => {
    console.log(`Agent Core exited with code ${code}`);
    if(mainWindow && !mainWindow.isDestroyed()) {
       mainWindow.webContents.send('agent-log', `CRITICAL: Core Service Stopped (Code ${code})`);
    }
  });
}

// --- IPC Bridge (React <-> Electron) ---

ipcMain.on('minimize-window', () => mainWindow.minimize());

ipcMain.on('close-window', () => {
    // In Dev, allow closing. In Prod, this might just hide.
    // For this implementation, we allow closing via the UI button if explicitly clicked.
    if (mainWindow) {
        if (isDev) mainWindow.close();
        else mainWindow.hide();
    }
});

ipcMain.on('enroll-agent', (event, empId) => {
  // Send enrollment command to Python process via Stdin
  if(pythonProcess && pythonProcess.stdin) {
    try {
        pythonProcess.stdin.write(JSON.stringify({ type: 'enroll', emp_id: empId }) + "\n");
    } catch (err) {
        console.error("Failed to send enroll command:", err);
    }
  }
});

// --- App Lifecycle ---

// Security: Prevent multiple instances
const gotTheLock = app.requestSingleInstanceLock();
if (!gotTheLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    // Someone tried to run a second instance, we should focus our window.
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.show();
      mainWindow.focus();
    }
  });

  app.whenReady().then(createWindow);
}

app.on('window-all-closed', () => {
  // On macOS it is common for applications and their menu bar
  // to stay active until the user quits explicitly with Cmd + Q
  if (process.platform !== 'darwin') {
      // In production, we usually want to keep running in tray, 
      // but for now we quit if all windows are forcibly closed.
      app.quit();
  }
});

app.on('will-quit', () => {
  // Clean up python process
  if (pythonProcess) pythonProcess.kill();
});