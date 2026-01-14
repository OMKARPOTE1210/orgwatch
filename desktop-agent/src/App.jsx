import React, { useState, useEffect, useRef } from 'react';
import { ShieldCheck, Activity, User, Server, Minus, X, Loader2, CheckCircle, Terminal, AlertTriangle, Wifi, RefreshCw } from 'lucide-react';

// Safe Import for Electron IPC
let ipcRenderer;
if (window.require) {
  try {
    ipcRenderer = window.require('electron').ipcRenderer;
  } catch (error) {
    console.warn('Electron IPC not found.');
  }
}

export default function App() {
  const [status, setStatus] = useState('initializing'); // initializing | enrollment | active | error
  const [empId, setEmpId] = useState('');
  const [logs, setLogs] = useState([]);
  const [stats, setStats] = useState({ cpu: 0, ram: 0 });
  const [serverOnline, setServerOnline] = useState(true); // Track backend status
  const logsEndRef = useRef(null);

  // Auto-scroll logs
  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  useEffect(() => {
    const handleLog = (event, data) => {
      const message = data.toString().trim();
      
      // 1. FILTER: Ignore noisy Python warnings (pkg_resources)
      if (message.includes("pkg_resources is deprecated") || message.includes("from pkg_resources import Requirement")) {
        return; 
      }

      // 2. DETECT: Connection Errors (Backend down)
      if (message.includes("WinError 10061") || message.includes("Connection refused") || message.includes("Max retries exceeded")) {
        setServerOnline(false);
        setLogs(prev => [`⚠️ Backend Offline: Cannot reach server at port 8000.`, ...prev]);
        return;
      }

      // 3. DETECT: Critical Python Crashes
      if (message.includes("Traceback") || message.includes("ModuleNotFoundError")) {
        setLogs(prev => [`❌ CRITICAL ERROR: ${message}`, ...prev]);
        return; 
      }

      try {
        // Handle JSON Heartbeats (Hidden from logs, updates UI)
        if(message.includes('{"type": "heartbeat"')) {
           const jsonStr = message.substring(message.indexOf('{'));
           const parsed = JSON.parse(jsonStr);
           setStats({ 
             cpu: parsed.data.usage?.cpu_percent || 0, 
             ram: parsed.data.usage?.ram_percent || 0 
           });
           setStatus('active');
           setServerOnline(true);
           return; 
        }
        
        // Handle Status
        if(message.includes('{"status":')) {
           const parsed = JSON.parse(message);
           if(parsed.status === 'enrolled' || parsed.status === 'loaded') {
             setStatus('active');
             setServerOnline(true);
           }
           return;
        }
      } catch (e) {}

      // Regular Logs
      setLogs(prev => [`> ${message}`, ...prev.slice(0, 50)]);
    };

    if (ipcRenderer) ipcRenderer.on('agent-log', handleLog);

    // FAIL-SAFE: Force Enrollment if stuck for > 5 seconds
    const timer = setTimeout(() => {
      setStatus(prev => {
        if (prev === 'initializing') {
            setLogs(prevLogs => ["⚠️ Connection Timeout: Starting in Offline Mode...", ...prevLogs]);
            return 'enrollment';
        }
        return prev;
      });
    }, 5000);

    return () => clearTimeout(timer);
  }, []);

  const handleEnroll = (e) => {
    e.preventDefault();
    if (!empId) return;
    setStatus('initializing');
    setLogs(prev => ["> Handshaking with OrgWatch Core...", ...prev]);
    if (ipcRenderer) ipcRenderer.send('enroll-agent', empId);
    
    // Simulate success if backend offline (for demo purposes)
    setTimeout(() => {
      // If we are still initializing after 3s, likely failed. 
      // But we stay in 'initializing' to show logs unless user forces skip.
    }, 3000);
  };

  return (
    <div className="h-screen w-screen bg-slate-950 text-slate-200 flex flex-col border border-slate-800 overflow-hidden font-sans selection:bg-cyan-500/30">
      
      {/* Title Bar */}
      <div className="h-10 bg-slate-900 border-b border-slate-800 flex items-center justify-between px-4 shrink-0" style={{WebkitAppRegion: 'drag'}}>
        <div className="flex items-center gap-2 text-cyan-400 font-bold text-xs tracking-wider">
          <Activity size={14} /> ORGWATCH SECURE AGENT
        </div>
        <div className="flex gap-2" style={{WebkitAppRegion: 'no-drag'}}>
          <button onClick={() => ipcRenderer?.send('minimize-window')} className="p-1 hover:text-white"><Minus size={14}/></button>
          <button onClick={() => ipcRenderer?.send('close-window')} className="p-1 hover:text-red-400"><X size={14}/></button>
        </div>
      </div>

      <div className="flex-1 flex flex-col relative overflow-hidden">
        
        {/* VIEW: ENROLLMENT */}
        {status === 'enrollment' && (
          <div className="flex-1 flex flex-col items-center justify-center animate-fade-in p-8">
            <div className="w-20 h-20 bg-cyan-500/10 rounded-3xl flex items-center justify-center text-cyan-400 mb-8 border border-cyan-500/20">
              <ShieldCheck size={40} />
            </div>
            <h1 className="text-2xl font-bold text-white mb-2">Device Enrollment</h1>
            <p className="text-slate-400 text-sm text-center mb-8 max-w-xs">
              Authenticate to join the secure network.
            </p>
            
            {/* Server Status Warning */}
            {!serverOnline && (
               <div className="flex items-center gap-2 text-xs text-red-400 bg-red-950/30 border border-red-900/50 px-3 py-2 rounded-lg mb-6">
                 <AlertTriangle size={14} /> Backend Server Unreachable
               </div>
            )}

            <form onSubmit={handleEnroll} className="w-full max-w-xs space-y-4">
              <div className="relative group">
                <User className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" size={18} />
                <input 
                  value={empId} 
                  onChange={(e) => setEmpId(e.target.value)} 
                  className="w-full bg-slate-900/50 border border-slate-700 rounded-xl py-3.5 pl-12 pr-4 text-sm text-white focus:border-cyan-500/50 outline-none" 
                  placeholder="Enter Employee ID" 
                  required 
                />
              </div>
              <button className="w-full py-3.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold rounded-xl text-sm shadow-lg transition-all active:scale-[0.98]">
                Secure & Register
              </button>
            </form>
          </div>
        )}

        {/* VIEW: ACTIVE MONITORING */}
        {status === 'active' && (
          <div className="flex-1 flex flex-col p-6 animate-fade-in">
            {/* Status Header */}
            <div className="flex items-center justify-between mb-6 bg-slate-900/50 p-4 rounded-2xl border border-slate-800/50">
              <div>
                <h2 className="text-lg font-bold text-white flex items-center gap-2">
                   System Protected <CheckCircle size={16} className="text-emerald-500"/>
                </h2>
                <div className="flex items-center gap-2 text-slate-400 text-xs mt-1 font-mono">
                  <Wifi size={12} className={serverOnline ? "text-emerald-500" : "text-red-500"}/> 
                  {serverOnline ? "Tunnel Active" : "Offline Mode"}
                </div>
              </div>
              <div className="w-12 h-12 rounded-full bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center relative">
                <div className="absolute inset-0 bg-emerald-500/20 rounded-full animate-ping"></div>
                <Activity size={24} className="text-emerald-400 relative z-10" />
              </div>
            </div>

            {/* Gauges */}
            <div className="grid grid-cols-2 gap-4 mb-6">
              <div className="bg-slate-900 p-5 rounded-2xl border border-slate-800">
                <div className="text-slate-500 text-xs font-bold mb-1 uppercase">CPU Load</div>
                <div className="text-3xl font-mono font-bold text-white">{stats.cpu}%</div>
                <div className="w-full bg-slate-800 h-1.5 mt-3 rounded-full overflow-hidden">
                  <div className="h-full bg-cyan-500 transition-all duration-500" style={{width: `${stats.cpu}%`}} />
                </div>
              </div>
              <div className="bg-slate-900 p-5 rounded-2xl border border-slate-800">
                <div className="text-slate-500 text-xs font-bold mb-1 uppercase">RAM Usage</div>
                <div className="text-3xl font-mono font-bold text-white">{stats.ram}%</div>
                <div className="w-full bg-slate-800 h-1.5 mt-3 rounded-full overflow-hidden">
                  <div className="h-full bg-purple-500 transition-all duration-500" style={{width: `${stats.ram}%`}} />
                </div>
              </div>
            </div>

            {/* Command Log Console */}
            <div className="bg-black/40 rounded-2xl border border-slate-800 flex-1 overflow-hidden flex flex-col backdrop-blur-sm">
              <div className="px-4 py-3 border-b border-slate-800 text-xs font-bold text-slate-500 uppercase flex items-center gap-2 bg-slate-900/80">
                <Terminal size={12} /> C2 Command Uplink
              </div>
              <div className="p-4 font-mono text-[11px] text-cyan-100/80 space-y-1.5 overflow-y-auto flex-1 custom-scrollbar">
                {logs.length === 0 && <div className="opacity-50 italic">Listening for remote commands...</div>}
                {logs.map((log, i) => (
                  <div key={i} className="border-l-2 border-slate-700 pl-2">
                    {log}
                  </div>
                ))}
                <div ref={logsEndRef} />
              </div>
            </div>
          </div>
        )}

        {/* VIEW: INITIALIZING (WITH DEBUG LOGS) */}
        {status === 'initializing' && (
          <div className="flex-1 flex flex-col items-center justify-center p-8 space-y-6 animate-fade-in">
            <Loader2 className="animate-spin text-cyan-400" size={48} />
            <div className="text-center space-y-1">
               <p className="text-white font-medium text-lg">Initializing Secure Agent...</p>
               <p className="text-slate-500 text-xs">Loading AI Modules & Encryption</p>
            </div>

            {/* DEBUG CONSOLE: Shows why it might be stuck */}
            <div className="w-full max-w-sm bg-black/40 rounded-xl border border-slate-800 p-4 mt-4">
               <div className="flex items-center gap-2 text-red-400 text-xs font-bold mb-2">
                  <AlertTriangle size={12}/> Boot Logs
               </div>
               <div className="h-32 overflow-y-auto font-mono text-[10px] text-slate-400 space-y-1">
                  {logs.length === 0 && (
                     <span className="opacity-50 italic">Waiting for Python process...</span>
                  )}
                  {logs.map((l, i) => <div key={i} className="truncate">{l}</div>)}
                  <div ref={logsEndRef} />
               </div>
            </div>

            {/* Manual Override Button */}
            <button 
                onClick={() => setStatus('enrollment')}
                className="text-slate-600 text-xs hover:text-white underline decoration-slate-800 hover:decoration-white transition-all cursor-pointer"
            >
                Force Load Login Screen
            </button>
          </div>
        )}

      </div>
    </div>
  );
}