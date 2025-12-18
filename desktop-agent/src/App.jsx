import React, { useState, useEffect, useRef } from 'react';
import { ShieldCheck, Activity, User, Server, Minus, X, Loader2, CheckCircle, Terminal } from 'lucide-react';

const ipcRenderer = window.require ? window.require('electron').ipcRenderer : null;

export default function App() {
  const [status, setStatus] = useState('initializing');
  const [empId, setEmpId] = useState('');
  const [logs, setLogs] = useState([]);
  const [stats, setStats] = useState({ cpu: 0, ram: 0 });
  const logsEndRef = useRef(null);

  useEffect(() => { logsEndRef.current?.scrollIntoView({ behavior: "smooth" }); }, [logs]);

  useEffect(() => {
    if (!ipcRenderer) return;
    
    ipcRenderer.on('agent-log', (event, data) => {
      const message = data.toString().trim();
      try {
        if(message.includes('{')) {
           const parsed = JSON.parse(message.substring(message.indexOf('{')));
           if (parsed.status === 'enrolled' || parsed.status === 'loaded') setStatus('active');
           if (parsed.type === 'heartbeat') {
             setStats({ cpu: parsed.data.usage?.cpu_percent || 0, ram: parsed.data.usage?.ram_percent || 0 });
             setStatus('active');
             return; // Don't show heartbeats in text log
           }
        }
      } catch (e) {}
      setLogs(prev => [`${new Date().toLocaleTimeString()} ${message}`, ...prev.slice(0, 50)]);
    });

    const timer = setTimeout(() => {
      setStatus(prev => prev === 'initializing' ? 'enrollment' : prev);
    }, 4000);
    return () => clearTimeout(timer);
  }, []);

  const handleEnroll = (e) => {
    e.preventDefault();
    setStatus('initializing');
    ipcRenderer?.send('enroll-agent', empId);
  };

  return (
    <div className="h-screen w-screen bg-slate-950 text-slate-200 flex flex-col border border-slate-800 overflow-hidden font-sans selection:bg-cyan-500/30">
      <div className="h-10 bg-slate-900 border-b border-slate-800 flex items-center justify-between px-4 shrink-0" style={{WebkitAppRegion: 'drag'}}>
        <div className="flex items-center gap-2 text-cyan-400 font-bold text-xs tracking-wider"><Activity size={14} /> ORGWATCH SECURE AGENT</div>
        <div className="flex gap-2" style={{WebkitAppRegion: 'no-drag'}}>
          <button onClick={() => ipcRenderer?.send('minimize-window')} className="p-1 hover:text-white"><Minus size={14}/></button>
          <button onClick={() => ipcRenderer?.send('close-window')} className="p-1 hover:text-red-400"><X size={14}/></button>
        </div>
      </div>

      <div className="flex-1 flex flex-col relative overflow-hidden">
        {status === 'enrollment' && (
          <div className="flex-1 flex flex-col items-center justify-center animate-fade-in p-8">
            <div className="w-20 h-20 bg-cyan-500/10 rounded-3xl flex items-center justify-center text-cyan-400 mb-8 border border-cyan-500/20"><ShieldCheck size={40} /></div>
            <h1 className="text-2xl font-bold text-white mb-2">Device Enrollment</h1>
            <form onSubmit={handleEnroll} className="w-full max-w-xs space-y-4">
              <div className="relative group"><User className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" size={18} /><input value={empId} onChange={(e) => setEmpId(e.target.value)} className="w-full bg-slate-900/50 border border-slate-700 rounded-xl py-3.5 pl-12 pr-4 text-sm text-white outline-none" placeholder="Enter Employee ID" required /></div>
              <button className="w-full py-3.5 bg-cyan-600 hover:bg-cyan-500 text-white font-bold rounded-xl text-sm shadow-lg">Secure & Register</button>
            </form>
          </div>
        )}

        {status === 'active' && (
          <div className="flex-1 flex flex-col p-6 animate-fade-in">
            <div className="flex items-center justify-between mb-6 bg-slate-900/50 p-4 rounded-2xl border border-slate-800/50">
              <div><h2 className="text-lg font-bold text-white flex items-center gap-2">System Protected <CheckCircle size={16} className="text-emerald-500"/></h2><div className="text-slate-400 text-xs mt-1 font-mono">ID: {empId || 'ACTIVE'}</div></div>
              <div className="w-12 h-12 rounded-full bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center animate-pulse"><Activity size={24} className="text-emerald-400" /></div>
            </div>
            <div className="grid grid-cols-2 gap-4 mb-6">
              <div className="bg-slate-900 p-5 rounded-2xl border border-slate-800"><div className="text-slate-500 text-xs font-bold mb-1 uppercase">CPU Load</div><div className="text-3xl font-mono font-bold text-white">{stats.cpu}%</div><div className="w-full bg-slate-800 h-1.5 mt-3 rounded-full overflow-hidden"><div className="h-full bg-cyan-500 transition-all duration-500" style={{width: `${stats.cpu}%`}} /></div></div>
              <div className="bg-slate-900 p-5 rounded-2xl border border-slate-800"><div className="text-slate-500 text-xs font-bold mb-1 uppercase">RAM Usage</div><div className="text-3xl font-mono font-bold text-white">{stats.ram}%</div><div className="w-full bg-slate-800 h-1.5 mt-3 rounded-full overflow-hidden"><div className="h-full bg-purple-500 transition-all duration-500" style={{width: `${stats.ram}%`}} /></div></div>
            </div>
            <div className="bg-black/40 rounded-2xl border border-slate-800 flex-1 overflow-hidden flex flex-col backdrop-blur-sm">
              <div className="px-4 py-3 border-b border-slate-800 text-xs font-bold text-slate-500 uppercase flex items-center gap-2 bg-slate-900/80"><Terminal size={12} /> C2 Command Uplink</div>
              <div className="p-4 font-mono text-[11px] text-cyan-100/80 space-y-1.5 overflow-y-auto flex-1 custom-scrollbar">
                {logs.map((log, i) => <div key={i} className="border-l-2 border-slate-700 pl-2">{log}</div>)}
                <div ref={logsEndRef} />
              </div>
            </div>
          </div>
        )}

        {status === 'initializing' && <div className="flex-1 flex flex-col items-center justify-center p-8 space-y-6 animate-fade-in"><Loader2 className="animate-spin text-cyan-400" size={48} /><p className="text-slate-500 text-sm">Connecting to OrgWatch Core...</p></div>}
      </div>
    </div>
  );
}