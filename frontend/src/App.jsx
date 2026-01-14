import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
  LayoutDashboard, Monitor, ShieldAlert, Settings, Activity, Search, Bell, 
  Server, Laptop, CheckCircle2, AlertTriangle, XCircle, Menu, ChevronRight, Filter, LogOut, 
  Lock, User, Globe, Cpu, HardDrive, Save, X, Plus, Trash2, RefreshCw, Power, ShieldCheck, 
  Smartphone as PhoneIcon, Bot, Sparkles, Terminal, FileText, BrainCircuit, Loader2, ScanEye,
  Wifi, BarChart3, PieChart, Zap, Skull, KeyRound, Download, FileJson, Hash, Globe2, ToggleRight,
  Eye, ExternalLink
} from 'lucide-react';
import { 
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, 
  BarChart, Bar, PieChart as RePie, Pie, Cell, Radar, RadarChart, PolarGrid, 
  PolarAngleAxis, PolarRadiusAxis, Legend 
} from 'recharts';
import { motion, AnimatePresence } from 'framer-motion';

/** UTILITIES **/
function cn(...classes) {
  return classes.filter(Boolean).join(' ');
}

// Custom Glass Card Component
const GlassCard = ({ children, className, hover = true }) => (
  <motion.div 
    initial={{ opacity: 0, y: 20 }}
    animate={{ opacity: 1, y: 0 }}
    className={cn(
      "bg-slate-900/60 backdrop-blur-xl border border-slate-800 rounded-2xl p-6 relative overflow-hidden",
      hover && "hover:border-cyan-500/30 transition-colors duration-300",
      className
    )}
  >
    <div className="absolute top-0 right-0 w-32 h-32 bg-cyan-500/5 rounded-full blur-3xl -z-10" />
    <div className="absolute bottom-0 left-0 w-32 h-32 bg-purple-500/5 rounded-full blur-3xl -z-10" />
    {children}
  </motion.div>
);

/** MOCK DATA GENERATORS **/
const generateHistory = () => Array.from({ length: 12 }, (_, i) => ({
  time: `${i * 2}:00`,
  usage: Math.floor(Math.random() * 60) + 20,
  network: Math.floor(Math.random() * 1000) + 500,
  threats: Math.floor(Math.random() * 5)
}));

const RADAR_DATA = [
  { subject: 'Malware', A: 120, fullMark: 150 },
  { subject: 'Phishing', A: 98, fullMark: 150 },
  { subject: 'DDoS', A: 86, fullMark: 150 },
  { subject: 'Insider', A: 99, fullMark: 150 },
  { subject: 'Ransomware', A: 85, fullMark: 150 },
  { subject: 'SQL Inj', A: 65, fullMark: 150 },
];

const OS_DATA = [
  { name: 'Windows 11', value: 400, color: '#3b82f6' },
  { name: 'macOS', value: 300, color: '#8b5cf6' },
  { name: 'Linux', value: 300, color: '#10b981' },
  { name: 'iOS/Android', value: 200, color: '#f59e0b' },
];

const THREAT_INTEL_DATA = [
  { id: 'IOC-2024-99', type: 'IP Address', value: '192.168.44.22', reputation: 'Malicious', origin: 'Russia', date: '2024-03-15' },
  { id: 'IOC-2024-98', type: 'File Hash', value: 'a1b2...99c1', reputation: 'Suspicious', origin: 'Unknown', date: '2024-03-14' },
  { id: 'IOC-2024-97', type: 'Domain', value: 'login-secure-update.com', reputation: 'Phishing', origin: 'China', date: '2024-03-12' },
  { id: 'IOC-2024-96', type: 'C2 Server', value: '104.22.11.1', reputation: 'High Risk', origin: 'Iran', date: '2024-03-10' },
  { id: 'IOC-2024-95', type: 'Email', value: 'hr-updates@fake-corp.com', reputation: 'Spam/Malware', origin: 'USA', date: '2024-03-09' },
];

const INITIAL_DEVICES = [
  { id: 'DEV-001', name: 'FIN-WORKSTATION-A', type: 'desktop', user: 'Alice Chen', ip: '10.0.4.55', status: 'online', risk: 12, os: 'Windows 11', cpu_usage: '12%', ram_usage: '45%', history: generateHistory() },
  { id: 'DEV-002', name: 'DEV-MACBOOK-PRO', type: 'laptop', user: 'Mark T.', ip: '10.0.4.102', status: 'warning', risk: 65, os: 'macOS Sonoma', cpu_usage: '88%', ram_usage: '92%', history: generateHistory() },
  { id: 'DEV-003', name: 'HR-LAPTOP-04', type: 'laptop', user: 'Sarah J.', ip: '10.0.5.22', status: 'offline', risk: 0, os: 'Windows 10', cpu_usage: '0%', ram_usage: '0%', history: generateHistory() },
  { id: 'DEV-004', name: 'PROD-DB-REPLICA', type: 'server', user: 'SYSTEM', ip: '192.168.1.5', status: 'online', risk: 5, os: 'Ubuntu 22.04', cpu_usage: '45%', ram_usage: '60%', history: generateHistory() },
  { id: 'DEV-005', name: 'MKT-DESKTOP-02', type: 'desktop', user: 'Paul R.', ip: '10.0.4.89', status: 'online', risk: 28, os: 'Windows 11', cpu_usage: '22%', ram_usage: '34%', history: generateHistory() },
];

const INITIAL_ALERTS = [
  { id: 1, title: 'Suspicious PowerShell Execution', desc: 'Encoded command block detected on startup registry key.', source: 'DEV-002', severity: 'critical', time: '10m ago' },
  { id: 2, title: 'Unusual Outbound Traffic', desc: 'High volume data transfer to unknown IP (84.12.x.x).', source: 'DEV-005', severity: 'high', time: '45m ago' },
];

/** SHARED COMPONENTS **/

const StatusBadge = ({ status }) => {
  const styles = {
    online: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
    offline: "bg-slate-500/10 text-slate-400 border-slate-500/20",
    warning: "bg-amber-500/10 text-amber-400 border-amber-500/20",
    critical: "bg-red-500/10 text-red-400 border-red-500/20",
    isolated: "bg-purple-500/10 text-purple-400 border-purple-500/20"
  };
  
  return (
    <div className={cn("px-2.5 py-1 rounded-full text-xs font-bold border flex items-center gap-2 w-fit", styles[status] || styles.offline)}>
      <div className={cn("w-1.5 h-1.5 rounded-full animate-pulse", 
        status === 'online' ? "bg-emerald-400" : 
        status === 'warning' ? "bg-amber-400" : 
        status === 'critical' ? "bg-red-400" : 
        status === 'isolated' ? "bg-purple-400" :
        "bg-slate-400")} />
      {status ? status.toUpperCase() : "UNKNOWN"}
    </div>
  );
};

// --- LOGIN SCREEN ---
const LoginScreen = ({ onLogin }) => {
  const [step, setStep] = useState('credentials');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [otp, setOtp] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  const handleCredentialsSubmit = (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError('');
    setTimeout(() => {
      if (email === 'admin@orgwatch.ai' && password === 'password') {
        setIsLoading(false);
        setStep('2fa');
      } else {
        setError('Invalid credentials. Try admin@orgwatch.ai / password');
        setIsLoading(false);
      }
    }, 1000);
  };

  const handle2FASubmit = (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError('');
    setTimeout(() => {
      if (otp.length === 6) {
        onLogin();
      } else {
        setError('Invalid code. Please enter any 6 digits.');
        setIsLoading(false);
      }
    }, 1000);
  };

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4 relative overflow-hidden">
      <div className="absolute inset-0 bg-[url('https://grainy-gradients.vercel.app/noise.svg')] opacity-5 pointer-events-none"/>
      <div className="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] bg-cyan-500/10 rounded-full blur-[100px] pointer-events-none"/>
      <div className="absolute bottom-[-10%] right-[-10%] w-[40%] h-[40%] bg-purple-500/10 rounded-full blur-[100px] pointer-events-none"/>

      <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} className="w-full max-w-md">
        <GlassCard className="border-slate-800 bg-slate-900/80 shadow-2xl backdrop-blur-xl">
          <div className="text-center mb-8">
            <div className="flex justify-center mb-4">
              <div className="p-3 bg-cyan-500/10 rounded-xl border border-cyan-500/20 shadow-lg shadow-cyan-500/10">
                <Activity className="text-cyan-400" size={32} />
              </div>
            </div>
            <h1 className="text-2xl font-bold text-white tracking-wider">ORG<span className="text-cyan-400">WATCH</span></h1>
            <p className="text-slate-400 text-sm mt-2">Secure Command Entry</p>
          </div>

          {step === 'credentials' ? (
            <form onSubmit={handleCredentialsSubmit} className="space-y-5">
              {error && <div className="p-3 bg-red-500/10 border border-red-500/20 text-red-400 text-sm rounded-lg flex items-center gap-2"><AlertTriangle size={16} /> {error}</div>}
              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-slate-400 uppercase tracking-wider ml-1">Identity</label>
                <div className="relative group">
                  <User className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 group-focus-within:text-cyan-400 transition-colors" size={18} />
                  <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} className="w-full pl-10 pr-4 py-3 bg-slate-950/50 border border-slate-800 rounded-xl text-white focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/50 outline-none transition-all placeholder:text-slate-600" placeholder="admin@orgwatch.ai" required />
                </div>
              </div>
              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-slate-400 uppercase tracking-wider ml-1">Passcode</label>
                <div className="relative group">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 group-focus-within:text-cyan-400 transition-colors" size={18} />
                  <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} className="w-full pl-10 pr-4 py-3 bg-slate-950/50 border border-slate-800 rounded-xl text-white focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/50 outline-none transition-all placeholder:text-slate-600" placeholder="••••••••" required />
                </div>
              </div>
              <button type="submit" disabled={isLoading} className="w-full py-3 bg-cyan-600 hover:bg-cyan-500 text-white font-bold rounded-xl shadow-lg shadow-cyan-500/20 transition-all flex items-center justify-center gap-2 mt-2">
                {isLoading ? <Loader2 className="animate-spin" size={20} /> : "Authenticate"}
              </button>
            </form>
          ) : (
            <motion.form initial={{ x: 20, opacity: 0 }} animate={{ x: 0, opacity: 1 }} onSubmit={handle2FASubmit} className="space-y-6">
              <div className="text-center space-y-2">
                <div className="w-16 h-16 bg-slate-950 border border-slate-800 rounded-full flex items-center justify-center mx-auto text-cyan-400 relative">
                  <KeyRound size={28} />
                  <div className="absolute inset-0 border-2 border-cyan-500/30 rounded-full animate-ping opacity-20"></div>
                </div>
                <h3 className="text-white font-bold text-lg">Two-Factor Verification</h3>
                <p className="text-slate-400 text-sm">Enter the 6-digit code from your authenticator.</p>
              </div>
              {error && <div className="p-3 bg-red-500/10 border border-red-500/20 text-red-400 text-sm rounded-lg flex items-center gap-2 text-center justify-center"><XCircle size={16} /> {error}</div>}
              <input type="text" maxLength={6} value={otp} onChange={(e) => setOtp(e.target.value.replace(/\D/g,''))} className="w-full text-center tracking-[1em] text-3xl font-mono font-bold py-4 bg-slate-950/50 border border-slate-800 rounded-xl text-white focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/50 outline-none transition-all placeholder:text-slate-700" placeholder="000000" autoFocus />
              <button type="submit" disabled={isLoading} className="w-full py-3 bg-cyan-600 hover:bg-cyan-500 text-white font-bold rounded-xl shadow-lg shadow-cyan-500/20 transition-all flex items-center justify-center gap-2">
                 {isLoading ? <Loader2 className="animate-spin" size={20} /> : "Verify Session"}
              </button>
              <button type="button" onClick={() => setStep('credentials')} className="w-full text-sm text-slate-500 hover:text-slate-300 transition-colors">Cancel and return to login</button>
            </motion.form>
          )}
        </GlassCard>
      </motion.div>
    </div>
  );
};

// --- AI MODAL ---
const AIAnalysisModal = ({ target, onClose }) => {
  const [logs, setLogs] = useState([]);
  const [isAnalyzing, setIsAnalyzing] = useState(true);
  const [isExecuting, setIsExecuting] = useState(false);
  const [report, setReport] = useState(null);

  // PRODUCTION URL CONFIGURATION
  const API_BASE = "https://orgwatch.onrender.com"; 

  useEffect(() => {
    setLogs(["Requesting Secure Agent Handshake...", "Queuing AI Task on Device..."]);
    
    let commandId = null;
    let pollInterval = null;

    const startScan = async () => {
      try {
        // 1. Send Command to Backend
        const res = await axios.post(`${API_BASE}/api/devices/${target.id}/scan`);
        commandId = res.data.command_id;
        setLogs(prev => [...prev, `Command Queued (ID: ${commandId})...`, "Waiting for Agent Response..."]);
        
        // 2. Poll for Completion
        pollInterval = setInterval(async () => {
           try {
             const statusRes = await axios.get(`${API_BASE}/api/commands/${commandId}`);
             if (statusRes.data.status === 'completed') {
                clearInterval(pollInterval);
                setReport(statusRes.data.result);
                setIsAnalyzing(false);
             } else if (statusRes.data.status === 'processing') {
                if(!logs.includes("Agent is scanning...")) setLogs(prev => [...prev, "Agent is scanning...", "Analyzing heuristics..."]);
             }
           } catch(e) {}
        }, 1000);

      } catch (e) {
        setLogs(prev => [...prev, "Error: Device unreachable or offline."]);
      }
    };

    startScan();
    return () => clearInterval(pollInterval);
  }, [target]);

  const handleExecution = () => {
      setIsExecuting(true);
      setTimeout(() => { setIsExecuting(false); onClose(); }, 1500);
  };

  const handleDownload = () => {
    if (!report) return;
    const content = `ORG-WATCH AI FORENSIC REPORT\n============================\nDate: ${new Date().toLocaleString()}\nTarget: ${target.name}\nID: ${target.id}\n\nVERDICT: ${report.verdict}\nRISK SCORE: ${report.riskScore}/100\n\nFINDINGS:\n${report.findings.join('\n')}`;
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Report_${target.id}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-slate-950/80 backdrop-blur-md" onClick={onClose} />
      <motion.div initial={{ scale: 0.9, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} className="relative w-full max-w-3xl bg-slate-900 border border-cyan-500/30 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[85vh]">
        <div className="p-4 border-b border-cyan-500/20 bg-cyan-950/20 flex justify-between items-center">
          <div className="flex items-center gap-3"><Sparkles className="text-cyan-400 animate-pulse" size={20} /><h3 className="text-cyan-50 font-bold tracking-widest uppercase">OrgWatch Cortex <span className="text-cyan-400">AI</span></h3></div>
          <button onClick={onClose} className="text-slate-400 hover:text-white"><X size={20} /></button>
        </div>
        <div className="flex-1 overflow-y-auto p-6 bg-slate-950/50">
          {isAnalyzing ? (
            <div className="font-mono text-sm space-y-3">
              {logs.map((log, i) => (
                <motion.div key={i} initial={{ x: -10, opacity: 0 }} animate={{ x: 0, opacity: 1 }} className="text-cyan-300/80 flex gap-2"><span className="text-slate-600">[{new Date().toLocaleTimeString()}]</span>{`> ${log}`}</motion.div>
              ))}
              <div className="flex items-center gap-2 text-cyan-400 mt-4"><Loader2 size={16} className="animate-spin" /> Processing Neural Matrix...</div>
            </div>
          ) : (
            <div className="space-y-8 animate-fade-in">
              <div className="grid grid-cols-2 gap-4">
                <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 relative overflow-hidden">
                  <div className="absolute top-0 right-0 p-4 opacity-10"><BrainCircuit size={80} className="text-cyan-500"/></div>
                  <div className="text-slate-400 text-xs font-bold uppercase mb-2">Verdict</div>
                  <div className={cn("text-xl font-bold flex items-center gap-2", report?.riskScore > 50 ? "text-red-400" : "text-emerald-400")}>{report?.riskScore > 50 ? <Skull size={24} /> : <CheckCircle2 size={24} />}{report?.verdict}</div>
                </div>
                <div className="p-6 rounded-xl bg-slate-900 border border-slate-800">
                   <div className="text-slate-400 text-xs font-bold uppercase mb-2">AI Confidence</div>
                   <div className="text-3xl font-mono text-white">{report?.confidence || "99.1%"}</div>
                   <div className="w-full bg-slate-800 h-1.5 mt-4 rounded-full overflow-hidden"><motion.div initial={{ width: 0 }} animate={{ width: "99%" }} className="h-full bg-cyan-500 shadow-[0_0_10px_rgba(6,182,212,0.5)]" /></div>
                </div>
              </div>
              <div>
                <h4 className="text-white font-semibold mb-4 flex items-center gap-2"><FileText size={18} className="text-cyan-400"/> Forensic Findings</h4>
                <div className="space-y-3">{report?.findings?.map((f, i) => (<motion.div key={i} initial={{ x: -20, opacity: 0 }} animate={{ x: 0, opacity: 1, transition: { delay: i * 0.1 } }} className="flex items-start gap-3 text-sm text-slate-300 p-3 rounded-lg bg-slate-800/40 border-l-2 border-red-500/50">{f}</motion.div>))}</div>
              </div>
            </div>
          )}
        </div>
        {!isAnalyzing && (
          <div className="p-4 border-t border-slate-800 bg-slate-900 flex justify-end gap-3">
            <button onClick={handleDownload} className="px-4 py-2 border border-slate-700 text-slate-300 hover:text-white hover:bg-slate-800 rounded-lg text-sm flex items-center gap-2"><Download size={16} /> Download Report</button>
            <button onClick={handleExecution} disabled={isExecuting} className={cn("px-6 py-2 text-white font-medium rounded-lg shadow-lg transition-all flex items-center gap-2", "bg-gradient-to-r from-red-600 to-red-800 hover:shadow-red-500/20")}>
              {isExecuting ? <Loader2 size={16} className="animate-spin" /> : <Terminal size={16} />} {isExecuting ? "Executing..." : "Resolve"}
            </button>
          </div>
        )}
      </motion.div>
    </div>
  );
};

// --- DETAIL MODAL ---
const DeviceDetailModal = ({ device, onClose, onAnalyze, onIsolate }) => {
  if (!device) return null;
  const historyData = device.history || generateHistory();
  const deviceRadar = [
    { subject: 'CPU', A: parseInt(device.cpu_usage) || 50, fullMark: 100 },
    { subject: 'RAM', A: parseInt(device.ram_usage) || 50, fullMark: 100 },
    { subject: 'Disk', A: 45, fullMark: 100 },
    { subject: 'Net', A: 80, fullMark: 100 },
    { subject: 'Temp', A: 60, fullMark: 100 },
  ];

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div className="absolute inset-0 bg-slate-950/60 backdrop-blur-sm" onClick={onClose} />
      <motion.div initial={{ x: "100%" }} animate={{ x: 0 }} exit={{ x: "100%" }} transition={{ type: "spring", damping: 25, stiffness: 200 }} className="relative w-full max-w-2xl bg-slate-950 h-full shadow-2xl flex flex-col border-l border-slate-800">
        <div className="p-6 border-b border-slate-800 flex justify-between items-center bg-slate-900">
           <div>
             <h3 className="text-2xl font-bold text-white">{device.name}</h3>
             <div className="flex items-center gap-3 mt-1"><StatusBadge status={device.status} /><span className="text-slate-500 text-sm font-mono">{device.ip} • {device.os}</span></div>
           </div>
           <button onClick={onClose} className="p-2 hover:bg-slate-800 rounded-full text-slate-400"><X size={24} /></button>
        </div>
        <div className="flex-1 overflow-y-auto p-8 space-y-8 bg-slate-950">
           <div className="grid grid-cols-3 gap-4">
              <div className="p-4 bg-slate-900 rounded-xl border border-slate-800">
                <div className="text-slate-500 text-xs font-bold mb-1">RISK SCORE</div>
                <div className="text-3xl font-bold text-white">{device.risk}/100</div>
                <div className="w-full bg-slate-800 h-1 mt-2 rounded-full overflow-hidden"><div className={cn("h-full", device.risk > 50 ? "bg-red-500" : "bg-emerald-500")} style={{width: `${device.risk}%`}}/></div>
              </div>
              <div className="p-4 bg-slate-900 rounded-xl border border-slate-800"><div className="text-slate-500 text-xs font-bold mb-1">CPU LOAD</div><div className="text-3xl font-bold text-cyan-400">{device.cpu_usage || "0%"}</div></div>
              <div className="p-4 bg-slate-900 rounded-xl border border-slate-800"><div className="text-slate-500 text-xs font-bold mb-1">RAM USAGE</div><div className="text-3xl font-bold text-purple-400">{device.ram_usage || "0%"}</div></div>
           </div>
           <div className="h-64 bg-slate-900/50 rounded-xl border border-slate-800 p-4">
             <h4 className="text-white font-semibold mb-4 text-sm flex gap-2"><Activity size={16}/> Real-time Resource Usage</h4>
             <ResponsiveContainer width="100%" height="100%">
               <AreaChart data={historyData}>
                 <defs><linearGradient id="colorCpu" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3}/><stop offset="95%" stopColor="#06b6d4" stopOpacity={0}/></linearGradient></defs>
                 <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} />
                 <XAxis dataKey="time" stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} />
                 <Tooltip contentStyle={{backgroundColor: '#0f172a', borderColor: '#1e293b', color: '#fff'}} itemStyle={{color: '#fff'}} />
                 <Area type="monotone" dataKey="usage" stroke="#06b6d4" strokeWidth={2} fillOpacity={1} fill="url(#colorCpu)" />
               </AreaChart>
             </ResponsiveContainer>
           </div>
           <div className="h-64 bg-slate-900/50 rounded-xl border border-slate-800 p-4">
              <h4 className="text-white font-semibold mb-4 text-sm flex gap-2"><ScanEye size={16}/> Device Health Profile</h4>
              <ResponsiveContainer width="100%" height="100%">
                <RadarChart cx="50%" cy="50%" outerRadius="80%" data={deviceRadar}>
                  <PolarGrid stroke="#334155" />
                  <PolarAngleAxis dataKey="subject" tick={{ fill: '#94a3b8', fontSize: 12 }} />
                  <PolarRadiusAxis angle={30} domain={[0, 100]} tick={false} axisLine={false} />
                  <Radar name="Device" dataKey="A" stroke="#8b5cf6" strokeWidth={2} fill="#8b5cf6" fillOpacity={0.3} />
                </RadarChart>
              </ResponsiveContainer>
           </div>
        </div>
        <div className="p-6 border-t border-slate-800 bg-slate-900 flex gap-4">
           <button onClick={() => onAnalyze(device)} className="flex-1 py-3 bg-indigo-600 text-white font-bold rounded-lg hover:bg-indigo-700 flex items-center justify-center gap-2 shadow-lg shadow-indigo-500/20"><Bot size={18}/> Run AI Diagnostics</button>
           <button onClick={() => onIsolate(device.id)} disabled={device.status === 'isolated' || device.status === 'offline'} className="px-4 py-3 bg-red-600/10 text-red-500 border border-red-500/20 font-bold rounded-lg hover:bg-red-600 hover:text-white flex items-center justify-center gap-2 transition-all disabled:opacity-50"><Power size={18}/> {device.status === 'isolated' ? 'Isolated' : 'Isolate'}</button>
        </div>
      </motion.div>
    </div>
  );
};

// --- VIEWS ---

const DashboardView = ({ devices, alerts }) => (
  <div className="space-y-6 animate-fade-in pb-10">
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
      <GlassCard className="flex items-center justify-between"><div><p className="text-slate-400 text-xs font-bold uppercase tracking-wider">Total Fleet</p><h3 className="text-3xl font-bold text-white mt-1">{devices.length}</h3><div className="text-emerald-400 text-xs font-bold mt-2 flex items-center gap-1"><Wifi size={12}/> 98% Online</div></div><div className="p-3 bg-cyan-500/10 rounded-xl text-cyan-400"><Server size={24} /></div></GlassCard>
      <GlassCard className="flex items-center justify-between"><div><p className="text-slate-400 text-xs font-bold uppercase tracking-wider">Active Threats</p><h3 className="text-3xl font-bold text-white mt-1">{alerts.length}</h3><div className="text-red-400 text-xs font-bold mt-2 flex items-center gap-1"><AlertTriangle size={12}/> +12% Spike</div></div><div className="p-3 bg-red-500/10 rounded-xl text-red-400"><ShieldAlert size={24} /></div></GlassCard>
      <GlassCard className="flex items-center justify-between"><div><p className="text-slate-400 text-xs font-bold uppercase tracking-wider">Security Score</p><h3 className="text-3xl font-bold text-white mt-1">84<span className="text-lg text-slate-500">/100</span></h3><div className="text-emerald-400 text-xs font-bold mt-2 flex items-center gap-1"><CheckCircle2 size={12}/> Optimal</div></div><div className="p-3 bg-emerald-500/10 rounded-xl text-emerald-400"><Activity size={24} /></div></GlassCard>
      <GlassCard className="flex items-center justify-between"><div><p className="text-slate-400 text-xs font-bold uppercase tracking-wider">Network Load</p><h3 className="text-3xl font-bold text-white mt-1">4.2<span className="text-lg text-slate-500"> TB</span></h3><div className="text-cyan-400 text-xs font-bold mt-2 flex items-center gap-1"><Zap size={12}/> Heavy Load</div></div><div className="p-3 bg-purple-500/10 rounded-xl text-purple-400"><BarChart3 size={24} /></div></GlassCard>
    </div>
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <GlassCard className="lg:col-span-2 min-h-[400px]">
        <div className="flex justify-between items-center mb-6"><h3 className="text-white font-bold flex items-center gap-2"><Globe size={18} className="text-cyan-400"/> Global Network Traffic</h3><select className="bg-slate-800 text-slate-300 text-xs rounded border border-slate-700 px-2 py-1 outline-none"><option>Last 24 Hours</option><option>Last 7 Days</option></select></div>
        <div className="h-[320px]">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={generateHistory()}>
              <defs>
                <linearGradient id="colorNet" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3}/><stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/></linearGradient>
                <linearGradient id="colorThreat" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#ef4444" stopOpacity={0.3}/><stop offset="95%" stopColor="#ef4444" stopOpacity={0}/></linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} />
              <XAxis dataKey="time" stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} />
              <YAxis stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} />
              <Tooltip contentStyle={{backgroundColor: '#0f172a', borderColor: '#1e293b', color: '#fff'}} />
              <Area type="monotone" dataKey="network" stroke="#3b82f6" strokeWidth={2} fill="url(#colorNet)" />
              <Area type="monotone" dataKey="threats" stroke="#ef4444" strokeWidth={2} fill="url(#colorThreat)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </GlassCard>
      <GlassCard>
        <h3 className="text-white font-bold mb-6 flex items-center gap-2"><ShieldCheck size={18} className="text-purple-400"/> Attack Vector Analysis</h3>
        <div className="h-[320px]">
          <ResponsiveContainer width="100%" height="100%">
            <RadarChart cx="50%" cy="50%" outerRadius="80%" data={RADAR_DATA}>
              <PolarGrid stroke="#334155" />
              <PolarAngleAxis dataKey="subject" tick={{ fill: '#94a3b8', fontSize: 11 }} />
              <PolarRadiusAxis angle={30} domain={[0, 150]} tick={false} axisLine={false} />
              <Radar name="Threats" dataKey="A" stroke="#8b5cf6" strokeWidth={2} fill="#8b5cf6" fillOpacity={0.4} />
              <Tooltip contentStyle={{backgroundColor: '#0f172a', borderColor: '#1e293b', color: '#fff'}} />
            </RadarChart>
          </ResponsiveContainer>
        </div>
      </GlassCard>
    </div>
  </div>
);

const ThreatIntelView = () => (
  <div className="space-y-6 animate-fade-in pb-10">
    <div className="flex gap-4 mb-4">
      <div className="p-4 bg-red-950/20 border border-red-500/20 rounded-xl flex-1 flex items-center gap-4">
        <div className="p-3 bg-red-500/20 rounded-full text-red-500"><Globe2 size={24}/></div>
        <div><div className="text-sm text-slate-400">Global Threat Level</div><div className="text-2xl font-bold text-white">ELEVATED</div></div>
      </div>
      <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl flex-1 flex items-center gap-4">
        <div className="p-3 bg-slate-800 rounded-full text-slate-400"><Hash size={24}/></div>
        <div><div className="text-sm text-slate-400">IOCs Ingested</div><div className="text-2xl font-bold text-white">12,402</div></div>
      </div>
    </div>
    <GlassCard>
      <div className="flex justify-between items-center mb-6">
        <h3 className="text-white font-bold flex items-center gap-2"><FileJson size={18} className="text-cyan-400"/> Live Indicator Feed</h3>
        <div className="flex gap-2">
          <button className="px-3 py-1.5 bg-slate-800 text-xs text-slate-300 rounded-lg hover:text-white">IP Addresses</button>
          <button className="px-3 py-1.5 bg-slate-800 text-xs text-slate-300 rounded-lg hover:text-white">Hashes</button>
          <button className="px-3 py-1.5 bg-slate-800 text-xs text-slate-300 rounded-lg hover:text-white">Domains</button>
        </div>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-slate-800 text-slate-500 text-sm">
              <th className="p-3 font-medium">Indicator ID</th>
              <th className="p-3 font-medium">Type</th>
              <th className="p-3 font-medium">Value</th>
              <th className="p-3 font-medium">Origin</th>
              <th className="p-3 font-medium">Date</th>
              <th className="p-3 font-medium">Reputation</th>
              <th className="p-3 font-medium text-right">Action</th>
            </tr>
          </thead>
          <tbody>
            {THREAT_INTEL_DATA.map((ioc, i) => (
              <tr key={i} className="border-b border-slate-800/50 text-slate-300 hover:bg-slate-800/30">
                <td className="p-3 font-mono text-cyan-400 text-xs">{ioc.id}</td>
                <td className="p-3 text-sm">{ioc.type}</td>
                <td className="p-3 font-mono text-slate-400 text-xs">{ioc.value}</td>
                <td className="p-3 text-sm">{ioc.origin}</td>
                <td className="p-3 text-sm text-slate-500">{ioc.date}</td>
                <td className="p-3"><span className="px-2 py-1 bg-red-500/10 text-red-400 rounded text-xs border border-red-500/20">{ioc.reputation}</span></td>
                <td className="p-3 text-right"><button className="p-1 hover:text-cyan-400 text-slate-500"><ExternalLink size={14}/></button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </GlassCard>
  </div>
);

const SettingsView = () => (
  <div className="space-y-6 animate-fade-in max-w-4xl mx-auto">
    <GlassCard>
      <h3 className="text-white font-bold mb-6 text-lg border-b border-slate-800 pb-4">System Configuration</h3>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div><div className="text-white font-medium">Multi-Factor Authentication</div><div className="text-sm text-slate-500">Require 2FA for all admin logins</div></div>
          <ToggleRight className="text-emerald-500 cursor-pointer" size={32} />
        </div>
        <div className="flex items-center justify-between">
          <div><div className="text-white font-medium">AI Auto-Response</div><div className="text-sm text-slate-500">Allow Cortex to isolate devices automatically if risk &gt; 90%</div></div>
          <ToggleRight className="text-slate-600 cursor-pointer" size={32} />
        </div>
        <div className="flex items-center justify-between">
          <div><div className="text-white font-medium">Data Retention</div><div className="text-sm text-slate-500">Log storage period (Days)</div></div>
          <input type="number" className="bg-slate-950 border border-slate-800 text-white p-2 rounded w-20 text-center" defaultValue={90} />
        </div>
        <div className="pt-4 border-t border-slate-800 flex justify-end">
          <button className="px-6 py-2 bg-cyan-600 hover:bg-cyan-500 text-white font-bold rounded-lg transition-all">Save Changes</button>
        </div>
      </div>
    </GlassCard>
  </div>
);

// --- APP SHELL ---

export default function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [activeView, setActiveView] = useState('dashboard');
  const [selectedDevice, setSelectedDevice] = useState(null);
  const [aiAnalysis, setAiAnalysis] = useState({ isOpen: false, type: null, target: null });
  const [devices, setDevices] = useState([]); // Start empty, fetch real data
  const [alerts, setAlerts] = useState(INITIAL_ALERTS);
  const [toasts, setToasts] = useState([]);

  // PRODUCTION URL CONFIGURATION
  // Replace this string with the URL Render gives you after deployment
  const API_BASE = "https://orgwatch-api.onrender.com"; 

  // Fetch devices
  useEffect(() => {
    if (isLoggedIn) {
      const fetchDevices = async () => {
        try {
          const res = await axios.get(`${API_BASE}/api/devices`);
          setDevices(res.data.length > 0 ? res.data : INITIAL_DEVICES); // Use Initial if Backend empty
        } catch (error) {
          console.error("API Error", error);
          setDevices(INITIAL_DEVICES); // Fallback
        }
      };
      
      fetchDevices();
      const interval = setInterval(fetchDevices, 3000); 
      return () => clearInterval(interval);
    }
  }, [isLoggedIn]);

  const addToast = (message, type = 'info') => {
    const id = Date.now();
    setToasts(prev => [...prev, { id, message, type }]);
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 4000);
  };

  const handleIsolateDevice = (id) => {
    setSelectedDevice(null);
    setAiAnalysis({ isOpen: false, type: null, target: null });
    addToast('Initiating isolation protocol...', 'info');
    setTimeout(() => {
      setDevices(prev => prev.map(d => d.id === id ? { ...d, status: 'isolated', risk: 0 } : d));
      addToast(`Device ${id} successfully isolated.`, 'success');
    }, 1500);
  };

  const handleLogin = () => setIsLoggedIn(true);
  const handleLogout = () => setIsLoggedIn(false);

  if (!isLoggedIn) {
    return (
      <div className="relative">
        <LoginScreen onLogin={handleLogin} />
        <div className="fixed bottom-6 right-6 z-50 flex flex-col gap-3">
          {toasts.map(toast => (
            <div key={toast.id} className="px-4 py-3 rounded-xl shadow-lg border border-slate-800 bg-slate-900 text-white">{toast.message}</div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen bg-slate-950 font-sans text-slate-200 overflow-hidden selection:bg-cyan-500/30">
      <aside className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col z-20">
        <div className="h-20 flex items-center px-6 border-b border-slate-800 bg-slate-900/50 backdrop-blur-md">
          <Activity className="text-cyan-400 mr-3" size={28} />
          <h1 className="text-xl font-bold tracking-wider text-white">ORG<span className="text-cyan-400">WATCH</span></h1>
        </div>
        <nav className="flex-1 py-8 px-4 space-y-2">
           {[
             { id: 'dashboard', label: 'Mission Control', icon: LayoutDashboard },
             { id: 'devices', label: 'Device Assets', icon: Monitor },
             { id: 'alerts', label: 'Threat Intel', icon: ShieldAlert },
             { id: 'settings', label: 'System Config', icon: Settings },
           ].map(item => (
             <button key={item.id} onClick={() => setActiveView(item.id)} className={cn("w-full flex items-center gap-4 px-4 py-3.5 rounded-xl text-sm font-medium transition-all duration-300 relative overflow-hidden group", activeView === item.id ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 shadow-[0_0_15px_rgba(6,182,212,0.1)]" : "text-slate-400 hover:bg-slate-800 hover:text-slate-200")}>
               <item.icon size={20} className={cn("relative z-10 transition-transform group-hover:scale-110", activeView === item.id && "animate-pulse")} />
               <span className="relative z-10">{item.label}</span>
               {activeView === item.id && <div className="absolute left-0 top-0 h-full w-1 bg-cyan-400" />}
             </button>
           ))}
        </nav>
        <div className="p-4 border-t border-slate-800 bg-slate-900/50">
           <div className="flex items-center gap-3 p-3 rounded-xl bg-slate-800 border border-slate-700 mb-3">
              <div className="w-10 h-10 rounded-full bg-gradient-to-tr from-cyan-500 to-blue-600 flex items-center justify-center font-bold text-white shadow-lg">AD</div>
              <div><div className="text-sm font-bold text-white">Admin User</div><div className="text-xs text-slate-400">SecOps Lead</div></div>
           </div>
           <button onClick={handleLogout} className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-red-500/10 text-red-400 text-sm font-bold hover:bg-red-500 hover:text-white transition-all"><LogOut size={16} /> Sign Out</button>
        </div>
      </aside>

      <div className="flex-1 flex flex-col relative overflow-hidden">
        <div className="absolute inset-0 bg-[url('https://grainy-gradients.vercel.app/noise.svg')] opacity-5 pointer-events-none"/>
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#80808012_1px,transparent_1px),linear-gradient(to_bottom,#80808012_1px,transparent_1px)] bg-[size:24px_24px] pointer-events-none" />
        
        <header className="h-20 border-b border-slate-800 bg-slate-900/40 backdrop-blur-sm flex items-center justify-between px-8 z-10">
           <h2 className="text-2xl font-bold text-white flex items-center gap-3">
             {activeView === 'dashboard' && <><LayoutDashboard className="text-cyan-400"/> Mission Control</>}
             {activeView === 'devices' && <><Monitor className="text-purple-400"/> Device Fleet</>}
             {activeView === 'alerts' && <><ShieldAlert className="text-red-400"/> Threat Intel</>}
             {activeView === 'settings' && <><Settings className="text-slate-400"/> System Config</>}
           </h2>
           <div className="flex items-center gap-6">
              <div className="relative">
                 <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" size={18} />
                 <input type="text" placeholder="Search systems..." className="bg-slate-950 border border-slate-800 rounded-full pl-10 pr-4 py-2 text-sm focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/50 outline-none w-64 transition-all" />
              </div>
              <button className="relative p-2 text-slate-400 hover:text-white transition-colors"><Bell size={20} /><span className="absolute top-1.5 right-2 w-2 h-2 bg-red-500 rounded-full animate-ping" /><span className="absolute top-1.5 right-2 w-2 h-2 bg-red-500 rounded-full" /></button>
           </div>
        </header>

        <main className="flex-1 overflow-y-auto p-8 relative z-0">
          <AnimatePresence mode="wait">
             <motion.div key={activeView} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }} transition={{ duration: 0.2 }}>
               {activeView === 'dashboard' && <DashboardView devices={devices} alerts={alerts} />}
               {activeView === 'devices' && (
                 <div className="grid gap-4">
                    {devices.length === 0 && <div className="text-slate-500 text-center mt-10">No agents connected. Run the Desktop Agent to enroll.</div>}
                    {devices.map((d) => (
                      <div key={d.id} onClick={() => setSelectedDevice(d)} className="group bg-slate-900/40 p-5 rounded-xl border border-slate-800 hover:border-cyan-500/40 hover:bg-slate-800/60 transition-all cursor-pointer flex items-center justify-between">
                         <div className="flex items-center gap-4">
                            <div className={cn("p-3 rounded-xl transition-colors", d.risk > 50 ? "bg-red-500/10 text-red-500" : "bg-cyan-500/10 text-cyan-500")}>{d.type === 'server' ? <Server size={24}/> : <Laptop size={24}/>}</div>
                            <div><h4 className="text-lg font-bold text-white group-hover:text-cyan-400 transition-colors">{d.name}</h4><div className="flex items-center gap-3 text-sm text-slate-400 mt-1"><span className="font-mono">{d.ip}</span></div></div>
                         </div>
                         <div className="flex items-center gap-8"><StatusBadge status={d.status} /><ChevronRight className="text-slate-600 group-hover:text-white transition-colors" /></div>
                      </div>
                    ))}
                 </div>
               )}
               {activeView === 'alerts' && <ThreatIntelView />}
               {activeView === 'settings' && <SettingsView />}
             </motion.div>
          </AnimatePresence>
        </main>
      </div>

      <AnimatePresence>
        {selectedDevice && <DeviceDetailModal device={selectedDevice} onClose={() => setSelectedDevice(null)} onAnalyze={() => setAiAnalysis({ isOpen: true, type: 'device', target: selectedDevice })} onIsolate={handleIsolateDevice} />}
        {aiAnalysis.isOpen && <AIAnalysisModal target={aiAnalysis.target} type={aiAnalysis.type} onClose={() => setAiAnalysis({ isOpen: false, target: null })} onExecute={(id) => handleIsolateDevice(id)} />}
      </AnimatePresence>

      <div className="fixed bottom-6 right-6 z-50 flex flex-col gap-3">
        {toasts.map(toast => (
          <div key={toast.id} className="px-4 py-3 rounded-xl shadow-lg border border-slate-700 bg-slate-900 text-white flex items-center gap-2">
            {toast.type === 'success' ? <CheckCircle2 className="text-emerald-500"/> : <Activity className="text-cyan-500"/>}
            {toast.message}
          </div>
        ))}
      </div>
    </div>
  );
}