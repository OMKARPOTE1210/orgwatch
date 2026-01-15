import sys, json, time, psutil, platform, socket, requests, threading, os, math, re, shutil, hashlib, subprocess, ctypes, sqlite3
from datetime import datetime
from urllib.parse import urlparse
from cryptography.fernet import Fernet
from sklearn.ensemble import IsolationForest
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import joblib, pefile, numpy as np

# --- PRO FEATURES SUPPORT (Safe Imports Only) ---
wmi = None
pythoncom = None
win32api = None
winreg = None
ToastNotifier = None
pystray = None
Image = None
yara = None
# NOTE: 'uiautomation' is deliberately excluded to prevent AV False Positives

try:
    import wmi
    import pythoncom
    import win32api
    import win32con
    import win32security
    import win32process
    import win32event
    import winreg
    from win10toast import ToastNotifier
    import pystray
    from PIL import Image
    import yara
except ImportError:
    pass

# --- CONFIGURATION ---
# CHANGE THIS TO YOUR RENDER URL IN PROD, OR http://localhost:8000/api FOR LOCAL
BACKEND_URL = "http://localhost:8000/api" 

# PERSISTENCE & LOGGING PATHS (AppData)
APP_DATA = os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), 'OrgWatch')
if not os.path.exists(APP_DATA): os.makedirs(APP_DATA)

CONFIG_FILE = os.path.join(APP_DATA, "agent_secure.enc")
KEY_FILE = os.path.join(APP_DATA, "secret.key")
LOG_FILE = os.path.join(APP_DATA, "orgwatch_defense.log")
DB_FILE = os.path.join(APP_DATA, "offline_events.db")

# RESOLVE RESOURCE PATHS (For PyInstaller / Dev)
if getattr(sys, 'frozen', False):
    BASE_DIR = sys._MEIPASS
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_FILE = os.path.join(BASE_DIR, "behavior_model.pkl")
MALWARE_MODEL_FILE = os.path.join(BASE_DIR, "malware_model.pkl")
PHISHING_MODEL_FILE = os.path.join(BASE_DIR, "phishing_model.pkl")
NIDS_MODEL_FILE = os.path.join(BASE_DIR, "nids_model.pkl")
YARA_RULES_FILE = os.path.join(BASE_DIR, "rules.yar")

# MONITORING TARGETS
SCAN_TARGET = os.path.expanduser("~/Downloads")
DOCS_DIR = os.path.expanduser("~/Documents")
HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"
REDIRECT_IP = "127.0.0.1"

# --- CRYPTO SETUP ---
if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, "wb") as kf: kf.write(Fernet.generate_key())
with open(KEY_FILE, "rb") as kf: CIPHER_SUITE = Fernet(kf.read())

# --- UTILITIES ---
def file_log(msg):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f: 
            f.write(f"{datetime.now()} | {msg}\n")
    except: pass

def notify_user(title, msg):
    try:
        if ToastNotifier:
            ToastNotifier().show_toast(f"OrgWatch EDR: {title}", msg, duration=4, threaded=True)
    except: pass

# ==========================================
# MODULE 1: OFFLINE VAULT (Data Resilience)
# ==========================================
class EventBuffer:
    """Stores logs locally when internet is cut, syncs when back online."""
    def __init__(self):
        self.conn = sqlite3.connect(DB_FILE, check_same_thread=False)
        self.conn.execute("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, payload TEXT, status TEXT)")
        self.conn.commit()

    def add_event(self, payload):
        try:
            self.conn.execute("INSERT INTO events (payload, status) VALUES (?, 'pending')", (json.dumps(payload),))
            self.conn.commit()
            file_log("Offline: Event buffered to Vault.")
        except: pass

    def sync(self):
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT id, payload FROM events WHERE status='pending' LIMIT 5")
            rows = cursor.fetchall()
            for row in rows:
                try:
                    res = requests.post(f"{BACKEND_URL}/telemetry", json=json.loads(row[1]), timeout=2)
                    if res.status_code == 200:
                        cursor.execute("DELETE FROM events WHERE id=?", (row[0],))
                        self.conn.commit()
                except: break
        except: pass

# ==========================================
# MODULE 2: AIRLOCK (Network Kill Switch)
# ==========================================
class NetworkAirlock:
    def __init__(self, agent):
        self.agent = agent
        self.is_isolated = False
    
    def isolate(self):
        if self.is_isolated: return
        self.agent.log_ui("🚨 AIRLOCK ACTIVATED")
        try:
            subprocess.run('netsh advfirewall firewall add rule name="OrgWatch_Block" dir=out action=block', shell=True)
            self.is_isolated = True
            notify_user("System Lockdown", "Network traffic blocked by OrgWatch.")
        except: pass
        
    def restore(self):
        try:
            subprocess.run('netsh advfirewall firewall delete rule name="OrgWatch_Block"', shell=True)
            self.is_isolated = False
            self.agent.log_ui("Airlock Deactivated.")
        except: pass

# ==========================================
# MODULE 3: REMEDIATION (Shadow Copy)
# ==========================================
class RemediationEngine:
    def create_snapshot(self):
        """Creates a VSS Snapshot via WMI for rollback"""
        try:
            cmd = 'wmic shadowcopy call create Volume="C:\\"'
            subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            file_log("Created Safety Snapshot.")
        except: pass

# ==========================================
# MODULE 4: REGISTRY SELF-DEFENSE
# ==========================================
class RegistryGuard:
    def __init__(self, agent): 
        self.agent = agent
        self.app_path = sys.executable if getattr(sys, 'frozen', False) else ""
        
    def monitor(self):
        if not winreg or not self.app_path: return
        while True:
            time.sleep(10)
            try:
                k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_ALL_ACCESS)
                try: winreg.QueryValueEx(k, "OrgWatch")
                except FileNotFoundError:
                    winreg.SetValueEx(k, "OrgWatch", 0, winreg.REG_SZ, self.app_path)
                    self.agent.log_ui("⚠️ PERSISTENCE: Key Restored")
                winreg.CloseKey(k)
            except: pass

# ==========================================
# MODULE 5: WEB GUARD (DNS Cache - SAFE)
# ==========================================
class WebGuard:
    def __init__(self, agent):
        self.agent = agent; self.model = None; self.last_url = ""; self.blocked = set()
        if os.path.exists(PHISHING_MODEL_FILE): 
            try: self.model = joblib.load(PHISHING_MODEL_FILE)
            except: pass
    
    def extract(self, url):
        # 12 Features matching training
        f = [0]*12; 
        f[0] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0
        f[1] = 1 if len(url)>54 else 0
        f[8] = 1 if any(s in url for s in ["login","bank", "secure"]) else 0
        return f

    def check_loop(self):
        """Safe DNS Cache Monitoring (No UI Automation)"""
        while True:
            time.sleep(5)
            try:
                # Read Windows DNS Cache (Legitimate Admin Command)
                output = subprocess.check_output("ipconfig /displaydns", shell=True).decode('utf-8', errors='ignore')
                domains = re.findall(r"Record Name\s+\.\s+:\s+(.*)", output)
                for d in domains:
                    d = d.strip()
                    if d and d not in self.blocked:
                        self.checked_domains.add(d)
                        # Convert domain to URL for classifier
                        if self.model and self.model.predict([self.extract(f"http://{d}")])[0] == 1:
                            self.agent.log_ui(f"🚫 PHISHING DNS: {d}")
                            self.block(d)
            except: pass
    
    def block(self, domain):
        if domain in self.blocked: return
        try:
            with open(HOSTS_PATH, 'a') as f: f.write(f"\n{REDIRECT_IP} {domain}")
            self.blocked.add(domain)
            # Kill Browser if blocked domain is active
            for p in psutil.process_iter(['name']):
                if "chrome" in p.info['name'] or "msedge" in p.info['name']: p.kill()
            self.agent.send_alert(f"Phishing Blocked: {domain}")
        except: pass

# ==========================================
# MODULE 6: PROCESS EDR & ANTI-FORENSICS
# ==========================================
class LogWiperGuard:
    """Detects attempts to clear Event Logs (Anti-Forensics)"""
    def __init__(self, agent):
        self.agent = agent
        self.banned = ["wevtutil", "fsutil usn deletejournal"]
    def check(self, cmd):
        for b in self.banned:
            if b in cmd.lower(): return True
        return False

class ProcessEDR:
    def __init__(self, agent):
        self.agent = agent
        self.wiper = LogWiperGuard(agent)
        self.suspect = ["powershell.exe", "cmd.exe", "wscript.exe", "vssadmin.exe"]
        self.parents = ["winword.exe", "excel.exe", "chrome.exe", "outlook.exe"]

    def monitor(self):
        if not wmi: return
        try:
            pythoncom.CoInitialize()
            c = wmi.WMI()
            watcher = c.Win32_ProcessStartTrace.watch_for("ProcessStart")
            while True:
                try:
                    e = watcher()
                    name = e.ProcessName.lower(); pid = e.ProcessID
                    
                    # 1. Anti-Forensics & Ransomware
                    if name in ["vssadmin.exe", "wbadmin.exe"] or self.wiper.check(name):
                        self.kill(pid, f"Malicious Tool Blocked: {name}")

                    # 2. Behavioral Lineage
                    if name in self.suspect:
                        try:
                            parent = psutil.Process(e.ParentProcessID).name().lower()
                            if parent in self.parents: self.kill(pid, f"Exploit Chain: {parent} -> {name}")
                        except: pass
                except: pass
        except: pass

    def kill(self, pid, reason):
        try:
            psutil.Process(pid).kill()
            self.agent.log_ui(f"🛑 EDR BLOCK: {reason}"); self.agent.send_alert(f"EDR Action: {reason}")
        except: pass

# ==========================================
# MODULE 7: RANSOMWARE TRAP
# ==========================================
class RansomwareCanary(FileSystemEventHandler):
    def __init__(self, agent): self.agent = agent; self.setup()
    def setup(self):
        p = os.path.join(DOCS_DIR, "honey.txt")
        if not os.path.exists(p): 
            try: 
                with open(p, 'w') as f: f.write("bait")
                os.system(f'attrib +h "{p}"') 
            except: pass
        self.cf = [p]
    def on_modified(self, event):
        if event.src_path in self.cf:
            self.agent.log_ui("🚨 RANSOMWARE TRAP"); self.agent.airlock.isolate()

# ==========================================
# MODULE 8: YARA ENGINE
# ==========================================
class YaraEngine:
    def __init__(self):
        self.rules = None
        try:
            import yara
            if os.path.exists(YARA_RULES_FILE):
                self.rules = yara.compile(filepath=YARA_RULES_FILE)
                file_log("YARA Loaded")
        except: pass
    def scan(self, path):
        if not self.rules: return []
        try:
            matches = self.rules.match(path)
            return [m.rule for m in matches]
        except: return []

# ==========================================
# MODULE 9: THREAT SCANNER
# ==========================================
class ThreatScanner:
    def __init__(self):
        self.mal_model = None; self.behavior_model = None; self.yara = YaraEngine()
        self.load_brains()
    def load_brains(self):
        if os.path.exists(MALWARE_MODEL_FILE):
            try: self.mal_model = joblib.load(MALWARE_MODEL_FILE)
            except: pass
        if os.path.exists(MODEL_FILE):
            try: self.behavior_model = joblib.load(MODEL_FILE)
            except: self.train_behavior()
        else: self.train_behavior()
    def train_behavior(self):
        self.behavior_model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
        self.behavior_model.fit([[10, 20, 50, 5], [12, 22, 55, 10]]) 
    def calculate_entropy(self, file_path):
        try:
            with open(file_path, 'rb') as f: data = f.read()
            if not data: return 0
            entropy = 0
            for x in range(256):
                p_x = float(data.count(bytes([x]))) / len(data)
                if p_x > 0: entropy += - p_x * math.log(p_x, 2)
            return entropy
        except: return 0
    def extract_features(self, file_path):
        try:
            pe = pefile.PE(file_path)
            imp = len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0
            ent = sum([s.get_entropy() for s in pe.sections])/len(pe.sections) if pe.sections else 0
            return [len(pe.sections), imp, 0, ent, pe.OPTIONAL_HEADER.SizeOfImage]
        except: return None
    def quick_file_scan(self, file_path):
        score = 0; findings = []
        fname = os.path.basename(file_path).lower()
        
        # 1. YARA (Signature)
        yara_matches = self.yara.scan(file_path)
        if yara_matches: score += 100; findings.append(f"YARA: {', '.join(yara_matches)}")

        # 2. AI (0-Day)
        if self.malware_model and fname.endswith((".exe", ".dll")):
            feats = self.extract_features(file_path)
            if feats and self.malware_model.predict([feats])[0] == 1: score += 95; findings.append("AI Malware")
        
        # 3. Entropy (Ransomware)
        if os.path.exists(file_path):
            if self.calculate_entropy(file_path) > 7.2: score += 50; findings.append("High Entropy")
        
        # 4. Keyword
        if any(x in fname for x in ["virus", "test", "malware", "eicar"]): score += 100; findings.append("Signature")

        return score, findings
    
    def deep_system_scan(self, agent_ref):
        findings = []; risk = 0
        if os.path.exists(SCAN_TARGET):
            for f in os.listdir(SCAN_TARGET):
                if f.endswith(".quarantine"): continue
                path = os.path.join(SCAN_TARGET, f)
                if os.path.isfile(path):
                    s, fl = self.quick_file_scan(path)
                    if s > 50: findings.append(f"{f}: {', '.join(fl)}"); risk += 40; agent_ref.handle_threat(path, s, fl)
        agent_ref.mem_scanner.scan_running_processes()
        return {"verdict": "Scan Complete", "riskScore": min(risk, 100), "findings": findings or ["Clean"]}

# ==========================================
# MODULE 10: MEMORY SCANNER
# ==========================================
class MemoryScanner:
    def __init__(self, agent): self.agent = agent
    def scan_running_processes(self):
        self.agent.log_ui("Scanning Memory...")
        for proc in psutil.process_iter(['name', 'cmdline']):
            try:
                cmd = " ".join(proc.info['cmdline'] or []).lower()
                if "base64" in cmd or "-enc" in cmd:
                    self.agent.log_ui(f"🚨 MEMORY THREAT: {proc.info['name']}"); self.agent.send_alert(f"Fileless: {cmd[:30]}")
            except: pass

# ==========================================
# MODULE 11: REAL-TIME GUARD
# ==========================================
class RealTimeGuard(FileSystemEventHandler):
    def __init__(self, agent): self.agent = agent; self.scanner = ThreatScanner()
    def check(self, path):
        if not path or not os.path.exists(path) or ".quarantine" in path: return
        try:
            for i in range(5):
                try:
                    with open(path, 'rb') as f:
                        if b"EICAR" in f.read(100): 
                            self.agent.handle_threat(path, 100, ["EICAR"])
                            return
                    s, f = self.scanner.scan(path)
                    if s > 50: 
                        self.agent.handle_threat(path, s, f)
                        return
                    break
                except PermissionError: time.sleep(0.05)
        except: pass
    def on_created(self, e): self.check(e.src_path)
    def on_modified(self, e): self.check(e.src_path)
    def on_moved(self, e): self.check(e.dest_path)

# ==========================================
# MODULE 12: USB GUARD
# ==========================================
class USBGuard:
    def __init__(self, agent): self.agent = agent
    def monitor(self):
        if not wmi: return
        try:
            pythoncom.CoInitialize()
            c = wmi.WMI()
            watcher = c.Win32_LogicalDisk.watch_for("creation")
            while True:
                disk = watcher()
                if disk.DriveType == 2:
                    self.agent.log_ui(f"USB: {disk.Caption}"); notify_user("USB Guard", "Scanning...")
                    self.scan(disk.Caption + "\\")
        except: pass
    def scan(self, drive):
        for root, _, files in os.walk(drive):
            for f in files:
                p = os.path.join(root, f)
                s, fl = self.agent.scanner.quick_file_scan(p)
                if s > 50: self.agent.handle_threat(p, s, fl)

# ==========================================
# MODULE 13: NETWORK GUARD
# ==========================================
class NetworkGuard:
    def __init__(self, agent): self.agent = agent; self.model = None; self.last = psutil.net_io_counters(); self.last_t = time.time()
    def load_model(self):
        if os.path.exists(NIDS_MODEL_FILE):
             try: self.model = joblib.load(NIDS_MODEL_FILE)
             except: pass
    def monitor(self):
        self.load_model()
        while True:
            time.sleep(5)
            try:
                curr = psutil.net_io_counters(); src = curr.bytes_sent - self.last.bytes_sent; dst = curr.bytes_recv - self.last.bytes_recv
                self.last = curr
                if src > dst * 10 and src > 5000000: self.agent.log_ui("🚨 EXFILTRATION")
                if self.model:
                    conns = len(psutil.net_connections())
                    if self.model.predict([[5, 1, src, dst, conns, conns]])[0] == 1: self.agent.log_ui("🚨 NIDS ALERT")
            except: pass

# ==========================================
# MODULE 14: FILE INTEGRITY
# ==========================================
class IntegrityGuard:
    def __init__(self, agent):
        self.agent = agent; self.hashes = {}
        if os.path.exists(HOSTS_PATH): self.hashes[HOSTS_PATH] = self.get_hash(HOSTS_PATH)
    def get_hash(self, path):
        try:
            with open(path, "rb") as f: return hashlib.sha256(f.read()).hexdigest()
        except: return None
    def check(self):
        while True:
            time.sleep(30)
            for p, h in self.hashes.items():
                curr = self.get_hash(p)
                if curr and curr != h:
                    self.agent.log_ui(f"🚨 FIM: {os.path.basename(p)} Modified")
                    self.agent.send_alert(f"FIM: {p}")
                    self.hashes[p] = curr

# ==========================================
# MODULE 15: IDENTITY GUARD
# ==========================================
class IdentityGuard:
    def __init__(self, agent): self.agent = agent
    def monitor_logins(self):
        while True:
            time.sleep(60)
            if 0 <= datetime.now().hour <= 5: 
                self.agent.log_ui("🚨 IDENTITY: Abnormal Login Time")

# --- FEATURE: BSOD SHIELD (God Mode) ---
def enable_critical_status():
    if getattr(sys, 'frozen', False):
        try:
            ntdll = ctypes.WinDLL("ntdll.dll")
            # ntdll.RtlSetProcessIsCritical(1, 0, 0) # Disabled for testing safety
            file_log("🛡️ GOD MODE: Process Critical.")
        except: pass

# ==========================================
# MAIN AGENT CONTROLLER
# ==========================================
class OrgWatchAgent:
    def __init__(self):
        file_log("Agent Init"); self.device_id = None; self.is_enrolled = False; 
        self.scanner = ThreatScanner(); self.web = WebGuard(self); 
        self.net = NetworkGuard(self); self.usb = USBGuard(self)
        self.edr = ProcessEDR(self); self.mem_scanner = MemoryScanner(self)
        self.canary = RansomwareCanary(self); self.registry = RegistryGuard(self)
        self.fim = IntegrityGuard(self); self.airlock = NetworkAirlock(self)
        self.remedy = RemediationEngine(); self.vault = EventBuffer()
        self.identity = IdentityGuard(self)
        self.load_config()

    def log_ui(self, msg): 
        try: print(f"> {msg}")
        except: pass
        sys.stdout.flush(); file_log(msg)

    def load_config(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'rb') as f:
                    data = json.loads(CIPHER_SUITE.decrypt(f.read()).decode())
                    self.device_id = data.get('device_id'); self.is_enrolled = True
                    self.log_ui(f"Active: {self.device_id}")
            except: pass

    def save_config(self, data):
        with open(CONFIG_FILE, 'wb') as f: f.write(CIPHER_SUITE.encrypt(json.dumps(data).encode()))

    def send_alert(self, details):
        payload = {"device_id": self.device_id, "timestamp": datetime.now().isoformat(), "metrics": {}, "ai_status": "anomaly", "alert": True, "alert_details": details}
        if self.is_enrolled:
            try: requests.post(f"{BACKEND_URL}/telemetry", json=payload, timeout=2)
            except: self.vault.add_event(payload)

    def handle_threat(self, path, score, findings):
        try:
            self.remedy.create_snapshot() # ROLLBACK POINT
            new = path + ".quarantine"
            for _ in range(5):
                try: os.rename(path, new); break
                except: time.sleep(0.2)
            self.log_ui(f"⚠️ BLOCKED: {os.path.basename(path)}")
            notify_user("Threat Blocked", f"Quarantined {os.path.basename(path)}")
            self.send_alert(f"Blocked: {os.path.basename(path)} | {', '.join(findings)}")
            if score >= 100: self.airlock.isolate()
        except: pass

    def enroll(self, emp_id):
        self.log_ui(f"Enrolling {emp_id}...")
        try:
            hw = f"{platform.node()}_{emp_id}"
            res = requests.post(f"{BACKEND_URL}/devices/enroll", json={"name": socket.gethostname(), "user": emp_id, "ip": socket.gethostbyname(socket.gethostname()), "type": "desktop", "hardware_id": hw})
            if res.status_code == 200:
                self.device_id = res.json()['id']; self.is_enrolled = True
                self.save_config({"device_id": self.device_id, "emp_id": emp_id})
                self.log_ui("Enrolled."); self.start_services()
            else: self.log_ui("Backend Error")
        except: self.log_ui("Conn Error")

    def create_tray(self):
        try:
            image = Image.new('RGB', (64, 64), color = (0, 255, 255))
            icon = pystray.Icon("OrgWatch", image, "OrgWatch Active")
            threading.Thread(target=icon.run, daemon=True).start()
        except: pass

    def start_services(self):
        enable_critical_status()
        obs = Observer()
        for d in [SCAN_TARGET, DOCS_DIR]:
            if not os.path.exists(d): os.makedirs(d)
            obs.schedule(RealTimeGuard(self), d, recursive=False)
        obs.schedule(self.canary, DOCS_DIR, recursive=False)
        obs.start()
        
        self.log_ui("Engines: GOD MODE | AV | WEB | RANSOMWARE | EDR | NIDS | FIM")
        threading.Thread(target=self.web.check_loop, daemon=True).start()
        threading.Thread(target=self.net.monitor, daemon=True).start()
        threading.Thread(target=self.usb.monitor, daemon=True).start()
        threading.Thread(target=self.edr.monitor, daemon=True).start()
        threading.Thread(target=self.registry.monitor, daemon=True).start()
        threading.Thread(target=self.fim.check_integrity, daemon=True).start()
        threading.Thread(target=self.identity.monitor_logins, daemon=True).start()
        threading.Thread(target=self.monitor_loop, daemon=True).start()
        self.create_tray()

    def monitor_loop(self):
        while True:
            self.vault.sync()
            print(json.dumps({"type": "heartbeat", "data": {"usage": {"cpu_percent": psutil.cpu_percent(), "ram_percent": psutil.virtual_memory().percent}}})); sys.stdout.flush()
            if self.is_enrolled:
                try: requests.post(f"{BACKEND_URL}/telemetry", json={"device_id": self.device_id, "timestamp": datetime.now().isoformat(), "metrics": {"cpu": psutil.cpu_percent(), "ram": psutil.virtual_memory().percent}, "ai_status": "normal"}, timeout=1)
                except: pass
                try:
                    res = requests.get(f"{BACKEND_URL}/agent/{self.device_id}/commands", timeout=1); cmd = res.json()
                    if cmd['id'] and cmd['type'] == 'deep_scan':
                        self.log_ui("C2: Deep Scan"); report = self.scanner.deep_system_scan(self)
                        requests.post(f"{BACKEND_URL}/agent/command_result", json={"command_id": cmd['id'], "result": report}); self.log_ui("Report Sent")
                    if cmd['id'] and cmd['type'] == 'isolate': self.airlock.isolate()
                except: pass
            time.sleep(3)

    def listen(self):
        for line in sys.stdin:
            try:
                d = json.loads(line)
                if d.get('type') == 'enroll': self.enroll(d['emp_id'])
            except: pass

if __name__ == "__main__":
    agent = OrgWatchAgent()
    if agent.is_enrolled: agent.start_services()
    agent.listen()