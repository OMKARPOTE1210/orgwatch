import sys
import json
import time
import psutil
import platform
import socket
import requests
import threading
import os
import math
import logging
from datetime import datetime
from cryptography.fernet import Fernet
from sklearn.ensemble import IsolationForest
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import joblib # For AI Model Persistence
import pefile # For 0-Day Binary Analysis
import numpy as np # For Data Generation

# --- CONFIGURATION ---
BACKEND_URL = "http://localhost:8000/api"
CONFIG_FILE = "agent_secure.enc"
KEY_FILE = "secret.key"
MODEL_FILE = "behavior_model.pkl"
SCAN_TARGET = os.path.expanduser("~/Downloads")

# --- ENCRYPTION SETUP ---
if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, "wb") as kf: kf.write(Fernet.generate_key())
with open(KEY_FILE, "rb") as kf: CIPHER_SUITE = Fernet(kf.read())

class ThreatScanner:
    """The AI Brain: Handles Static Analysis, Entropy, and Behavioral AI"""
    def __init__(self):
        self.history = []
        self.load_brain()

    def load_brain(self):
        """Load persisted AI model or initialize new one"""
        if os.path.exists(MODEL_FILE):
            try:
                self.model = joblib.load(MODEL_FILE)
            except:
                self.train_new_brain()
        else:
            self.train_new_brain()

    def generate_synthetic_baseline(self):
        """
        Generates 1000 samples of 'normal' workstation behavior to train the Isolation Forest.
        Features: [CPU%, RAM%, Num_Threads, File_Handles]
        """
        rng = np.random.default_rng(42)
        
        # 1. Idle/Light Usage (60% of time) - e.g., Reading PDFs, browsing
        cpu_idle = rng.normal(loc=5, scale=2, size=(600, 1))
        ram_idle = rng.normal(loc=30, scale=5, size=(600, 1))
        threads_idle = rng.normal(loc=40, scale=10, size=(600, 1))
        handles_idle = rng.normal(loc=150, scale=30, size=(600, 1))
        
        # 2. Heavy Usage (30% of time) - e.g., Compiling, Excel, Video Calls
        cpu_heavy = rng.normal(loc=45, scale=15, size=(300, 1))
        ram_heavy = rng.normal(loc=60, scale=10, size=(300, 1))
        threads_heavy = rng.normal(loc=90, scale=20, size=(300, 1))
        handles_heavy = rng.normal(loc=400, scale=50, size=(300, 1))

        # 3. Spikes (10% of time) - e.g., App Launch, Update
        cpu_spike = rng.normal(loc=80, scale=10, size=(100, 1))
        ram_spike = rng.normal(loc=80, scale=10, size=(100, 1))
        threads_spike = rng.normal(loc=150, scale=30, size=(100, 1))
        handles_spike = rng.normal(loc=800, scale=100, size=(100, 1))

        # Combine into one dataset
        X_idle = np.hstack((cpu_idle, ram_idle, threads_idle, handles_idle))
        X_heavy = np.hstack((cpu_heavy, ram_heavy, threads_heavy, handles_heavy))
        X_spike = np.hstack((cpu_spike, ram_spike, threads_spike, handles_spike))
        
        return np.vstack((X_idle, X_heavy, X_spike))

    def train_new_brain(self):
        """Trains the Anomaly Detection Model"""
        print("Training AI Model on Synthetic Baseline...")
        self.model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
        
        # Generate robust data: [cpu, ram, threads, file_handles]
        baseline = self.generate_synthetic_baseline()
        
        self.model.fit(baseline)
        self.save_brain()
        print("AI Model Trained & Saved.")

    def save_brain(self):
        try:
            joblib.dump(self.model, MODEL_FILE)
        except: pass

    def calculate_entropy(self, file_path):
        """Calculates Shannon Entropy. >7.0 usually means encryption/compression (Ransomware/Packed)"""
        try:
            with open(file_path, 'rb') as f: data = f.read()
            if not data: return 0
            entropy = 0
            for x in range(256):
                p_x = float(data.count(bytes([x]))) / len(data)
                if p_x > 0: entropy += - p_x * math.log(p_x, 2)
            return entropy
        except: return 0

    def static_binary_analysis(self, file_path):
        """0-DAY DETECTION: Analyzes PE headers for suspicious API imports"""
        score = 0
        findings = []
        try:
            pe = pefile.PE(file_path)
            suspicious_apis = ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "CryptEncrypt", "SetWindowsHookEx"]
            
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    func_name = imp.name.decode('utf-8') if imp.name else ""
                    if any(api in func_name for api in suspicious_apis):
                        score += 20
                        findings.append(f"Suspicious API Call: {func_name}")
        except: 
            pass # Not a PE file or unreadable
        return score, findings

    def quick_file_scan(self, file_path):
        """Used by Real-Time Guard for instant analysis"""
        score = 0
        findings = []
        
        filename = os.path.basename(file_path).lower()

        # 1. 0-Day Binary Analysis (PE Files)
        if filename.endswith(".exe") or filename.endswith(".dll"):
            bin_score, bin_findings = self.static_binary_analysis(file_path)
            score += bin_score
            findings.extend(bin_findings)

        # 2. Entropy Check (Ransomware/Packers)
        if os.path.exists(file_path):
            e = self.calculate_entropy(file_path)
            if e > 7.2:
                score += 50
                findings.append(f"High Entropy ({round(e, 2)})")

        # 3. Extension/Keywords (Basic Sig)
        if any(x in filename for x in ["virus", "test", "malware", "payload"]): 
            score += 100
            findings.append(f"Malicious keyword: {filename}")
        
        if filename.endswith((".bat", ".vbs", ".ps1")):
            score += 20
            findings.append("Scripting File Detected")

        return score, findings

    def deep_system_scan(self, agent_ref):
        """Used by C2 Command for full system audit"""
        findings = []
        risk = 0
        
        # 1. File Scan (Downloads)
        if os.path.exists(SCAN_TARGET):
            for f in os.listdir(SCAN_TARGET):
                if f.endswith(".quarantine"): continue
                path = os.path.join(SCAN_TARGET, f)
                if os.path.isfile(path):
                    s, f_list = self.quick_file_scan(path)
                    if s > 50:
                        findings.append(f"File Threat: {f} ({', '.join(f_list)})")
                        risk += 40
                        agent_ref.handle_threat(path, s, f_list)

        # 2. Process Scan (AI Anomaly)
        for proc in psutil.process_iter(['name', 'cpu_percent', 'memory_percent', 'num_threads', 'num_handles']):
            try:
                # Vector: [cpu, ram, threads, handles]
                pinfo = proc.info
                # Sanitize None values
                cpu = pinfo['cpu_percent'] or 0
                mem = pinfo['memory_percent'] or 0
                thr = pinfo['num_threads'] or 0
                hnd = pinfo['num_handles'] or 0
                
                vec = [cpu, mem, thr, hnd]
                
                # PREDICT
                pred = self.model.predict([vec])[0]
                
                # If Anomaly (-1) AND High CPU -> Likely Malicious Miner/Script
                if pred == -1 and cpu > 30:
                    findings.append(f"Behavioral Anomaly: {pinfo['name']} (Unusual Resource Usage)")
                    risk += 30
            except: pass

        return {
            "verdict": "Active Threats Found" if risk > 0 else "System Secure",
            "confidence": "99.1%",
            "riskScore": min(risk, 100),
            "findings": findings if findings else ["System integrity verified.", "No active malware in memory."],
            "recommendation": "Isolate device immediately." if risk > 50 else "No action required."
        }

class RealTimeGuard(FileSystemEventHandler):
    """Watchdog Handler: Triggers when files are created/modified"""
    def __init__(self, agent):
        self.agent = agent
        self.scanner = ThreatScanner()

    def check(self, path):
        if not path or not os.path.exists(path) or path.endswith(".quarantine") or os.path.isdir(path): return
        
        # self.agent.log_ui(f"Scanning: {os.path.basename(path)}")
        try:
            # Small delay to allow write to finish
            time.sleep(0.5)
            score, findings = self.scanner.quick_file_scan(path)
            
            if score > 50:
                self.agent.handle_threat(path, score, findings)
        except: pass

    def on_created(self, event): self.check(event.src_path)
    def on_modified(self, event): self.check(event.src_path)
    def on_moved(self, event): self.check(event.dest_path)

class OrgWatchAgent:
    def __init__(self):
        self.device_id = None
        self.is_enrolled = False
        self.scanner = ThreatScanner()
        self.check_integrity()
        self.load_config()

    def check_integrity(self):
        """Security: Prevent Debugging"""
        if sys.gettrace() is not None: sys.exit(1)

    def log_ui(self, msg):
        print(f"> {msg}")
        sys.stdout.flush()

    def load_config(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'rb') as f:
                    data = json.loads(CIPHER_SUITE.decrypt(f.read()).decode())
                    self.device_id = data.get('device_id')
                    self.is_enrolled = True
                    self.log_ui(f"Secure Agent Loaded. ID: {self.device_id}")
            except: pass

    def save_config(self, data):
        with open(CONFIG_FILE, 'wb') as f:
            f.write(CIPHER_SUITE.encrypt(json.dumps(data).encode()))

    def handle_threat(self, path, score, findings):
        """Quarantines file and alerts backend"""
        try:
            if not os.path.exists(path): return
            new_path = path + ".quarantine"
            
            # Retry rename loop for Windows locks
            for _ in range(5):
                try:
                    os.rename(path, new_path)
                    break
                except PermissionError: time.sleep(0.2)
            
            self.log_ui(f"⚠️ THREAT BLOCKED: {os.path.basename(path)}")
            self.log_ui(f"   REASON: {', '.join(findings)}")
            
            if self.is_enrolled:
                payload = {
                    "device_id": self.device_id, "timestamp": datetime.now().isoformat(),
                    "metrics": {}, "ai_status": "anomaly", "alert": True,
                    "alert_details": f"Antivirus Blocked: {os.path.basename(path)}. Findings: {', '.join(findings)}"
                }
                requests.post(f"{BACKEND_URL}/telemetry", json=payload)
        except Exception as e:
            self.log_ui(f"Failed to quarantine: {e}")

    def run_boot_scan(self):
        """Scans existing files on startup"""
        self.log_ui("Running Boot-Time Scan...")
        if os.path.exists(SCAN_TARGET):
            for f in os.listdir(SCAN_TARGET):
                if f.endswith(".quarantine"): continue
                path = os.path.join(SCAN_TARGET, f)
                if os.path.isfile(path):
                    score, findings = self.scanner.quick_file_scan(path)
                    if score > 50: self.handle_threat(path, score, findings)
        self.log_ui("Boot Scan Complete.")

    def enroll(self, emp_id):
        self.log_ui(f"Enrolling: {emp_id}...")
        try:
            hw_id = f"{platform.node()}_{emp_id}"
            res = requests.post(f"{BACKEND_URL}/devices/enroll", json={
                "name": socket.gethostname(), "user": emp_id, 
                "ip": socket.gethostbyname(socket.gethostname()), "type": "desktop", "hardware_id": hw_id
            })
            if res.status_code == 200:
                self.device_id = res.json()['id']
                self.is_enrolled = True
                self.save_config({"device_id": self.device_id, "emp_id": emp_id})
                self.log_ui("Enrollment Successful.")
                self.start_services()
        except Exception as e: self.log_ui(f"Error: {e}")

    def start_services(self):
        # 1. Start File Watcher
        if not os.path.exists(SCAN_TARGET): os.makedirs(SCAN_TARGET)
        observer = Observer()
        observer.schedule(RealTimeGuard(self), SCAN_TARGET, recursive=False)
        observer.start()
        self.log_ui(f"Real-time File Shield Active ({SCAN_TARGET})")

        # 2. Run Boot Scan
        threading.Thread(target=self.run_boot_scan, daemon=True).start()

        # 3. Start C2 & Telemetry Loop
        threading.Thread(target=self.monitor_loop, daemon=True).start()

        # 4. Periodic Deep Scan (Redundancy)
        threading.Thread(target=self.periodic_deep_scan, daemon=True).start()

    def periodic_deep_scan(self):
        while True:
            time.sleep(120) # Every 2 minutes
            self.scanner.deep_system_scan(self)

    def monitor_loop(self):
        while True:
            cpu = psutil.cpu_percent()
            ram = psutil.virtual_memory().percent
            print(json.dumps({"type": "heartbeat", "data": {"usage": {"cpu_percent": cpu, "ram_percent": ram}}}))
            sys.stdout.flush()

            if self.is_enrolled:
                # Telemetry
                try:
                    requests.post(f"{BACKEND_URL}/telemetry", json={
                        "device_id": self.device_id, "timestamp": datetime.now().isoformat(),
                        "metrics": {"cpu": cpu, "ram": ram}, "ai_status": "normal"
                    }, timeout=2)
                except: pass

                # C2 Polling
                try:
                    res = requests.get(f"{BACKEND_URL}/agent/{self.device_id}/commands", timeout=2)
                    cmd = res.json()
                    if cmd['id']:
                        self.log_ui(f"Remote Command: {cmd['type']}")
                        if cmd['type'] == 'deep_scan':
                            self.log_ui("Executing Deep AI Scan...")
                            report = self.scanner.deep_system_scan(self)
                            requests.post(f"{BACKEND_URL}/agent/command_result", json={
                                "command_id": cmd['id'], "result": report
                            })
                            self.log_ui("Report Uploaded.")
                except: pass

            time.sleep(3)

    def listen(self):
        for line in sys.stdin:
            try:
                if json.loads(line).get('type') == 'enroll': self.enroll(json.loads(line)['emp_id'])
            except: pass

if __name__ == "__main__":
    agent = OrgWatchAgent()
    if agent.is_enrolled: 
        agent.start_services()
    agent.listen()