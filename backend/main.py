from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional, List
import models, database
import random, time, logging, json
from datetime import datetime

# --- CONFIGURATION ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("OrgWatch-C2")

models.Base.metadata.create_all(bind=database.engine)
app = FastAPI(title="OrgWatch Enterprise API")

# --- CORS (Crucial for Frontend Communication) ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, replace with specific domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- SCHEMAS ---
class DeviceEnroll(BaseModel):
    name: str
    user: str
    ip: str
    type: str
    hardware_id: Optional[str] = None

class TelemetryData(BaseModel):
    device_id: str
    metrics: dict
    ai_status: str
    alert: Optional[bool] = False
    alert_details: Optional[str] = None

class CommandResult(BaseModel):
    command_id: int
    result: dict

# --- EMAIL LOGIC (Simulated) ---
def send_email_alert(device_id: str, issue: str):
    logger.warning(f"\n[MAIL SERVER] 🚨 Sending Alert for {device_id}\nSubject: SECURITY INCIDENT\nBody: {issue}\n")

# --- ENDPOINTS ---

@app.post("/api/devices/enroll")
def enroll_device(device: DeviceEnroll, db: Session = Depends(database.get_db)):
    new_id = device.hardware_id if device.hardware_id else f"DEV-{random.randint(10000,99999)}"
    
    # Upsert Logic
    existing = db.query(models.Device).filter(models.Device.id == new_id).first()
    if existing:
        existing.ip = device.ip
        existing.user = device.user
        existing.status = "online"
        existing.last_seen = datetime.now()
    else:
        db_device = models.Device(
            id=new_id, name=device.name, user=device.user, ip=device.ip,
            status="online", risk=0, os="Windows 11", cpu_usage="0%", ram_usage="0%"
        )
        db.add(db_device)
        
        # Log enrollment
        log = models.Log(device_id=new_id, event="Enrollment", details=f"Device registered: {device.name}", timestamp=datetime.now())
        db.add(log)
    
    db.commit()
    return {"id": new_id, "status": "success"}

@app.post("/api/telemetry")
def receive_telemetry(data: TelemetryData, background_tasks: BackgroundTasks, db: Session = Depends(database.get_db)):
    # 1. Auto-Recover Device if missing (DB Reset protection)
    device = db.query(models.Device).filter(models.Device.id == data.device_id).first()
    if not device:
        device = models.Device(
            id=data.device_id, name="Unregistered Device", user="Unknown", ip="0.0.0.0",
            status="online", risk=0, os="Windows", cpu_usage="0%", ram_usage="0%"
        )
        db.add(device)
        db.commit()
        db.refresh(device)

    # 2. Update Real-time Stats
    device.cpu_usage = f"{data.metrics.get('cpu', 0)}%"
    device.ram_usage = f"{data.metrics.get('ram', 0)}%"
    device.last_seen = datetime.now()
    
    if data.ai_status == "anomaly":
        device.risk = min(device.risk + 15, 100)
        device.status = "warning"
    else:
        # Slowly heal risk if normal
        device.status = "online"
        
    db.commit()

    # 3. Log Heartbeat (Optional: Reduce noise by logging only periodically or on change)
    # For demo, logging everything to show activity stream
    # log_hb = models.Log(
    #     device_id=data.device_id, 
    #     event="Heartbeat", 
    #     details=f"CPU: {data.metrics.get('cpu')}% | RAM: {data.metrics.get('ram')}%", 
    #     timestamp=datetime.now()
    # )
    # db.add(log_hb)

    # 4. Handle Alerts
    if data.alert:
        # Create Alert
        new_alert = models.Alert(
            title=f"AI Threat: {data.device_id}", 
            severity="critical", 
            description=data.alert_details,
            source_device_id=data.device_id,
            timestamp=datetime.now()
        )
        db.add(new_alert)
        
        # Create Log
        log_alert = models.Log(
            device_id=data.device_id,
            event="Anomaly",
            details=data.alert_details,
            timestamp=datetime.now()
        )
        db.add(log_alert)
        db.commit()
        
        # Send Mail
        background_tasks.add_task(send_email_alert, data.device_id, data.alert_details)
    else:
        db.commit()
        
    return {"status": "processed"}

# --- COMMAND & CONTROL (C2) ---

@app.post("/api/devices/{device_id}/scan")
def trigger_scan(device_id: str, db: Session = Depends(database.get_db)):
    cmd = models.Command(device_id=device_id, type="deep_scan", status="pending")
    db.add(cmd)
    
    # Log Action
    log = models.Log(device_id=device_id, event="Command Issued", details="Deep Scan requested by Admin", timestamp=datetime.now())
    db.add(log)
    
    db.commit()
    db.refresh(cmd)
    return {"command_id": cmd.id, "status": "queued"}

@app.get("/api/commands/{command_id}")
def get_command_status(command_id: int, db: Session = Depends(database.get_db)):
    cmd = db.query(models.Command).filter(models.Command.id == command_id).first()
    if not cmd: raise HTTPException(404, "Command not found")
    
    result_data = None
    if cmd.result:
        try: result_data = json.loads(cmd.result)
        except: result_data = {"error": "Failed to parse result"}
            
    return {"status": cmd.status, "result": result_data}

@app.get("/api/agent/{device_id}/commands")
def get_pending_commands(device_id: str, db: Session = Depends(database.get_db)):
    # Fetch oldest pending command
    cmd = db.query(models.Command).filter(models.Command.device_id == device_id, models.Command.status == "pending").first()
    if cmd:
        cmd.status = "processing"
        db.commit()
        return {"id": cmd.id, "type": cmd.type}
    return {"id": None}

@app.post("/api/agent/command_result")
def upload_result(data: CommandResult, db: Session = Depends(database.get_db)):
    cmd = db.query(models.Command).filter(models.Command.id == data.command_id).first()
    if cmd:
        cmd.status = "completed"
        cmd.result = json.dumps(data.result)
        
        # Log Completion
        log = models.Log(device_id=cmd.device_id, event="Command Completed", details="Deep Scan Report Uploaded", timestamp=datetime.now())
        db.add(log)
        
        db.commit()
    return {"status": "ok"}

# --- DATA RETRIEVAL ---

@app.get("/api/devices")
def get_devices(db: Session = Depends(database.get_db)):
    return db.query(models.Device).all()

@app.get("/api/logs")
def get_live_logs(db: Session = Depends(database.get_db)):
    # Return last 50 logs for the dashboard feed
    return db.query(models.Log).order_by(models.Log.timestamp.desc()).limit(50).all()