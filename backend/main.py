from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional, List
import models, database
import random, time, logging, json, os
from datetime import datetime

# --- CONFIGURATION ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("OrgWatch-C2")

# Create tables
models.Base.metadata.create_all(bind=database.engine)

app = FastAPI(title="OrgWatch Enterprise API")

# --- CORS SETTINGS (CRITICAL FOR PRODUCTION) ---
origins = [
    "http://localhost:5173",            # Local Frontend
    "http://localhost",                 # Docker Frontend
    "https://omkarpote1210.github.io",  # YOUR GITHUB PAGES FRONTEND
    # "https://your-custom-domain.com"    # Future domain - Add your domain here
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Allow all for now to ensure Desktop App connects easily. RESTRICT THIS IN PROD!
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

class LogResponse(BaseModel):
    id: int
    timestamp: datetime
    event: str
    details: str
    device_id: Optional[str]

    class Config:
        from_attributes = True # updated for Pydantic v2

# --- EMAIL LOGIC (SIMULATED) ---
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
    
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"Error enrolling device: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")
        
    return {"id": new_id, "status": "success"}

@app.post("/api/telemetry")
def receive_telemetry(data: TelemetryData, background_tasks: BackgroundTasks, db: Session = Depends(database.get_db)):
    # 1. Auto-Recover Device if missing
    device = db.query(models.Device).filter(models.Device.id == data.device_id).first()
    if not device:
        device = models.Device(
            id=data.device_id, name="Unregistered Device", user="Unknown", ip="0.0.0.0",
            status="online", risk=0, os="Windows", cpu_usage="0%", ram_usage="0%"
        )
        db.add(device)
        try:
            db.commit()
            db.refresh(device)
        except Exception as e:
            db.rollback()
            logger.error(f"Error creating auto-recovered device: {e}")
            # Continue processing even if device creation failed to log alert? 
            # Ideally we fail here, but let's try to be robust.

    # 2. Update Real-time Stats
    if device:
        device.cpu_usage = f"{data.metrics.get('cpu', 0)}%"
        device.ram_usage = f"{data.metrics.get('ram', 0)}%"
        device.last_seen = datetime.now()
        
        if data.ai_status == "anomaly":
            device.risk = min(device.risk + 15, 100)
            device.status = "warning"
        else:
            # simple healing mechanic
            device.status = "online"
            
        try:
            db.commit()
        except Exception as e:
            db.rollback()
            logger.error(f"Error updating telemetry stats: {e}")

    # 3. Handle Alerts & Logs
    if data.alert:
        new_alert = models.Alert(
            title=f"AI Threat: {data.device_id}", 
            severity="critical", 
            description=data.alert_details,
            source_device_id=data.device_id,
            timestamp=datetime.now()
        )
        db.add(new_alert)
        
        # Log entry for alert
        new_log = models.Log(
            device_id=data.device_id,
            event="Threat Detected",
            details=data.alert_details,
            timestamp=datetime.now()
        )
        db.add(new_log)
        
        try:
            db.commit()
            background_tasks.add_task(send_email_alert, data.device_id, data.alert_details)
        except Exception as e:
            db.rollback()
            logger.error(f"Error saving alert: {e}")
    else:
        # Optional: Log heartbeat for debugging or specific events
        # To avoid spamming logs table, maybe only log significant changes or periodic info
        pass
        
    return {"status": "processed"}

# --- COMMAND & CONTROL (C2) ---

@app.post("/api/devices/{device_id}/scan")
def trigger_scan(device_id: str, db: Session = Depends(database.get_db)):
    cmd = models.Command(device_id=device_id, type="deep_scan", status="pending")
    db.add(cmd)
    try:
        db.commit()
        db.refresh(cmd)
    except Exception as e:
        db.rollback()
        logger.error(f"Error triggering scan: {e}")
        raise HTTPException(status_code=500, detail="Failed to queue command")
        
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
    cmd = db.query(models.Command).filter(models.Command.device_id == device_id, models.Command.status == "pending").first()
    if cmd:
        cmd.status = "processing"
        try:
            db.commit()
            return {"id": cmd.id, "type": cmd.type}
        except Exception as e:
            db.rollback()
            logger.error(f"Error retrieving pending command: {e}")
            return {"id": None}
    return {"id": None}

@app.post("/api/agent/command_result")
def upload_result(data: CommandResult, db: Session = Depends(database.get_db)):
    cmd = db.query(models.Command).filter(models.Command.id == data.command_id).first()
    if cmd:
        cmd.status = "completed"
        cmd.result = json.dumps(data.result)
        try:
            db.commit()
        except Exception as e:
            db.rollback()
            logger.error(f"Error saving command result: {e}")
            return {"status": "error"}
            
    return {"status": "ok"}

@app.get("/api/devices")
def get_devices(db: Session = Depends(database.get_db)):
    return db.query(models.Device).all()

@app.get("/api/logs", response_model=List[LogResponse])
def get_live_logs(db: Session = Depends(database.get_db)):
    # Return last 50 logs descending
    # Assuming 'models.Log' exists based on the full architecture plan, 
    # if not, fallback to alerting logs or create the model
    try:
        logs = db.query(models.Log).order_by(models.Log.timestamp.desc()).limit(20).all()
        return logs
    except Exception as e:
        # Fallback if Logs table doesn't exist yet or other error
        logger.error(f"Error fetching logs: {e}")
        return []