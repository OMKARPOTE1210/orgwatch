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

# --- PRODUCTION CORS SETTINGS ---
origins = [
    "http://localhost:5173",                     # Local Dev
    "https://omkarpote1210.github.io",           # YOUR GITHUB PAGES (Production)
    "https://orgwatch-api.onrender.com"          # Your Render Backend
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins, # Securely allow only your frontend
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ... (Keep the rest of the Schemas and Endpoints exactly as they were in the previous complete file) ...
# ... (Copy-paste the Schemas and Functions from the previous full main.py here) ...

# --- SCHEMAS ---
class DeviceEnroll(BaseModel):
    name: str; user: str; ip: str; type: str; hardware_id: Optional[str] = None
class TelemetryData(BaseModel):
    device_id: str; metrics: dict; ai_status: str; alert: Optional[bool] = False; alert_details: Optional[str] = None
class CommandResult(BaseModel):
    command_id: int; result: dict
class LogResponse(BaseModel):
    id: int; timestamp: datetime; event: str; details: str; device_id: Optional[str]
    class Config: from_attributes = True

# --- ENDPOINTS ---
def send_email_alert(device_id: str, issue: str):
    logger.warning(f"\n[MAIL SERVER] 🚨 Alert for {device_id}: {issue}\n")

@app.post("/api/devices/enroll")
def enroll_device(device: DeviceEnroll, db: Session = Depends(database.get_db)):
    new_id = device.hardware_id if device.hardware_id else f"DEV-{random.randint(10000,99999)}"
    existing = db.query(models.Device).filter(models.Device.id == new_id).first()
    if existing:
        existing.ip = device.ip; existing.user = device.user; existing.status = "online"; existing.last_seen = datetime.now()
    else:
        db.add(models.Device(id=new_id, name=device.name, user=device.user, ip=device.ip, status="online", risk=0, os="Windows 11", cpu_usage="0%", ram_usage="0%"))
    db.commit()
    return {"id": new_id, "status": "success"}

@app.post("/api/telemetry")
def receive_telemetry(data: TelemetryData, background_tasks: BackgroundTasks, db: Session = Depends(database.get_db)):
    device = db.query(models.Device).filter(models.Device.id == data.device_id).first()
    if not device:
        device = models.Device(id=data.device_id, name="Unregistered Device", user="Unknown", ip="0.0.0.0", status="online", risk=0, os="Windows", cpu_usage="0%", ram_usage="0%")
        db.add(device); db.commit(); db.refresh(device)
    device.cpu_usage = f"{data.metrics.get('cpu', 0)}%"; device.ram_usage = f"{data.metrics.get('ram', 0)}%"; device.last_seen = datetime.now()
    if data.ai_status == "anomaly": device.risk = min(device.risk + 15, 100); device.status = "warning"
    else: device.status = "online"
    db.commit()
    if data.alert:
        db.add(models.Alert(title=f"AI Threat: {data.device_id}", severity="critical", description=data.alert_details, source_device_id=data.device_id, timestamp=datetime.now()))
        if hasattr(models, 'Log'): db.add(models.Log(device_id=data.device_id, event="Threat Detected", details=data.alert_details, timestamp=datetime.now()))
        db.commit()
        background_tasks.add_task(send_email_alert, data.device_id, data.alert_details)
    return {"status": "processed"}

@app.post("/api/devices/{device_id}/scan")
def trigger_scan(device_id: str, db: Session = Depends(database.get_db)):
    cmd = models.Command(device_id=device_id, type="deep_scan", status="pending")
    db.add(cmd); db.commit(); db.refresh(cmd)
    return {"command_id": cmd.id, "status": "queued"}

@app.get("/api/commands/{command_id}")
def get_command_status(command_id: int, db: Session = Depends(database.get_db)):
    cmd = db.query(models.Command).filter(models.Command.id == command_id).first()
    if not cmd: raise HTTPException(404, "Command not found")
    return {"status": cmd.status, "result": json.loads(cmd.result) if cmd.result else None}

@app.get("/api/agent/{device_id}/commands")
def get_pending_commands(device_id: str, db: Session = Depends(database.get_db)):
    cmd = db.query(models.Command).filter(models.Command.device_id == device_id, models.Command.status == "pending").first()
    if cmd: cmd.status = "processing"; db.commit(); return {"id": cmd.id, "type": cmd.type}
    return {"id": None}

@app.post("/api/agent/command_result")
def upload_result(data: CommandResult, db: Session = Depends(database.get_db)):
    cmd = db.query(models.Command).filter(models.Command.id == data.command_id).first()
    if cmd: cmd.status = "completed"; cmd.result = json.dumps(data.result); db.commit()
    return {"status": "ok"}

@app.get("/api/devices")
def get_devices(db: Session = Depends(database.get_db)): return db.query(models.Device).all()

@app.get("/api/logs")
def get_live_logs(db: Session = Depends(database.get_db)):
    try: return db.query(models.Log).order_by(models.Log.timestamp.desc()).limit(50).all()
    except: return []