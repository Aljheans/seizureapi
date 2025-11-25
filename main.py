from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, timedelta
import databases
import sqlalchemy
import os
import json
from fastapi.middleware.cors import CORSMiddleware

# ===== Database Setup =====
if "DATABASE_URL" in os.environ:
    raw_url = os.environ["DATABASE_URL"]
    if raw_url.startswith("postgres://"):
        raw_url = raw_url.replace("postgres://", "postgresql://", 1)
    DATABASE_URL = raw_url
    print("➡ Using PostgreSQL:", DATABASE_URL)
else:
    DATABASE_URL = f"sqlite:///{os.path.abspath('seizure.db')}"
    print("➡ Using SQLite fallback:", DATABASE_URL)

database = databases.Database(DATABASE_URL)
metadata = sqlalchemy.MetaData()

engine = sqlalchemy.create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
)

app = FastAPI(title="Seizure Monitor Backend")

# ===== Tables =====
users = sqlalchemy.Table(
    "users", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("username", sqlalchemy.String, unique=True),
    sqlalchemy.Column("password", sqlalchemy.String),
    sqlalchemy.Column("is_admin", sqlalchemy.Boolean, default=False),
)

devices = sqlalchemy.Table(
    "devices", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("user_id", sqlalchemy.Integer, sqlalchemy.ForeignKey("users.id")),
    sqlalchemy.Column("device_id", sqlalchemy.String, unique=True),
    sqlalchemy.Column("label", sqlalchemy.String),
)

device_data = sqlalchemy.Table(
    "device_data", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("device_id", sqlalchemy.String),
    sqlalchemy.Column("timestamp", sqlalchemy.DateTime),
    sqlalchemy.Column("payload", sqlalchemy.Text),
)

seizure_events = sqlalchemy.Table(
    "seizure_events", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("user_id", sqlalchemy.Integer, sqlalchemy.ForeignKey("users.id")),
    sqlalchemy.Column("timestamp", sqlalchemy.DateTime),
    sqlalchemy.Column("device_ids", sqlalchemy.String),
)

metadata.create_all(engine)

# ===== Models =====
class DevicePayload(BaseModel):
    device_id: str
    timestamp_ms: int
    sensors: dict
    seizure_flag: bool = False

# ===== Middleware =====
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ===== Startup / Shutdown =====
@app.on_event("startup")
async def startup():
    await database.connect()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

# ===== Health Check =====
@app.get("/api/health")
async def health_check():
    return {"status": "ok", "db": DATABASE_URL}

# ===== Devices Data Endpoint (No Auth) =====
@app.post("/api/devices/data")
async def receive_device_data(payload: DevicePayload):
    # Only save if device is registered
    device_row = await database.fetch_one(devices.select().where(devices.c.device_id == payload.device_id))
    if not device_row:
        raise HTTPException(status_code=403, detail="Device not registered")

    ts = datetime.utcfromtimestamp(payload.timestamp_ms / 1000.0)

    await database.execute(device_data.insert().values(
        device_id=payload.device_id,
        timestamp=ts,
        payload=json.dumps(payload.dict())
    ))

    # Seizure detection logic
    if payload.seizure_flag:
        user_id = device_row["user_id"]
        window_start = datetime.utcnow() - timedelta(seconds=5)

        user_devices = await database.fetch_all(devices.select().where(devices.c.user_id == user_id))
        ids = [d["device_id"] for d in user_devices]

        recent_rows = await database.fetch_all(
            device_data.select()
            .where(device_data.c.device_id.in_(ids))
            .where(device_data.c.timestamp >= window_start)
        )

        triggered = list({
            r["device_id"]
            for r in recent_rows
            if json.loads(r["payload"]).get("seizure_flag")
        })

        if len(triggered) >= 3:
            recent_log = await database.fetch_one(
                seizure_events.select()
                .where(seizure_events.c.user_id == user_id)
                .where(seizure_events.c.timestamp >= window_start)
            )
            if not recent_log:
                await database.execute(seizure_events.insert().values(
                    user_id=user_id,
                    timestamp=datetime.utcnow(),
                    device_ids=",".join(triggered)
                ))

    return {"status": "ok"}

# ===== Optional: List Registered Devices =====
@app.get("/api/devices")
async def list_devices():
    rows = await database.fetch_all(devices.select())
    output = []
    for r in rows:
        latest_data = await database.fetch_one(
            device_data.select()
            .where(device_data.c.device_id == r["device_id"])
            .order_by(device_data.c.timestamp.desc())
            .limit(1)
        )
        battery_percent = 100
        last_sync = None
        if latest_data:
            payload = json.loads(latest_data["payload"])
            battery_percent = payload.get("battery_percent", 100)
            last_sync = latest_data["timestamp"]
        output.append({
            "device_id": r["device_id"],
            "label": r["label"],
            "battery_percent": battery_percent,
            "last_sync": last_sync.isoformat() if last_sync else None
        })
    return output

# ===== Run =====
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
