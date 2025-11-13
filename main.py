from fastapi import FastAPI, Depends, HTTPException, Body
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, timedelta
from jose import JWTError, jwt
import databases
import sqlalchemy

DATABASE_URL = "sqlite:///./seizure.db"
database = databases.Database(DATABASE_URL)
metadata = sqlalchemy.MetaData()

# Tables
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
    sqlalchemy.Column("payload", sqlalchemy.JSON),
)


seizure_events = sqlalchemy.Table(
    "seizure_events", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("user_id", sqlalchemy.Integer, sqlalchemy.ForeignKey("users.id")),
    sqlalchemy.Column("timestamp", sqlalchemy.DateTime),
    sqlalchemy.Column("device_ids", sqlalchemy.String),
)

engine = sqlalchemy.create_engine(DATABASE_URL)
metadata.create_all(engine)
app = FastAPI(title="Seizure Monitor Backend")

SECRET_KEY = "CHANGE_THIS_SECRET"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

class UserCreate(BaseModel):
    username: str
    password: str
    is_admin: Optional[bool] = False

class Token(BaseModel):
    access_token: str
    token_type: str

class LoginRequest(BaseModel):
    username: str
    password: str

class DeviceRegister(BaseModel):
    device_id: str
    label: Optional[str] = None

class DeviceUpdate(BaseModel):
    label: str

class DevicePayload(BaseModel):
    device_id: str
    timestamp_ms: int
    sensors: dict
    seizure_flag: bool = False


async def get_user_by_username(username: str):
    query = users.select().where(users.c.username == username)
    return await database.fetch_one(query)

async def authenticate_user(username: str, password: str):
    user = await get_user_by_username(username)
    if not user or password != user["password"]:
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

@app.on_event("startup")
async def startup():
    await database.connect()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

#Auth Routes
@app.post("/api/register", response_model=dict)
async def register(u: UserCreate):
    existing = await get_user_by_username(u.username)
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    query = users.insert().values(username=u.username, password=u.password, is_admin=u.is_admin)
    user_id = await database.execute(query)
    return {"id": user_id, "username": u.username}

@app.post("/api/login", response_model=Token)
async def login(body: LoginRequest = Body(...)):
    user = await authenticate_user(body.username, body.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token = create_access_token(
        {"sub": user["username"], "is_admin": user["is_admin"]},
        timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}

#Security
from fastapi.security import OAuth2PasswordBearer
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(status_code=401, detail="Invalid or expired token")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = await get_user_by_username(username)
    if user is None:
        raise credentials_exception
    return user

#Current user info
@app.get("/api/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    return {
        "id": current_user["id"],
        "username": current_user["username"],
        "is_admin": current_user["is_admin"]
    }

# Device Management
@app.post("/api/devices/register")
async def register_device(d: DeviceRegister, current_user: dict = Depends(get_current_user)):
    q_count = devices.select().where(devices.c.user_id == current_user["id"])
    user_devices = await database.fetch_all(q_count)
    if len(user_devices) >= 4:
        raise HTTPException(status_code=400, detail="Maximum of 4 devices allowed per user")

    existing = await database.fetch_one(devices.select().where(devices.c.device_id == d.device_id))
    if existing:
        raise HTTPException(status_code=400, detail="Device ID already registered")

    q = devices.insert().values(user_id=current_user["id"], device_id=d.device_id, label=d.label or d.device_id)
    await database.execute(q)
    return {"status": "ok", "device_id": d.device_id}

@app.get("/api/mydevices")
async def get_my_devices(current_user: dict = Depends(get_current_user)):
    q = devices.select().where(devices.c.user_id == current_user["id"])
    rows = await database.fetch_all(q)
    return [{"device_id": r["device_id"], "label": r["label"]} for r in rows]

@app.put("/api/devices/{device_id}")
async def update_device(device_id: str, body: DeviceUpdate, current_user: dict = Depends(get_current_user)):
    device = await database.fetch_one(
        devices.select().where((devices.c.device_id == device_id) & (devices.c.user_id == current_user["id"]))
    )
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    q = devices.update().where(devices.c.id == device["id"]).values(label=body.label)
    await database.execute(q)
    return {"status": "updated", "device_id": device_id, "label": body.label}

# Delete device
@app.delete("/api/devices/{device_id}")
async def delete_device(device_id: str, current_user: dict = Depends(get_current_user)):
    device = await database.fetch_one(
        devices.select().where((devices.c.device_id == device_id) & (devices.c.user_id == current_user["id"]))
    )
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    await database.execute(devices.delete().where(devices.c.id == device["id"]))
    return {"status": "deleted", "device_id": device_id}

#Device Data
@app.post("/api/devices/data")
async def receive_device_data(payload: DevicePayload):
    device_row = await database.fetch_one(devices.select().where(devices.c.device_id == payload.device_id))
    if not device_row:
        raise HTTPException(status_code=403, detail="Device not registered")

    ts = datetime.utcfromtimestamp(payload.timestamp_ms / 1000.0)

    q = device_data.insert().values(
        device_id=payload.device_id,
        timestamp=ts,
        payload=payload.dict()
    )
    await database.execute(q)

    if payload.seizure_flag:
        user_id = device_row["user_id"]
        user_devices = await database.fetch_all(devices.select().where(devices.c.user_id == user_id))
        device_ids = [d["device_id"] for d in user_devices]
        window_start = datetime.utcnow() - timedelta(seconds=5)
        recent_rows = await database.fetch_all(
            device_data.select()
            .where(device_data.c.device_id.in_(device_ids))
            .where(device_data.c.timestamp >= window_start)
        )
        triggered_devices = [r["device_id"] for r in recent_rows if r["payload"].get("seizure_flag")]
        unique_triggered = list(set(triggered_devices))

        if len(unique_triggered) >= 3:
            existing_recent = await database.fetch_one(
                seizure_events.select()
                .where(seizure_events.c.user_id == user_id)
                .where(seizure_events.c.timestamp >= window_start)
            )
            if not existing_recent:
                await database.execute(
                    seizure_events.insert().values(
                        user_id=user_id,
                        timestamp=datetime.utcnow(),
                        device_ids=",".join(unique_triggered)
                    )
                )

    return {"status": "ok"}

@app.get("/api/devices/{device_id}", response_model=List[dict])
async def get_device_history(device_id: str, current_user: dict = Depends(get_current_user)):
    d = await database.fetch_one(devices.select().where(
        (devices.c.device_id == device_id) & (devices.c.user_id == current_user["id"])
    ))
    if not d:
        raise HTTPException(status_code=403, detail="Not your device")

    q = device_data.select().where(device_data.c.device_id == device_id)\
        .order_by(device_data.c.timestamp.desc()).limit(1000)
    rows = await database.fetch_all(q)
    return [
        {
            "id": r["id"],
            "device_id": r["device_id"],
            "timestamp": r["timestamp"].isoformat(),
            "payload": r["payload"]
        } for r in rows
    ]

# Admin: list users
@app.get("/api/users")
async def list_users(current_user: dict = Depends(get_current_user)):
    if not current_user["is_admin"]:
        raise HTTPException(status_code=403, detail="Not allowed")
    q = users.select()
    rows = await database.fetch_all(q)
    return [{"id": r["id"], "username": r["username"], "is_admin": r["is_admin"]} for r in rows]

#Seizure events
@app.get("/api/seizure_events")
async def get_seizure_events(current_user: dict = Depends(get_current_user)):
    q = seizure_events.select().where(seizure_events.c.user_id == current_user["id"]).order_by(seizure_events.c.timestamp.desc())
    rows = await database.fetch_all(q)
    return [
        {
            "timestamp": r["timestamp"].isoformat(),
            "device_ids": r["device_ids"].split(",")
        }
        for r in rows
    ]

@app.get("/api/seizure_events/latest")
async def get_latest_event(current_user: dict = Depends(get_current_user)):
    q = (
        seizure_events.select()
        .where(seizure_events.c.user_id == current_user["id"])
        .order_by(seizure_events.c.timestamp.desc())
        .limit(1)
    )
    row = await database.fetch_one(q)
    if not row:
        return {}
    return {"timestamp": row["timestamp"].isoformat(), "device_ids": row["device_ids"].split(",")}
