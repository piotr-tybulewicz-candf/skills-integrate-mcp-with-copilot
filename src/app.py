"""
High School Management System API

A simple FastAPI application for viewing and managing extracurricular activities
with token-based authentication and role-based access control.
"""

from datetime import datetime, timedelta, UTC
import hashlib
import hmac
import os
from pathlib import Path
import secrets
from typing import Any, Dict, List, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

app = FastAPI(title="Mergington High School API",
              description="API for viewing and signing up for extracurricular activities")

# Mount the static files directory
current_dir = Path(__file__).parent
app.mount("/static", StaticFiles(directory=os.path.join(Path(__file__).parent,
          "static")), name="static")

# In-memory activity database
activities = {
    "Chess Club": {
        "description": "Learn strategies and compete in chess tournaments",
        "schedule": "Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 12,
        "participants": ["michael@mergington.edu", "daniel@mergington.edu"]
    },
    "Programming Class": {
        "description": "Learn programming fundamentals and build software projects",
        "schedule": "Tuesdays and Thursdays, 3:30 PM - 4:30 PM",
        "max_participants": 20,
        "participants": ["emma@mergington.edu", "sophia@mergington.edu"]
    },
    "Gym Class": {
        "description": "Physical education and sports activities",
        "schedule": "Mondays, Wednesdays, Fridays, 2:00 PM - 3:00 PM",
        "max_participants": 30,
        "participants": ["john@mergington.edu", "olivia@mergington.edu"]
    },
    "Soccer Team": {
        "description": "Join the school soccer team and compete in matches",
        "schedule": "Tuesdays and Thursdays, 4:00 PM - 5:30 PM",
        "max_participants": 22,
        "participants": ["liam@mergington.edu", "noah@mergington.edu"]
    },
    "Basketball Team": {
        "description": "Practice and play basketball with the school team",
        "schedule": "Wednesdays and Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["ava@mergington.edu", "mia@mergington.edu"]
    },
    "Art Club": {
        "description": "Explore your creativity through painting and drawing",
        "schedule": "Thursdays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["amelia@mergington.edu", "harper@mergington.edu"]
    },
    "Drama Club": {
        "description": "Act, direct, and produce plays and performances",
        "schedule": "Mondays and Wednesdays, 4:00 PM - 5:30 PM",
        "max_participants": 20,
        "participants": ["ella@mergington.edu", "scarlett@mergington.edu"]
    },
    "Math Club": {
        "description": "Solve challenging problems and participate in math competitions",
        "schedule": "Tuesdays, 3:30 PM - 4:30 PM",
        "max_participants": 10,
        "participants": ["james@mergington.edu", "benjamin@mergington.edu"]
    },
    "Debate Team": {
        "description": "Develop public speaking and argumentation skills",
        "schedule": "Fridays, 4:00 PM - 5:30 PM",
        "max_participants": 12,
        "participants": ["charlotte@mergington.edu", "henry@mergington.edu"]
    }
}

# In-memory users and auth tokens (for demo/exercise purposes)
ROLE_STUDENT = "student"
ROLE_CLUB_ADMIN = "club_admin"
ROLE_SUPER_ADMIN = "super_admin"
VALID_ROLES = {ROLE_STUDENT, ROLE_CLUB_ADMIN, ROLE_SUPER_ADMIN}
TOKEN_TTL_HOURS = 8

users: Dict[str, Dict[str, Any]] = {}
tokens: Dict[str, Dict[str, Any]] = {}


class RegisterRequest(BaseModel):
    username: str
    password: str
    role: Literal["student", "club_admin", "super_admin"]


class LoginRequest(BaseModel):
    username: str
    password: str


class ActivityUpsertRequest(BaseModel):
    name: str
    description: str
    schedule: str
    max_participants: int


def _hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt),
        120000,
    ).hex()


def _create_user(username: str, password: str, role: str) -> None:
    if role not in VALID_ROLES:
        raise ValueError("Invalid role")
    salt = secrets.token_hex(16)
    users[username] = {
        "username": username,
        "role": role,
        "salt": salt,
        "password_hash": _hash_password(password, salt),
    }


def _verify_password(username: str, password: str) -> bool:
    user = users.get(username)
    if not user:
        return False
    expected_hash = user["password_hash"]
    computed_hash = _hash_password(password, user["salt"])
    return hmac.compare_digest(expected_hash, computed_hash)


def _issue_token(username: str, role: str) -> str:
    token = secrets.token_urlsafe(48)
    tokens[token] = {
        "username": username,
        "role": role,
        "expires_at": datetime.now(UTC) + timedelta(hours=TOKEN_TTL_HOURS),
    }
    return token


def _parse_bearer_token(authorization: str | None) -> str:
    if not authorization:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Missing Authorization header")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid authorization scheme")
    return token


def get_current_user(authorization: str | None = Header(default=None)) -> Dict[str, Any]:
    token = _parse_bearer_token(authorization)
    session = tokens.get(token)
    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid token")
    if session["expires_at"] < datetime.now(UTC):
        tokens.pop(token, None)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Token expired")
    return session


def require_roles(allowed_roles: List[str]):
    def _role_dependency(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
        if user["role"] not in allowed_roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="Insufficient permissions for this action")
        return user
    return _role_dependency


def _get_activity_or_404(activity_name: str) -> Dict[str, Any]:
    activity = activities.get(activity_name)
    if not activity:
        raise HTTPException(status_code=404, detail="Activity not found")
    return activity


# Default super admin for initial access in demos.
_create_user("superadmin", "change-me-now", ROLE_SUPER_ADMIN)


@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")


@app.post("/auth/register")
def register(payload: RegisterRequest):
    if payload.username in users:
        raise HTTPException(status_code=400, detail="Username already exists")
    if len(payload.password) < 8:
        raise HTTPException(status_code=400,
                            detail="Password must be at least 8 characters")

    _create_user(payload.username, payload.password, payload.role)
    return {
        "message": f"User {payload.username} registered successfully",
        "username": payload.username,
        "role": payload.role,
    }


@app.post("/auth/login")
def login(payload: LoginRequest):
    if not _verify_password(payload.username, payload.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid username or password")

    role = users[payload.username]["role"]
    token = _issue_token(payload.username, role)
    return {
        "access_token": token,
        "token_type": "bearer",
        "username": payload.username,
        "role": role,
        "expires_in_seconds": TOKEN_TTL_HOURS * 3600,
    }


@app.get("/auth/me")
def who_am_i(user: Dict[str, Any] = Depends(get_current_user)):
    return {
        "username": user["username"],
        "role": user["role"],
    }


@app.get("/activities")
def get_activities():
    return activities


@app.post("/activities/{activity_name}/signup")
def signup_for_activity(
    activity_name: str,
    email: str,
    user: Dict[str, Any] = Depends(require_roles([
        ROLE_STUDENT,
        ROLE_CLUB_ADMIN,
        ROLE_SUPER_ADMIN,
    ])),
):
    """Sign up a student for an activity"""
    # Students can only sign up themselves.
    if user["role"] == ROLE_STUDENT and email != user["username"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Students may only sign themselves up",
        )

    activity = _get_activity_or_404(activity_name)

    if len(activity["participants"]) >= activity["max_participants"]:
        raise HTTPException(
            status_code=400,
            detail="Activity is full",
        )

    # Validate student is not already signed up
    if email in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is already signed up"
        )

    # Add student
    activity["participants"].append(email)
    return {"message": f"Signed up {email} for {activity_name}"}


@app.delete("/activities/{activity_name}/unregister")
def unregister_from_activity(
    activity_name: str,
    email: str,
    _: Dict[str, Any] = Depends(require_roles([ROLE_CLUB_ADMIN, ROLE_SUPER_ADMIN])),
):
    """Unregister a student from an activity"""
    activity = _get_activity_or_404(activity_name)

    # Validate student is signed up
    if email not in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is not signed up for this activity"
        )

    # Remove student
    activity["participants"].remove(email)
    return {"message": f"Unregistered {email} from {activity_name}"}


@app.post("/activities")
def create_activity(
    payload: ActivityUpsertRequest,
    _: Dict[str, Any] = Depends(require_roles([ROLE_CLUB_ADMIN, ROLE_SUPER_ADMIN])),
):
    if payload.max_participants < 1:
        raise HTTPException(status_code=400,
                            detail="max_participants must be greater than 0")
    if payload.name in activities:
        raise HTTPException(status_code=400, detail="Activity already exists")

    activities[payload.name] = {
        "description": payload.description,
        "schedule": payload.schedule,
        "max_participants": payload.max_participants,
        "participants": [],
    }
    return {"message": f"Created activity {payload.name}"}


@app.put("/activities/{activity_name}")
def update_activity(
    activity_name: str,
    payload: ActivityUpsertRequest,
    _: Dict[str, Any] = Depends(require_roles([ROLE_CLUB_ADMIN, ROLE_SUPER_ADMIN])),
):
    activity = _get_activity_or_404(activity_name)
    if payload.max_participants < len(activity["participants"]):
        raise HTTPException(
            status_code=400,
            detail="max_participants cannot be less than current participant count",
        )

    if payload.name != activity_name and payload.name in activities:
        raise HTTPException(status_code=400, detail="Target activity name already exists")

    updated_activity = {
        "description": payload.description,
        "schedule": payload.schedule,
        "max_participants": payload.max_participants,
        "participants": activity["participants"],
    }

    activities.pop(activity_name)
    activities[payload.name] = updated_activity
    return {"message": f"Updated activity {payload.name}"}


@app.get("/admin/overview")
def admin_overview(
    _: Dict[str, Any] = Depends(require_roles([ROLE_SUPER_ADMIN])),
):
    total_participants = sum(len(a["participants"]) for a in activities.values())
    return {
        "activity_count": len(activities),
        "user_count": len(users),
        "participants_total": total_participants,
        "users_by_role": {
            ROLE_STUDENT: sum(1 for user in users.values() if user["role"] == ROLE_STUDENT),
            ROLE_CLUB_ADMIN: sum(1 for user in users.values() if user["role"] == ROLE_CLUB_ADMIN),
            ROLE_SUPER_ADMIN: sum(1 for user in users.values() if user["role"] == ROLE_SUPER_ADMIN),
        },
    }
