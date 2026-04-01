
from fastapi import Depends, HTTPException, status
from ....models import User
from ....database import get_db
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

async def get_current_user_obj(db: AsyncSession = Depends(get_db)):
    # This is a placeholder. Replace with real authentication (token/cookie based)
    user = await db.execute(text("SELECT * FROM users WHERE username='admin'"))
    user_obj = user.fetchone()
    if not user_obj:
        raise HTTPException(status_code=401, detail="User not found")
    return user_obj

async def admin_required(user=Depends(get_current_user_obj)):
    # In real code, check user['is_admin'] or similar
    if not user or not getattr(user, 'is_admin', True):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return user
from fastapi import APIRouter
from datetime import timedelta
from pydantic import BaseModel
from ....auth import verify_password, get_password_hash, create_access_token
from ....config import settings

router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/register")
async def register(username: str, password: str, db: AsyncSession = Depends(get_db)):
    """Register a new user — creates a hashed-password user record."""
    from sqlalchemy.future import select as sa_select
    existing = await db.execute(sa_select(User).where(User.username == username))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Username already exists")
    hashed = get_password_hash(password)
    new_user = User(
        username=username,
        email=f"{username}@sentinel-ai.local",
        hashed_password=hashed,
        is_active=True,
        is_admin=False,
    )
    db.add(new_user)
    await db.commit()
    return {"status": "success", "message": "User registered successfully"}


@router.post("/login")
async def login(request: LoginRequest, db: AsyncSession = Depends(get_db)):
    """Login — validates credentials against DB user OR env MASTER_CLIENT_PASSWORD."""
    from sqlalchemy.future import select as sa_select
    # 1. Try DB user first
    result = await db.execute(sa_select(User).where(User.username == request.username))
    user = result.scalar_one_or_none()
    if user and verify_password(request.password, user.hashed_password):
        token = create_access_token(
            {"sub": user.username, "admin": user.is_admin},
            expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        )
        return {
            "status": "success",
            "access_token": token,
            "token_type": "bearer",
            "user": {
                "id": user.id,
                "username": user.username,
                "role": "admin" if user.is_admin else "user",
            },
        }
    # 2. Fallback: single admin account via env credentials
    admin_user = str(getattr(settings, "ADMIN_EMAIL", "") or "admin").split("@")[0] or "admin"
    master_pw = str(settings.MASTER_CLIENT_PASSWORD or "")
    if master_pw and request.username in {"admin", admin_user} and request.password == master_pw:
        token = create_access_token(
            {"sub": "admin", "admin": True},
            expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        )
        return {
            "status": "success",
            "access_token": token,
            "token_type": "bearer",
            "user": {"id": 0, "username": "admin", "role": "admin"},
        }
    raise HTTPException(status_code=401, detail="Invalid username or password")


@router.post("/logout")
async def logout():
    """Logout — client should discard the token."""
    return {"status": "success", "message": "Logged out successfully"}


@router.get("/me")
async def get_current_user():
    """Get current user info (placeholder — wire up JWT token verification as needed)."""
    return {
        "id": 0,
        "username": "admin",
        "email": settings.ADMIN_EMAIL or "admin@sentinel-ai.com",
        "role": "admin",
    }
