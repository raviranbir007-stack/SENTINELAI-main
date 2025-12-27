from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/register")
async def register(username: str, password: str):
    """Register a new user"""
    return {
        "status": "success",
        "message": "User registered successfully",
        "user_id": "user_123",
    }


@router.post("/login")
async def login(request: LoginRequest):
    """Login user"""
    return {
        "status": "success",
        "access_token": "token_xyz123",
        "token_type": "bearer",
        "user": {"id": "user_123", "username": request.username, "role": "admin"},
    }


@router.post("/logout")
async def logout():
    """Logout user"""
    return {"status": "success", "message": "Logged out successfully"}


@router.get("/me")
async def get_current_user():
    """Get current user info"""
    return {
        "id": "user_123",
        "username": "admin",
        "email": "admin@sentinel-ai.com",
        "role": "admin",
        "created_at": "2025-01-01T00:00:00",
    }
