from datetime import datetime, timedelta, timezone
from typing import Optional

try:
    from jose import JWTError, jwt
except Exception:
    JWTError = Exception

    class _JWTStub:
        @staticmethod
        def encode(*args, **kwargs):
            raise RuntimeError(
                "python-jose not installed; install python-jose[cryptography]"
            )

        @staticmethod
        def decode(*args, **kwargs):
            raise RuntimeError(
                "python-jose not installed; install python-jose[cryptography]"
            )

    jwt = _JWTStub()
from passlib.context import CryptContext
from pydantic import BaseModel

from .config import settings

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class TokenData(BaseModel):
    username: Optional[str] = None
    exp: Optional[datetime] = None


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password"""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Get password hash"""
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM
    )
    return encoded_jwt


def verify_token(token: str) -> TokenData:
    """Verify token"""
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        username: str = payload.get("sub")
        if username is None:
            raise JWTError
        token_data = TokenData(username=username)
    except JWTError:
        raise JWTError("Could not validate credentials")
    return token_data
