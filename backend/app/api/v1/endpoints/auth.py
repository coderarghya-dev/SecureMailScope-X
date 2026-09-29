"""
SecureMailScope X - Authentication REST Endpoints (Phase 29)
Provides User Registration, Login, JWT Token Issuance, and Profile Verification.
"""

from typing import Optional, Union, Any
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, field_validator

from app.core.auth import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
    UserRepository
)

router = APIRouter(prefix="/auth")
security = HTTPBearer(auto_error=False)


# =====================================================================
# Request / Response Schemas
# =====================================================================

class UserRegisterRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100, description="Full name or analyst handle")
    email: str = Field(..., min_length=5, max_length=255, description="Unique email address")
    password: str = Field(..., min_length=6, max_length=128, description="Account password (min 6 chars)")


class UserLoginRequest(BaseModel):
    email: str = Field(..., description="Registered email address")
    password: str = Field(..., description="Account password")


class UserResponse(BaseModel):
    id: str
    name: str
    email: str
    created_at: str

    @field_validator("created_at", mode="before")
    @classmethod
    def serialize_created_at(cls, v: Any) -> str:
        if v is None:
            return ""
        if hasattr(v, "isoformat"):
            return v.isoformat()
        return str(v)


class AuthTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


# =====================================================================
# Dependency: Get Current Authenticated User
# =====================================================================

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> dict:
    """
    Validates the Bearer JWT token from Authorization header.
    Returns authenticated user dict or raises HTTP 401 Unauthorized.
    """
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    payload = decode_access_token(token)
    if not payload or "sub" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload["sub"]
    user = UserRepository.get_user_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account no longer exists.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


async def get_optional_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Optional[dict]:
    """
    Extracts authenticated user from Bearer JWT token if present, returns None if unauthenticated.
    """
    if not credentials or not credentials.credentials:
        return None
    token = credentials.credentials
    payload = decode_access_token(token)
    if not payload or "sub" not in payload:
        return None
    user_id = payload["sub"]
    return UserRepository.get_user_by_id(user_id)


# =====================================================================
# API Endpoints
# =====================================================================

@router.post(
    "/register",
    response_model=AuthTokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register New User Account",
    description="Creates a new user account with securely hashed password and returns access token."
)
def register_user(req: UserRegisterRequest):
    clean_email = req.email.strip().lower()
    if "@" not in clean_email or "." not in clean_email.split("@")[-1]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email format."
        )

    existing_user = UserRepository.get_user_by_email(clean_email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email address already exists."
        )

    pwd_hash = hash_password(req.password)
    user = UserRepository.create_user(
        name=req.name.strip(),
        email=clean_email,
        password_hash=pwd_hash
    )

    token = create_access_token({"sub": user["id"], "email": user["email"], "name": user["name"]})

    return AuthTokenResponse(
        access_token=token,
        token_type="bearer",
        user=UserResponse(
            id=user["id"],
            name=user["name"],
            email=user["email"],
            created_at=user["created_at"]
        )
    )


@router.post(
    "/login",
    response_model=AuthTokenResponse,
    summary="User Login & Token Generation",
    description="Authenticates credentials and returns a signed JWT access token."
)
def login_user(req: UserLoginRequest):
    clean_email = req.email.strip().lower()
    user = UserRepository.get_user_by_email(clean_email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    if not verify_password(req.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    token = create_access_token({"sub": user["id"], "email": user["email"], "name": user["name"]})

    return AuthTokenResponse(
        access_token=token,
        token_type="bearer",
        user=UserResponse(
            id=user["id"],
            name=user["name"],
            email=user["email"],
            created_at=user["created_at"]
        )
    )


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get Current User Profile",
    description="Returns profile of the currently authenticated user based on validated JWT token."
)
def get_current_user_profile(user: dict = Depends(get_current_user)):
    return UserResponse(
        id=user["id"],
        name=user["name"],
        email=user["email"],
        created_at=user["created_at"]
    )
