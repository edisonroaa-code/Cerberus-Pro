"""
Auth Router — Extracted from ares_api.py (Fase 5 Refactoring).
Handles: register, login, refresh, logout, profile, forgot_password, reset_password, mfa_setup.
"""

import os
import secrets
import logging
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Request, HTTPException, Depends, status
from fastapi.responses import JSONResponse

from auth_security import (
    JWTManager, PasswordManager, MFAManager,
    User, UserCreate, LoginRequest, TokenResponse, Role,
    SecurityConfig, get_current_user, JWTPayload, TokenType,
    MFASetup, ResetPasswordRequest,
)
from services.email_service import EmailService

logger = logging.getLogger("cerberus.routers.auth")
router = APIRouter()


def _get_state():
    """Lazy import to avoid circular dependency with ares_api."""
    from ares_api import state
    return state


def _get_env():
    from ares_api import ENVIRONMENT
    return ENVIRONMENT


async def _audit(user_id, action, resource_type="auth", resource_id=None, status_val="success", error_message=None):
    """Proxy to ares_api.audit_log."""
    from ares_api import audit_log
    await audit_log(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        status=status_val,
        error_message=error_message,
    )


# ============================================================================
# AUTHENTICATION ENDPOINTS
# ============================================================================

@router.post("/register", response_model=User)
async def register(user_data: UserCreate):
    """Register new user (admin only in production)"""
    state = _get_state()

    # Validate username uniqueness
    if any(u.username == user_data.username for u in state.users.values()):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists"
        )

    # Create user
    user_id = f"user_{os.urandom(8).hex()}"
    user = User(
        id=user_id,
        username=user_data.username,
        email=user_data.email,
        full_name=user_data.full_name,
        role=user_data.role,
        password_hash=PasswordManager.hash_password(user_data.password),
        created_at=datetime.now(timezone.utc),
        last_login=None,
        mfa_enabled=user_data.role in [Role.ADMIN, Role.SUPER_ADMIN]
    )

    state.users[user_id] = user
    logger.info(f"✅ User registered: {user.username} ({user.role})")

    await _audit(user_id=user_id, action="user_created", resource_type="user", resource_id=user_id)

    return user


@router.post("/login", response_model=TokenResponse)
async def login(credentials: LoginRequest, request: Request):
    """Authenticate user and return JWT tokens"""
    state = _get_state()
    env = _get_env()

    # Find user
    user = None
    for u in state.users.values():
        if u.username == credentials.username:
            user = u
            break

    if not user or not PasswordManager.verify_password(credentials.password, user.password_hash):
        logger.warning(f"❌ Failed login attempt for: {credentials.username} from {request.client.host}")

        await _audit(
            user_id=credentials.username,
            action="login_failed",
            resource_type="auth",
            status_val="failure",
            error_message="Invalid credentials"
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )

    # Check MFA if enabled
    if user.mfa_enabled and SecurityConfig.MFA_REQUIRED_FOR_ROLES:
        if not credentials.mfa_code:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="MFA code required"
            )

        if not MFAManager.verify_totp(user.mfa_secret, credentials.mfa_code):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid MFA code"
            )

    # Generate tokens
    access_token = JWTManager.create_token(
        user_id=user.id,
        username=user.username,
        email=user.email,
        role=user.role
    )

    refresh_token = JWTManager.create_token(
        user_id=user.id,
        username=user.username,
        email=user.email,
        role=user.role,
        token_type=TokenType.REFRESH
    )

    # Update last login
    user.last_login = datetime.now(timezone.utc)

    logger.info(f"✅ User logged in: {user.username} from {request.client.host}")

    await _audit(user_id=user.id, action="login_success", resource_type="auth")

    # Cookie-first auth model
    response = JSONResponse(content={
        "access_token": access_token,
        "refresh_token": "",
        "expires_in": SecurityConfig.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "token_type": "bearer"
    })

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=env == "production",
        samesite="lax",
        path="/",
        max_age=SecurityConfig.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=env == "production",
        samesite="lax",
        path="/auth",
        max_age=SecurityConfig.JWT_REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
    )

    return response


@router.post("/refresh", response_model=TokenResponse)
async def refresh_access_token(request: Request):
    """Get new access token from refresh token"""
    state = _get_state()
    env = _get_env()

    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token missing")

    payload = JWTManager.verify_token(refresh_token)
    if str(payload.token_type) != TokenType.REFRESH.value:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token type")
    if payload.jti in state.revoked_tokens:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token revoked")

    user = state.users.get(payload.sub)
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not available")

    # Rotate refresh token
    state.revoked_tokens.add(payload.jti)
    new_access_token = JWTManager.create_token(
        user_id=user.id, username=user.username, email=user.email, role=user.role
    )
    new_refresh_token = JWTManager.create_token(
        user_id=user.id, username=user.username, email=user.email, role=user.role,
        token_type=TokenType.REFRESH
    )

    response = JSONResponse(content={
        "access_token": new_access_token,
        "refresh_token": "",
        "expires_in": SecurityConfig.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "token_type": "bearer"
    })
    response.set_cookie(
        key="access_token", value=new_access_token, httponly=True,
        secure=env == "production", samesite="lax", path="/",
        max_age=SecurityConfig.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )
    response.set_cookie(
        key="refresh_token", value=new_refresh_token, httponly=True,
        secure=env == "production", samesite="lax", path="/auth",
        max_age=SecurityConfig.JWT_REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
    )
    return response


@router.post("/logout")
async def logout(current_user: JWTPayload = Depends(get_current_user)):
    """Logout user (revoke token)"""
    state = _get_state()
    state.revoked_tokens.add(current_user.jti)
    logger.info(f"✅ User logged out: {current_user.username}")

    response = JSONResponse(content={"message": "Logged out successfully"})
    response.delete_cookie(key="access_token", path="/")
    response.delete_cookie(key="refresh_token", path="/auth")
    return response


@router.get("/me", tags=["Authentication"])
async def get_current_user_profile(current_user: JWTPayload = Depends(get_current_user)):
    """Get current user profile (session check)"""
    return {
        "id": current_user.sub,
        "username": current_user.username,
        "role": current_user.role,
        "permissions": current_user.permissions
    }


@router.post("/forgot-password", tags=["Authentication"])
async def forgot_password(email: str):
    """Request password reset link via email"""
    state = _get_state()
    user = next((u for u in state.users.values() if u.email == email), None)
    if not user:
        return {"message": "Si el correo existe, recibirá un token de recuperación."}

    token = secrets.token_urlsafe(32)
    user.reset_token = token
    user.reset_token_expiry = datetime.now(timezone.utc) + timedelta(hours=1)

    await EmailService.send_reset_email(user.email, user.username, token)

    logger.info(f"🔑 Password reset initiated for: {user.username}")

    return {"message": "Si el correo existe, recibirá un token de recuperación."}


@router.post("/reset-password", tags=["Authentication"])
async def reset_password(request: ResetPasswordRequest):
    """Reset password using token"""
    state = _get_state()
    user = next((u for u in state.users.values() if u.reset_token == request.token), None)

    if not user or (user.reset_token_expiry and user.reset_token_expiry < datetime.now(timezone.utc)):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token inválido o expirado"
        )

    user.password_hash = PasswordManager.hash_password(request.new_password)
    user.reset_token = None
    user.reset_token_expiry = None

    logger.info(f"✅ Password reset successfully for: {user.username}")

    await _audit(user_id=user.id, action="password_reset_success", resource_type="auth")

    return {"message": "Contraseña actualizada correctamente"}


@router.post("/mfa/setup", response_model=MFASetup)
async def setup_mfa(current_user: JWTPayload = Depends(get_current_user)):
    """Setup MFA for current user"""
    state = _get_state()

    if current_user.role not in [r.value for r in SecurityConfig.MFA_REQUIRED_FOR_ROLES]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="MFA required for admins only"
        )

    mfa_setup = MFAManager.setup_totp()

    user = state.users[current_user.sub]
    user.mfa_secret = mfa_setup.secret

    logger.info(f"✅ MFA setup initiated for: {current_user.username}")

    return mfa_setup
