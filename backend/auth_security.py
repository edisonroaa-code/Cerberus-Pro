"""
Cerberus Pro - Advanced Authentication & Authorization Module
Enterprise-grade security with JWT, OAuth2, MFA, RBAC, ABAC
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Set
from enum import Enum
import os
import secrets
from fastapi import Request, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, OAuth2
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
import hashlib
import hmac
from functools import wraps

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
import bcrypt
from pydantic import BaseModel, Field, EmailStr, field_validator, ConfigDict
import pyotp
import qrcode
from io import BytesIO
import base64
from cryptography.fernet import Fernet

# ============================================================================
# ENUMS & CONSTANTS
# ============================================================================

class Role(str, Enum):
    """User roles with hierarchical permissions"""
    SUPER_ADMIN = "super_admin"      # Full access
    ADMIN = "admin"                  # System administration
    LEAD = "lead"                    # Team lead
    PENTESTER = "pentester"          # Authorized pentester
    ANALYST = "analyst"              # Can view results only
    GUEST = "guest"                  # Read-only access
    AGENT = "agent"                  # Remote C2 Agent

class Permission(str, Enum):
    """Granular permissions (RBAC)"""
    # Scanning permissions
    SCAN_CREATE = "scan:create"
    SCAN_READ = "scan:read"
    SCAN_MODIFY = "scan:modify"
    SCAN_DELETE = "scan:delete"
    
    # Reporting permissions
    REPORT_CREATE = "report:create"
    REPORT_READ = "report:read"
    REPORT_EXPORT = "report:export"
    REPORT_DELETE = "report:delete"
    
    # User management
    USER_CREATE = "user:create"
    USER_READ = "user:read"
    USER_MODIFY = "user:modify"
    USER_DELETE = "user:delete"
    
    # Admin operations
    ADMIN_CONFIG = "admin:config"
    ADMIN_AUDIT = "admin:audit"
    ADMIN_SECRETS = "admin:secrets"
    
    # Target management
    TARGET_MANAGE = "target:manage"

    # Agent permissions
    AGENT_CONNECT = "agent:connect"
    AGENT_TASK_READ = "agent:task:read"
    AGENT_RESULT_WRITE = "agent:result:write"
    AGENT_MANAGE = "agent:manage"

# Role-Permission Mapping
ROLE_PERMISSIONS: Dict[Role, Set[Permission]] = {
    Role.SUPER_ADMIN: set(Permission),  # All permissions
    Role.ADMIN: {
        Permission.SCAN_CREATE, Permission.SCAN_READ, Permission.SCAN_MODIFY, Permission.SCAN_DELETE,
        Permission.REPORT_CREATE, Permission.REPORT_READ, Permission.REPORT_EXPORT, Permission.REPORT_DELETE,
        Permission.USER_CREATE, Permission.USER_READ, Permission.USER_MODIFY, Permission.USER_DELETE,
        Permission.ADMIN_CONFIG, Permission.ADMIN_AUDIT, Permission.TARGET_MANAGE,
        Permission.AGENT_MANAGE
    },
    Role.LEAD: {
        Permission.SCAN_CREATE, Permission.SCAN_READ, Permission.SCAN_MODIFY,
        Permission.REPORT_CREATE, Permission.REPORT_READ, Permission.REPORT_EXPORT,
        Permission.USER_READ, Permission.TARGET_MANAGE,
        Permission.AGENT_MANAGE
    },
    Role.PENTESTER: {
        Permission.SCAN_CREATE, Permission.SCAN_READ, Permission.SCAN_MODIFY,
        Permission.REPORT_CREATE, Permission.REPORT_READ, Permission.REPORT_EXPORT
    },
    Role.ANALYST: {
        Permission.SCAN_READ, Permission.REPORT_READ, Permission.REPORT_EXPORT
    },
    Role.GUEST: {
        Permission.REPORT_READ,
    },
    Role.AGENT: {
        Permission.AGENT_CONNECT, Permission.AGENT_TASK_READ, Permission.AGENT_RESULT_WRITE
    }
}

class MFAMethod(str, Enum):
    """Supported MFA methods"""
    TOTP = "totp"           # Time-based One-Time Password
    EMAIL = "email"
    SMS = "sms"
    HARDWARE_KEY = "hardware_key"

class TokenType(str, Enum):
    """JWT token types"""
    ACCESS = "access"
    REFRESH = "refresh"
    API_KEY = "api_key"

# Security configuration
class SecurityConfig:
    """Central security configuration"""
    
    # JWT Configuration
    JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "")
    if not JWT_SECRET_KEY:
        import warnings
        warnings.warn("SEC-003: JWT_SECRET_KEY not set! Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(64))\"", stacklevel=2)
        JWT_SECRET_KEY = "INSECURE-DEFAULT-CHANGE-ME"
    JWT_ISSUER = os.environ.get("JWT_ISSUER", "cerberus-pro")
    JWT_AUDIENCE = os.environ.get("JWT_AUDIENCE", "cerberus-dashboard")
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", 30))
    JWT_REFRESH_TOKEN_EXPIRE_DAYS = int(os.environ.get("JWT_REFRESH_TOKEN_EXPIRE_DAYS", 7))
    
    # Password Policy
    MIN_PASSWORD_LENGTH = 12
    REQUIRE_UPPERCASE = True
    REQUIRE_LOWERCASE = True
    REQUIRE_NUMBERS = True
    REQUIRE_SPECIAL_CHARS = True
    PASSWORD_EXPIRY_DAYS = 90
    PASSWORD_HISTORY_COUNT = 5
    
    # Session Management
    SESSION_TIMEOUT_MINUTES = 30
    MAX_SESSIONS_PER_USER = 3
    
    # Brute Force Protection
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION_MINUTES = 15
    
    # Rate Limiting
    RATE_LIMIT_REQUESTS = 100
    RATE_LIMIT_WINDOW_SECONDS = 60
    
    # MFA Configuration
    MFA_REQUIRED_FOR_ROLES = [Role.ADMIN, Role.SUPER_ADMIN]
    MFA_CODE_EXPIRY_SECONDS = 300
    MFA_MAX_ATTEMPTS = 3
    
    # Encryption
    MFA_ENCRYPTION_KEY = os.environ.get("MFA_ENCRYPTION_KEY", Fernet.generate_key().decode())


# ============================================================================
# DATA MODELS
# ============================================================================

class User(BaseModel):
    """User data model"""
    id: str
    username: str
    email: EmailStr
    full_name: str
    role: Role
    is_active: bool = True
    created_at: datetime
    last_login: Optional[datetime]
    password_hash: str  # Never expose this
    mfa_enabled: bool = False
    mfa_method: Optional[MFAMethod] = None
    mfa_secret: Optional[str] = None  # Encrypted
    reset_token: Optional[str] = None
    reset_token_expiry: Optional[datetime] = None
    
    model_config = ConfigDict(use_enum_values=True)

class UserCreate(BaseModel):
    """User creation request"""
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    full_name: str = Field(..., min_length=2)
    password: str = Field(..., min_length=SecurityConfig.MIN_PASSWORD_LENGTH)
    role: Role = Role.PENTESTER
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v: str) -> str:
        """Validate password complexity"""
        if SecurityConfig.REQUIRE_UPPERCASE and not any(c.isupper() for c in v):
            raise ValueError('Password must contain uppercase letter')
        if SecurityConfig.REQUIRE_LOWERCASE and not any(c.islower() for c in v):
            raise ValueError('Password must contain lowercase letter')
        if SecurityConfig.REQUIRE_NUMBERS and not any(c.isdigit() for c in v):
            raise ValueError('Password must contain digit')
        if SecurityConfig.REQUIRE_SPECIAL_CHARS and not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in v):
            raise ValueError('Password must contain special character')
        return v

class LoginRequest(BaseModel):
    """Login request"""
    username: str
    password: str
    mfa_code: Optional[str] = None

class TokenResponse(BaseModel):
    """JWT token response"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds

class ResetPasswordRequest(BaseModel):
    """Password reset request"""
    token: str
    new_password: str = Field(..., min_length=SecurityConfig.MIN_PASSWORD_LENGTH)

class JWTPayload(BaseModel):
    """JWT token payload"""
    sub: str  # user_id
    username: str
    email: str
    role: Role
    permissions: List[Permission]
    token_type: TokenType
    session_id: str
    iat: datetime
    exp: datetime
    jti: str  # JWT ID for revocation

class APIKeyModel(BaseModel):
    """API Key data model"""
    id: str
    user_id: str
    key_hash: str  # Never store plain key
    name: str
    scopes: List[Permission]
    is_active: bool
    created_at: datetime
    last_used: Optional[datetime]
    expires_at: Optional[datetime]

class MFASetup(BaseModel):
    """MFA setup response"""
    secret: str
    qr_code: str  # Base64 encoded
    backup_codes: List[str]

class AuditLog(BaseModel):
    """Audit log entry"""
    id: str
    user_id: str
    action: str
    resource_type: str
    resource_id: Optional[str]
    before: Optional[Dict]
    after: Optional[Dict]
    status: str  # success, failure
    error_message: Optional[str]
    timestamp: datetime
    ip_address: str
    user_agent: str

class Agent(BaseModel):
    """C2 Agent identity"""
    id: str
    name: str
    client_id: str
    client_secret_hash: str
    is_active: bool = True
    created_at: datetime
    last_connected: Optional[datetime]
    ip_address: Optional[str]
    version: Optional[str]

class AgentCredentials(BaseModel):
    """Agent login credentials"""
    client_id: str
    client_secret: str


# ============================================================================
# PASSWORD MANAGEMENT
# ============================================================================

class PasswordManager:
    """Secure password hashing and validation"""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password with bcrypt"""
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode(), salt).decode()
    
    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    
    @staticmethod
    def is_password_expired(last_changed: datetime) -> bool:
        """Check if password needs renewal"""
        now = datetime.now(timezone.utc)
        if last_changed.tzinfo is None:
            last_changed = last_changed.replace(tzinfo=timezone.utc)
        return (now - last_changed).days > SecurityConfig.PASSWORD_EXPIRY_DAYS


# ============================================================================
# JWT MANAGEMENT
# ============================================================================

class JWTManager:
    """JWT token generation and validation"""
    
    @staticmethod
    def create_token(
        user_id: str,
        username: str,
        email: str,
        role: Role,
        token_type: TokenType = TokenType.ACCESS,
        session_id: str = None,
        expires_in: Optional[timedelta] = None
    ) -> str:
        """Create JWT token"""

        # Pydantic models may store enums as raw values when `use_enum_values=True`.
        # Fail closed by coercing to the proper enum type.
        if isinstance(role, str):
            role = Role(role)
        if isinstance(token_type, str):
            token_type = TokenType(token_type)
        
        # Determine expiration
        if expires_in is None:
            if token_type == TokenType.ACCESS:
                expires_in = timedelta(minutes=SecurityConfig.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
            elif token_type == TokenType.REFRESH:
                expires_in = timedelta(days=SecurityConfig.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
            else:
                expires_in = timedelta(hours=1)
        
        now = datetime.now(timezone.utc)
        expire = now + expires_in
        
        # Build payload
        payload = {
            'sub': user_id,
            'username': username,
            'email': email,
            'role': role.value,
            'permissions': [p.value for p in ROLE_PERMISSIONS[role]],
            'token_type': token_type.value,
            'session_id': session_id or secrets.token_urlsafe(32),
            'iat': int(now.timestamp()),
            'exp': int(expire.timestamp()),
            'jti': secrets.token_urlsafe(32),  # Token ID for revocation
            'iss': SecurityConfig.JWT_ISSUER,
            'aud': SecurityConfig.JWT_AUDIENCE,
        }
        
        token = jwt.encode(
            payload,
            SecurityConfig.JWT_SECRET_KEY,
            algorithm=SecurityConfig.JWT_ALGORITHM
        )
        return token
    
    @staticmethod
    def verify_token(token: str) -> JWTPayload:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(
                token,
                SecurityConfig.JWT_SECRET_KEY,
                algorithms=[SecurityConfig.JWT_ALGORITHM],
                issuer=SecurityConfig.JWT_ISSUER,
                audience=SecurityConfig.JWT_AUDIENCE,
            )
            return JWTPayload(**payload)
        except JWTError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token: {str(e)}"
            )
    
    @staticmethod
    def refresh_token(refresh_token: str) -> str:
        """Create new access token from refresh token"""
        payload = JWTManager.verify_token(refresh_token)
        
        if payload.token_type != TokenType.REFRESH:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not a refresh token"
            )
        
        return JWTManager.create_token(
            user_id=payload.sub,
            username=payload.username,
            email=payload.email,
            role=Role(payload.role),
            token_type=TokenType.ACCESS,
            session_id=payload.session_id
        )


# ============================================================================
# API KEY MANAGEMENT
# ============================================================================

class APIKeyManager:
    """API key generation and validation"""
    
    @staticmethod
    def generate_api_key() -> str:
        """Generate secure API key"""
        return f"cerberus_{secrets.token_urlsafe(32)}"
    
    @staticmethod
    def hash_api_key(api_key: str) -> str:
        """Hash API key for storage"""
        return hashlib.sha256(api_key.encode()).hexdigest()
    
    @staticmethod
    def verify_api_key(api_key: str, api_key_hash: str) -> bool:
        """Verify API key"""
        return hmac.compare_digest(
            APIKeyManager.hash_api_key(api_key),
            api_key_hash
        )


# ============================================================================
# ENCRYPTION MANAGEMENT
# ============================================================================

class EncryptionManager:
    """Handles field-level encryption for sensitive database fields"""
    
    _fernet = Fernet(SecurityConfig.MFA_ENCRYPTION_KEY.encode())
    
    @classmethod
    def encrypt(cls, data: str) -> str:
        """Encrypt string data"""
        if not data:
            return None
        return cls._fernet.encrypt(data.encode()).decode()
    
    @classmethod
    def decrypt(cls, encrypted_data: str) -> str:
        """Decrypt string data"""
        if not encrypted_data:
            return None
        try:
            return cls._fernet.decrypt(encrypted_data.encode()).decode()
        except Exception as e:
            # If decryption fails (e.g. wrong key or plain data), log and handle
            # For now, we return None to indicate failure
            return None

# ============================================================================
# MFA MANAGEMENT
# ============================================================================

class MFAManager:
    """Multi-Factor Authentication management"""
    
    @staticmethod
    def setup_totp() -> MFASetup:
        """Setup TOTP (Google Authenticator compatible)"""
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp.provisioning_uri(name='Cerberus Pro'))
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buf = BytesIO()
        img.save(buf, format='PNG')
        qr_code_b64 = base64.b64encode(buf.getvalue()).decode()
        
        # Generate backup codes
        backup_codes = [secrets.token_hex(4) for _ in range(10)]
        
        return MFASetup(
            secret=EncryptionManager.encrypt(secret),
            qr_code=f"data:image/png;base64,{qr_code_b64}",
            backup_codes=backup_codes
        )
    
    @staticmethod
    def verify_totp(secret: str, code: str) -> bool:
        """Verify TOTP code"""
        # secret here is expected to be encrypted
        decrypted_secret = EncryptionManager.decrypt(secret)
        if not decrypted_secret:
            # Fallback for plain secrets during migration if necessary
            # For now, we assume it MUST be encrypted or it fails
            return False
            
        totp = pyotp.TOTP(decrypted_secret)
        # Allow for time drift (±1 window)
        return totp.verify(code, valid_window=1)
    
    @staticmethod
    def verify_backup_code(code: str, code_hash: str) -> bool:
        """Verify backup code"""
        return hmac.compare_digest(
            hashlib.sha256(code.encode()).hexdigest(),
            code_hash
        )


# ============================================================================
# ACCESS CONTROL
# ============================================================================

class AccessControl:
    """Role-Based & Attribute-Based Access Control"""
    
    @staticmethod
    def check_permission(user_role: Role, required_permission: Permission) -> bool:
        """Check if user role has permission (RBAC)"""
        return required_permission in ROLE_PERMISSIONS.get(user_role, set())
    
    @staticmethod
    def check_abac(
        user: JWTPayload,
        resource_type: str,
        action: str,
        resource_attributes: Dict = None,
        user_attributes: Dict = None
    ) -> bool:
        """Check access using Attribute-Based Access Control (ABAC)"""
        
        if resource_attributes is None:
            resource_attributes = {}
        if user_attributes is None:
            user_attributes = {}
        
        # Example ABAC rules
        rules = {
            'scan': {
                'create': lambda u, r: u.role in [Role.PENTESTER, Role.LEAD, Role.ADMIN, Role.SUPER_ADMIN],
                'modify': lambda u, r: u.role in [Role.LEAD, Role.ADMIN, Role.SUPER_ADMIN] or (u.sub == r.get('owner_id')),
                'delete': lambda u, r: u.role in [Role.ADMIN, Role.SUPER_ADMIN] or (u.sub == r.get('owner_id')),
            },
            'report': {
                'export': lambda u, r: u.role in [Role.PENTESTER, Role.LEAD, Role.ADMIN, Role.SUPER_ADMIN],
                'delete': lambda u, r: u.role in [Role.ADMIN, Role.SUPER_ADMIN],
            }
        }
        
        if resource_type not in rules or action not in rules[resource_type]:
            return False
        
        return rules[resource_type][action](user, resource_attributes)


# ============================================================================
# DEPENDENCY INJECTION FOR FASTAPI
# ============================================================================

security = HTTPBearer(auto_error=False)


class OAuth2PasswordBearerWithCookie(OAuth2):
    """OAuth2 helper that prefers HttpOnly cookie and falls back to Authorization header."""

    def __init__(self, token_url: str, auto_error: bool = True):
        flows = OAuthFlowsModel(password={"tokenUrl": token_url, "scopes": {}})
        super().__init__(flows=flows, auto_error=auto_error)
        self.auto_error = auto_error

    async def __call__(self, request: Request) -> Optional[str]:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.lower().startswith("bearer "):
            return auth_header.split(" ", 1)[1].strip()

        cookie_token = request.cookies.get("access_token")
        if cookie_token:
            return cookie_token

        if self.auto_error:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return None


oauth2_cookie_scheme = OAuth2PasswordBearerWithCookie(token_url="/auth/login", auto_error=False)

async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    cookie_or_bearer_token: Optional[str] = Depends(oauth2_cookie_scheme),
) -> JWTPayload:
    """FastAPI dependency to get current user from JWT (Cookie or Header)"""
    
    # SEC-001: Dev bypass REMOVED. All environments require valid JWT.
    # To develop locally, generate a real token via POST /auth/login.
        )
        
    token = None
    if cookie_or_bearer_token:
        token = cookie_or_bearer_token
    elif credentials:
        token = credentials.credentials
    elif "access_token" in request.cookies:
        token = request.cookies.get("access_token")
        
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
        
    return JWTManager.verify_token(token)

def require_permission(required_permission: Permission):
    """Dependency to require specific permission"""
    def permission_checker(user: JWTPayload = Depends(get_current_user)) -> JWTPayload:
        if not AccessControl.check_permission(Role(user.role), required_permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission required: {required_permission.value}"
            )
        return user
    return permission_checker

def require_role(*roles: Role):
    """Dependency to require specific role"""
    def role_checker(user: JWTPayload = Depends(get_current_user)) -> JWTPayload:
        if Role(user.role) not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role required: {', '.join([r.value for r in roles])}"
            )
        return user
    return role_checker

async def require_mfa(user: JWTPayload = Depends(get_current_user)) -> JWTPayload:
    """Dependency to require MFA for sensitive operations"""
    if user.role in [role.value for role in SecurityConfig.MFA_REQUIRED_FOR_ROLES]:
        # Check if MFA is enabled - implement actual check
        pass
    return user


# ============================================================================
# SECURITY DECORATORS
# ============================================================================

def require_https(func):
    """Decorator to require HTTPS"""
    @wraps(func)
    async def wrapper(request, *args, **kwargs):
        if request.url.scheme != "https" and not request.url.hostname == "localhost":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="HTTPS required"
            )
        return await func(request, *args, **kwargs)
    return wrapper

def audit_action(action: str, resource_type: str):
    """Decorator to audit user actions"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, user: JWTPayload, **kwargs):
            # Log audit
            # TODO: Implement audit logging
            result = await func(*args, user=user, **kwargs)
            return result
        return wrapper
    return decorator


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def mask_sensitive_data(data: str, show_chars: int = 4) -> str:
    """Mask sensitive data (password, token, etc)"""
    if len(data) <= show_chars:
        return "*" * len(data)
    return data[:show_chars] + "*" * (len(data) - show_chars)

def is_ip_whitelisted(ip: str, whitelist: List[str]) -> bool:
    """Check if IP is in whitelist"""
    return any(ip.startswith(prefix) for prefix in whitelist)

def get_request_fingerprint(request) -> str:
    """Generate request fingerprint for anomaly detection"""
    fingerprint_data = f"{request.client.host}{request.headers.get('user-agent', '')}"
    return hashlib.sha256(fingerprint_data.encode()).hexdigest()
