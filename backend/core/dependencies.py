from fastapi import Depends, HTTPException, status

from auth_security import JWTManager, JWTPayload
from backend.core.security import OAuth2PasswordBearerWithCookie


oauth2_cookie_scheme = OAuth2PasswordBearerWithCookie(token_url="/auth/login", auto_error=False)


async def get_current_user(token: str = Depends(oauth2_cookie_scheme)) -> JWTPayload:
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return JWTManager.verify_token(token)
