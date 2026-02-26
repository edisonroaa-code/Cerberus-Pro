from typing import Optional

from fastapi import HTTPException, Request, status
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from fastapi.security import OAuth2


class OAuth2PasswordBearerWithCookie(OAuth2):
    """Reads bearer token from HttpOnly cookie first, header second."""

    def __init__(self, token_url: str, auto_error: bool = True):
        flows = OAuthFlowsModel(password={"tokenUrl": token_url, "scopes": {}})
        super().__init__(flows=flows, auto_error=auto_error)
        self.auto_error = auto_error

    async def __call__(self, request: Request) -> Optional[str]:
        cookie_token = request.cookies.get("access_token")
        if cookie_token:
            return cookie_token

        auth = request.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            return auth.split(" ", 1)[1].strip()

        if self.auto_error:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return None
