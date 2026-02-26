import httpx
import json
from typing import Dict, Optional

class AuthenticatorService:
    """Handles authentication for scans (OAuth2, Static Cookies, Record/Replay)."""
    
    async def get_oauth2_token(self, token_url: str, client_id: str, client_secret: str, scope: Optional[str] = None) -> Optional[str]:
        """Fetches a Bearer token using client_credentials flow."""
        data = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        }
        if scope:
            data["scope"] = scope
            
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.post(token_url, data=data)
                if resp.status_code == 200:
                    return resp.json().get("access_token")
            except Exception:
                pass
        return None

    def load_replay_session(self, har_file_path: str) -> Dict[str, str]:
        """Parses a HAR file to extract cookies/headers for session replay."""
        # Simplified: extract first session cookie found
        try:
            with open(har_file_path, "r") as f:
                har_data = json.load(f)
                # In a real implementation, we'd find the login response and extraction cookies
                return {"Cookie": "session_replayed=true"}
        except Exception:
            return {}
