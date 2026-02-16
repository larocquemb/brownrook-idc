import os
from dotenv import load_dotenv
from typing import Any, Dict
import requests
from cachetools import TTLCache
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import jwt, JWTError

load_dotenv()
app = FastAPI(title="BrownRook IDC", version="0.2.0")
security = HTTPBearer()

# Optional debugpy logging for the debuggee process.
_debugpy_log_dir = os.getenv("DEBUGPY_LOG_DIR")
if _debugpy_log_dir:
    try:
        import debugpy

        debugpy.log_to(_debugpy_log_dir)
    except Exception:
        # Don't let logging setup break app startup.
        pass

# Debug hard stop (opt-in). Set DEBUGPY_WAIT=1 before launch.
if os.getenv("DEBUGPY_WAIT") == "1":
    import debugpy

    if not debugpy.is_client_connected():
        try:
            debugpy.listen(("127.0.0.1", 5678))
        except RuntimeError:
            # Already listening/connected via launcher.
            pass
        debugpy.wait_for_client()
    debugpy.breakpoint()

# ===== ConfiÙg (env-driven) =====
OIDC_ISSUER = os.getenv("OIDC_ISSUER", "").rstrip("/")
OIDC_AUDIENCE = os.getenv("OIDC_AUDIENCE", "")
OIDC_JWKS_URL = os.getenv("OIDC_JWKS_URL", "")

if not (OIDC_ISSUER and OIDC_AUDIENCE and OIDC_JWKS_URL):
    # Don’t crash import-time; fail securely on /secure with clear message.
    CONFIG_OK = False
else:
    CONFIG_OK = True

# Cache JWKS for 10 minutes to reduce latency and avoid rate limits
_jwks_cache: TTLCache = TTLCache(maxsize=2, ttl=600)


def _get_jwks() -> Dict[str, Any]:
    cached = _jwks_cache.get("jwks")
    if cached:
        return cached

    r = requests.get(OIDC_JWKS_URL, timeout=5)
    r.raise_for_status()
    jwks = r.json()
    _jwks_cache["jwks"] = jwks
    return jwks


def _verify_token(token: str) -> Dict[str, Any]:
    if not CONFIG_OK:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="OIDC not configured (set OIDC_ISSUER, OIDC_AUDIENCE, OIDC_JWKS_URL)",
        )

    try:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        if not kid:
            raise HTTPException(status_code=401, detail="Missing kid in token header")

        jwks = _get_jwks()
        keys = jwks.get("keys", [])
        key = next((k for k in keys if k.get("kid") == kid), None)
        if not key:
            # Key rotation case: refresh once
            _jwks_cache.pop("jwks", None)
            jwks = _get_jwks()
            keys = jwks.get("keys", [])
            key = next((k for k in keys if k.get("kid") == kid), None)
            if not key:
                raise HTTPException(status_code=401, detail="Unknown kid (no matching JWKS key)")

        claims = jwt.decode(
            token,
            key,
            algorithms=[header.get("alg", "RS256")],
            audience=OIDC_AUDIENCE,
            options={
                "verify_aud": True,
                "verify_iss": False,   # we verify manually (normalize /)
                "verify_exp": True,
            },
        )

        # Manual issuer check (handles trailing slash differences)
        token_iss = (claims.get("iss") or "").rstrip("/")
        expected_iss = OIDC_ISSUER.rstrip("/")
        if token_iss != expected_iss:
            raise HTTPException(status_code=401, detail="Issuer mismatch")
        return claims

    except HTTPException:
        raise
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except requests.RequestException:
        raise HTTPException(status_code=503, detail="JWKS fetch failed")


@app.get("/health")
def health():
    return {"status": "ok", "oidc_configured": CONFIG_OK}


@app.get("/secure")
def secure(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    claims = _verify_token(token)
    return {"claims": claims}


@app.on_event("startup")
async def startup():
    x = 1  # breakpoint here to verify debugger is working
