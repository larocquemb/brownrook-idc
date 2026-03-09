# Azure CLI login + token (for local testing with Conditional Access):
#    az login --allow-no-subscriptions
#   az account get-access-token \
#     --scope api://6d299c31-0dbe-4484-a18f-220d13558f3d/.default \
#     --query accessToken -o tsv
#   export TOKEN="$(az account get-access-token \
#     --scope api://6d299c31-0dbe-4484-a18f-220d13558f3d/.default \
#     --query accessToken -o tsv)"
#   curl -i -H "Authorization: Bearer $TOKEN" http://localhost:8080/secure

# Development run examples
#
# Run with uvicorn directly:
#   python -m uvicorn brownrook_idc.main:app --host 127.0.0.1 --port 8080
#   uvicorn brownrook_idc.main:app --host 127.0.0.1 --port 8080
#   uvicorn brownrook_idc.main:app --reload --host 127.0.0.1 --port 8080
#
# Run with debugger support:
#   DEBUGPY=1 python -m uvicorn brownrook_idc.main:app --host 127.0.0.1 --port 8080
#
# Run using the installed CLI entrypoint:
#   brownrook-idc
#
# Install project dependencies (editable install for development):
#   python -m venv .venv
#   source .venv/bin/activate
#   pip install -e .
#
# Install development dependencies:
#   pip install -e ".[dev]"

import json
import logging
import os
import time
from pprint import pformat
from typing import Any, Dict
import requests
from datetime import timezone, datetime
from cachetools import TTLCache
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import uvicorn
import jwt
from jwt import PyJWKClient
from jwt import InvalidTokenError
import urllib.error

def required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value

# ===== Config (env-driven) =====
logger = logging.getLogger("idc.auth")
load_dotenv()
APP_VERSION = os.getenv("APP_VERSION", "unknown")
GIT_COMMIT = os.getenv("GIT_COMMIT", "unknown")
BUILD_NUMBER = os.getenv("BUILD_NUMBER", "unknown")
IMAGE_REF = os.getenv("IMAGE_REF", "unknown")
POD_NAME = os.getenv("HOSTNAME", "unknown")
DEPLOYMENT_PROFILE = os.getenv("DEPLOYMENT_PROFILE", "unknown")
CLUSTER_NAME = os.getenv("CLUSTER_NAME", "unknown")
KUBERNETES_VERSION = os.getenv("KUBERNETES_VERSION", "unknown")
NODE_NAME = os.getenv("NODE_NAME", "unknown")
NODE_OS = os.getenv("NODE_OS", "unknown")
INFRA_COMMIT = os.getenv("INFRA_COMMIT", "unknown")
TENANT_ID = required_env("TENANT_ID")
OIDC_ISSUER = os.getenv(
    "OIDC_ISSUER",
    f"https://login.microsoftonline.com/{TENANT_ID}/v2.0",
).rstrip("/")
OIDC_JWKS_URL = os.getenv(
    "OIDC_JWKS_URL",
    f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys",
)
OIDC_AUDIENCE = os.getenv("OIDC_AUDIENCE", required_env("CLIENT_ID"))
OIDC_SCOPE = os.getenv("OIDC_SCOPE", "")

app = FastAPI(title="BrownRook IDC", version=APP_VERSION)
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

if os.getenv("DEBUGPY") == "1":
    import debugpy
    debugpy.listen(("127.0.0.1", 5678))
    print("✅ debugpy listening on 127.0.0.1:5678")
    # DON'T call wait_for_client() unless you want it to pause here

# Optional: wait for debugger to attach before serving requests.
if os.getenv("DEBUGPY_WAIT") == "1":
    try:
        import debugpy
        debugpy.wait_for_client()
    except Exception:
        # Don't let debugger setup break app startup.
        pass






if not (OIDC_ISSUER and OIDC_AUDIENCE and OIDC_JWKS_URL):
    # Don't crash import-time; fail securely on /secure with clear message.
    CONFIG_OK = False
else:
    CONFIG_OK = True

# Cache JWKS for 10 minutes to reduce latency and avoid rate limits
ALLOWED_ALGS = ["RS256"]
_jwks_cache: TTLCache = TTLCache(maxsize=2, ttl=600)
_jwk_client = PyJWKClient(OIDC_JWKS_URL)

def _unauthorized(detail: str, request_id: str | None = None) -> HTTPException:
    headers = {"WWW-Authenticate": "Bearer"}
    if request_id:
        headers["X-Request-ID"] = request_id
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers=headers,
    )

def _verify_token(token: str, request_id: str | None = None) -> dict:
    if not CONFIG_OK:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="OIDC not configured",
        )

    expected_iss = (OIDC_ISSUER or "").rstrip("/")
    expected_aud = OIDC_AUDIENCE

    try:
        signing_key = _jwk_client.get_signing_key_from_jwt(token)

        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=ALLOWED_ALGS,
            audience=expected_aud,
            issuer=expected_iss,
            leeway=60,
            options={
                "require": ["exp", "iss", "aud"],
                "verify_signature": True,
                "verify_exp": True,
                "verify_aud": True,
                "verify_iss": True,
            },
        )

        return claims

    # ---- JWKS / network errors → 503 ----
    except jwt.exceptions.PyJWKClientConnectionError as e:
        logger.error("JWKS fetch failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="JWKS fetch failed",
        )
    except urllib.error.URLError as e:
        logger.error("JWKS network error: %s", e)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="JWKS fetch failed",
        )

    # ---- Token validation errors → 401 ----
    except jwt.ExpiredSignatureError:
        logger.info("Token expired (request_id=%s)", request_id)
        raise _unauthorized("Token expired", request_id)

    except jwt.InvalidIssuerError:
        logger.info("Invalid issuer (request_id=%s)", request_id)
        raise _unauthorized("Invalid issuer", request_id)

    except jwt.InvalidAudienceError:
        logger.info("Invalid audience (request_id=%s)", request_id)
        raise _unauthorized("Invalid audience", request_id)

    except jwt.ImmatureSignatureError:
        logger.info("Token not yet valid (request_id=%s)", request_id)
        raise _unauthorized("Token not yet valid", request_id)

    except jwt.InvalidSignatureError:
        logger.info("Invalid signature (request_id=%s)", request_id)
        raise _unauthorized("Invalid token signature", request_id)

    except InvalidTokenError as e:
        logger.info("Invalid token (request_id=%s): %s", request_id, e)
        raise _unauthorized("Invalid token", request_id)

    except Exception as e:
        # Catch absolutely everything else to prevent 500 auth leaks
        logger.exception("Unexpected auth error (request_id=%s)", request_id)
        raise _unauthorized("Authentication failed", request_id)

@app.get("/")
def root() -> dict[str, str]:
    return {"message": "brownrook-idc is running"}

@app.get("/health")
def health():
    return {
        "status": "ok",
        "oidc_configured": CONFIG_OK,
    }

@app.get("/info")
def info():
    return {
        "time": datetime.now(timezone.utc).isoformat(),
        "version": APP_VERSION,
        "commit": GIT_COMMIT,
        "build": BUILD_NUMBER,
        "image": IMAGE_REF,
        "deployment_profile": DEPLOYMENT_PROFILE,
        "cluster": CLUSTER_NAME,
        "kubernetes_version": KUBERNETES_VERSION,
        "pod": POD_NAME
    }

@app.get("/version")
def version():
    return {
        "version": APP_VERSION,
        "commit": GIT_COMMIT,
        "build": BUILD_NUMBER,
        "image": IMAGE_REF,
    }
@app.get("/info")

def info():
    return {
        "version": APP_VERSION,
        "infra_commit": INFRA_COMMIT,
        "build": BUILD_NUMBER,
        "image": IMAGE_REF,
        "deployment_profile": DEPLOYMENT_PROFILE,
        "cluster": CLUSTER_NAME,
        "kubernetes_version": KUBERNETES_VERSION,
        "pod": POD_NAME,
    }


@app.get("/secure")
def secure(request: Request, credentials: HTTPAuthorizationCredentials = Depends(security)):
    request_id = request.headers.get("X-Request-ID")
    token = credentials.credentials
    claims = _verify_token(token, request_id)
    print("Token claims:\n" + pformat(claims, sort_dicts=True))
    now = int(time.time())
    exp = int(claims.get("exp", 0))
    expires_in = max(0, exp - now) if exp else None
    if expires_in is not None:
        print(f"Token expires in {expires_in} seconds")
    token_iss = (claims.get("iss") or "").rstrip("/")
    scp = claims.get("scp", "")
    scopes = scp.split() if isinstance(scp, str) else []
    expected_scope = OIDC_SCOPE.strip()
    # Response fields:
    # - claims: full JWT claims after verification.
    # - expires_in_seconds: seconds until token expiry (based on exp claim).
    # - token_checks: quick validation summary for aud/iss/scp.
    #   - aud_ok: token audience matches OIDC_AUDIENCE.
    #   - iss_ok: token issuer matches OIDC_ISSUER (normalized).
    #   - scp_ok: required scope present (or any scope if OIDC_SCOPE is unset).
    #   - aud/iss/scp: actual values from the token.
    #   - expected_*: values the API expects.
    body = {
        "claims": claims,
        "expires_in_seconds": expires_in,
        "token_checks": {
            "aud_ok": claims.get("aud") == OIDC_AUDIENCE,
            "iss_ok": token_iss == OIDC_ISSUER.rstrip("/"),
            "scp_ok": (expected_scope in scopes) if expected_scope else bool(scopes),
            "aud": claims.get("aud"),
            "iss": claims.get("iss"),
            "scp": scp,
            "expected_aud": OIDC_AUDIENCE,
            "expected_iss": OIDC_ISSUER,
            "expected_scp": expected_scope or None,
        },
    }
    return Response(
        content=json.dumps(body, indent=2, sort_keys=True),
        media_type="application/json",
    )

def main() -> None:
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8080"))
    uvicorn.run("brownrook_idc.main:app", host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
