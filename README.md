# BrownRook Identity & Control Plane (IDC)

## Overview

BrownRook IDC is the identity-aware control plane for BrownRook-hosted services.

It provides:

- OIDC-based authentication
- JWT validation and claim enforcement
- Secure API exposure behind reverse proxy
- Zero-trust service architecture foundation

This repository contains the Phase 1 implementation.

---

## Architecture (Phase 1)

Internet  
↓  
Route53 DNS  
↓  
Reverse Proxy (TLS termination)  
↓  
IDC API (JWT validation)

Trust model:

Trust = f(Identity, Token, Policy)

A request is accepted only if:

- JWT signature is valid
- Issuer is trusted
- Audience matches expected value
- Token is not expired

---

## Repository Structure

app/        → Application code (FastAPI service)  
infra/      → Deployment artifacts (proxy config, docker, etc.)  
docs/       → Architecture and security documentation  

---

## Local Development

### Requirements
- Python 3.11+
- pip
- virtualenv (recommended)

### Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt/

### Configuration

TENANT_ID=8b07f4bd-41e4-4106-8d49-00c5d79d35a2
CLIENT_ID=6d299c31-0dbe-4484-a18f-220d13558f3d

OIDC_ISSUER=https://login.microsoftonline.com/8b07f4bd-41e4-4106-8d49-00c5d79d35a2/v2.0
OIDC_JWKS_URL=https://login.microsoftonline.com/8b07f4bd-41e4-4106-8d49-00c5d79d35a2/discovery/v2.0/keys
OIDC_AUDIENCE=6d299c31-0dbe-4484-a18f-220d13558f3d

# Optional debugging
DEBUGPY=1
DEBUGPY_WAIT=0

---

## Running the API

From repository root:

```bash
source .venv/bin/activate
python -m uvicorn app.main:app --host 127.0.0.1 --port 8080

## Healtch Check
curl http://127.0.0.1:8080/health

## Acquire a token
export TOKEN="$(az account get-access-token \
  --scope api://6d299c31-0dbe-4484-a18f-220d13558f3d/.default \
  --query accessToken -o tsv)"

# Inspect

python - <<'PY'
import os, jwt
p = jwt.decode(os.environ["TOKEN"], options={"verify_signature": False})
print("ver:", p.get("ver"))
print("iss:", p.get("iss"))
print("aud:", p.get("aud"))
print("scp:", p.get("scp"))
PY

Expected:
	•	ver: 2.0
	•	iss: https://login.microsoftonline.com//v2.0
	•	aud: <CLIENT_ID>

## Call a Protected Endpoint

curl -i \
  -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8080/secure

Response meanings:
	•	200 → Token valid
	•	401 → Token invalid or unauthorized
	•	500 → Configuration or runtime error
    
