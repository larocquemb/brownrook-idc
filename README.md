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