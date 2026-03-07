# tests/test_health.py

from fastapi.testclient import TestClient
from brownrook_idc.main import app
import brownrook_idc.main as main_module

client = TestClient(app)

def test_health():
    r = client.get("/health")
    assert r.status_code == 200

def test_secure_requires_token():
    r = client.get("/secure")
    assert r.status_code == 401

def test_secure_with_token(monkeypatch):
    def fake_verify_token(*args, **kwargs):
        return {
            "sub": "test-user",
            "aud": "6d299c31-0dbe-4484-a18f-220d13558f3d",
            "iss": "https://login.microsoftonline.com/test/v2.0",
        }

    monkeypatch.setattr(main_module, "_verify_token", fake_verify_token)

    r = client.get(
        "/secure",
        headers={"Authorization": "Bearer fake-token"},
    )

    assert r.status_code == 200