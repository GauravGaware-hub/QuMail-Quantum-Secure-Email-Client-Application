# backend/km_client.py
import requests
import os

KM_BASE = os.environ.get("KM_API_URL", "http://127.0.0.1:5000/api")
KM_TOKEN = os.environ.get("KM_API_TOKEN", "demo-token")
HEADERS = {"Authorization": f"Bearer {KM_TOKEN}"}

def fetch_keys(owner: str, num_bytes: int = 1024):
    """
    Fetch quantum keys for `owner` from KM simulator.
    Returns JSON with keys or raises.
    """
    url = f"{KM_BASE}/keys/fetch"
    payload = {"owner": owner, "num_bytes": num_bytes}
    r = requests.post(url, json=payload, headers=HEADERS, timeout=10)
    r.raise_for_status()
    return r.json()

def list_keys(owner: str):
    url = f"{KM_BASE}/keys"
    r = requests.get(url, params={"owner": owner}, headers=HEADERS, timeout=10)
    r.raise_for_status()
    return r.json()
