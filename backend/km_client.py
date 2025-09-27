# backend/km_client.py
import requests
import os
import base64

KM_BASE = os.environ.get("KM_API_URL", "http://127.0.0.1:5000/api")
KM_TOKEN = os.environ.get("KM_API_TOKEN", "demo-token")

class KMClient:
    def __init__(self, base_url=None, token=None):
        self.base_url = base_url or KM_BASE
        self.token = token or KM_TOKEN
        self.headers = {"Authorization": f"Bearer {self.token}"}
    
    def get_quantum_key(self, user_email: str, key_length: int = 32) -> bytes:
        """
        Get quantum key for user from KM server.
        Returns key as bytes or None if failed.
        """
        try:
            url = f"{self.base_url}/keys"
            payload = {"user": user_email, "key_length": key_length}
            r = requests.post(url, json=payload, headers=self.headers, timeout=10)
            r.raise_for_status()
            
            response_data = r.json()
            key_b64 = response_data.get("quantum_key")
            if key_b64:
                return base64.b64decode(key_b64)
            return None
        except Exception as e:
            print(f"Error getting quantum key: {e}")
            return None
    
    def fetch_keys(self, owner: str, num_bytes: int = 1024):
        """
        Fetch quantum keys for `owner` from KM simulator.
        Returns JSON with keys or raises.
        """
        url = f"{self.base_url}/keys/fetch"
        payload = {"owner": owner, "num_bytes": num_bytes}
        r = requests.post(url, json=payload, headers=self.headers, timeout=10)
        r.raise_for_status()
        return r.json()

    def list_keys(self, owner: str):
        """
        List available keys for owner.
        """
        url = f"{self.base_url}/keys"
        r = requests.get(url, params={"owner": owner}, headers=self.headers, timeout=10)
        r.raise_for_status()
        return r.json()

# Keep standalone functions for backward compatibility
def fetch_keys(owner: str, num_bytes: int = 1024):
    """
    Fetch quantum keys for `owner` from KM simulator.
    Returns JSON with keys or raises.
    """
    url = f"{KM_BASE}/keys/fetch"
    payload = {"owner": owner, "num_bytes": num_bytes}
    headers = {"Authorization": f"Bearer {KM_TOKEN}"}
    r = requests.post(url, json=payload, headers=headers, timeout=10)
    r.raise_for_status()
    return r.json()

def list_keys(owner: str):
    url = f"{KM_BASE}/keys"
    headers = {"Authorization": f"Bearer {KM_TOKEN}"}
    r = requests.get(url, params={"owner": owner}, headers=headers, timeout=10)
    r.raise_for_status()
    return r.json()
