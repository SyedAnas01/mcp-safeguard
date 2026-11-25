import requests

def fetch_client_metadata(client_id: str) -> dict:
    resp = requests.get(client_id, timeout=5)
    resp.raise_for_status()
    return resp.json()

def load_jwks(jwks_uri):
    return requests.get(jwks_uri).json()
