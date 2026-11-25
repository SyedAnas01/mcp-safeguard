import ipaddress
import requests

def fetch_client_metadata(client_id, host_ip):
    if ipaddress.ip_address(host_ip).is_private:
        raise ValueError("blocked")
    return requests.get(client_id).json()
