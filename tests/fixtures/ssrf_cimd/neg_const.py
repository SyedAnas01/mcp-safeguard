import requests

def ping():
    return requests.get("https://example.com/status").status_code
