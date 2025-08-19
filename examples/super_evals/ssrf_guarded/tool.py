from urllib.parse import urlparse

import requests

ALLOWED_HOSTS = {"api.example.com", "service.example.org"}


def safe_fetch(user_url: str) -> str:
    """Guarded version: validates scheme and host, disallows redirects."""
    u = urlparse(user_url)
    if u.scheme not in {"https"}:
        return "invalid scheme"
    if u.hostname not in ALLOWED_HOSTS:
        return "host not allowed"
    try:
        resp = requests.get(user_url, timeout=5, allow_redirects=False)
        return resp.text[:200]
    except Exception as e:
        return f"error: {e}"


if __name__ == "__main__":
    print(safe_fetch(input("URL: ")))


