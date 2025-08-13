import requests


def fetch_url(user_url: str) -> str:
    """Intentionally missing host/IP validation and disables redirect safety.
    SSRF-eval: requests.get(user_url, allow_redirects=True)
    """
    try:
        resp = requests.get(user_url, timeout=5, allow_redirects=True)
        return resp.text[:200]
    except Exception as e:
        return f"error: {e}"


if __name__ == "__main__":
    # Example dangerous inputs:
    # - http://169.254.169.254/latest/meta-data/
    # - http://127.0.0.1:8080/admin
    # - file:///etc/passwd
    print(fetch_url(input("URL: ")))


