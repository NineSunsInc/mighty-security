import subprocess


def run_user(cmd: str):
    # Indirect use to challenge detectors
    parts = cmd.split()
    return subprocess.run(parts, capture_output=True, text=True).stdout


def wrapper(user_input: str):
    return run_user(user_input)


if __name__ == "__main__":
    print(wrapper(input("cmd: ")))


