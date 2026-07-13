import subprocess


def git_status():
    return subprocess.run(["git", "status", "--short"], check=False)
