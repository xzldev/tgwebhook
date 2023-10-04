import asyncio
import base64
import hashlib
import hmac
import json
import time
import urllib.parse
import urllib.parse

import requests
from django.http import HttpResponse

from .bot import bot_tele


def msg(text):
    webhook = "https://oapi.dingtalk.com/robot/send?access_token=41efe33d924a0a9008b438c5982751890ec76121edd33d1806529cf6e9093a5e"
    secret = "SEC04685db414a20ffd338b1d61843f0033f043dd3168d61420ff00bab08677eee3"
    timestamp = str(round(time.time() * 1000))
    secret_enc = secret.encode('utf-8')
    string_to_sign = '{}\n{}'.format(timestamp, secret)
    string_to_sign_enc = string_to_sign.encode('utf-8')
    hmac_code = hmac.new(secret_enc, string_to_sign_enc, digestmod=hashlib.sha256).digest()
    sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
    webhook = "{}&timestamp={}&sign={}".format(webhook, timestamp, sign)
    header = {
        "Content-Type": "application/json",
        "Charset": "UTF-8"
    }
    message ={
        "msgtype": "text",
        "text": {
            "content": text
        }
    }
    message_json = json.dumps(message)
    info = requests.post(url=webhook, data=message_json, headers=header)

def index(request):
    if request.method == 'POST':
        data = request.body
        res = json.loads(data.decode('utf-8'))
        print(res)
        msg("webhook:"+data.decode('utf-8'))
        asyncio.run(bot_tele(res))
        return HttpResponse("ok")
    else:
        return HttpResponse("hello world!")