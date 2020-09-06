from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.core.management.base import BaseCommand
from django.utils.dateparse import parse_datetime
from django.utils.timezone import now

import environ
import json
import re
import requests
from requests_oauthlib import OAuth1Session
import time

from ...models import Hash, Scan



# BaseCommandを継承して作成
class Command(BaseCommand):
    def handle(self, *args, **kwargs):
        env = environ.Env()

        # Twitter
        query_str = '"low detected" OR "not much detected" -filter:retweets'
        twitter = OAuth1Session(env("CK"), env("CS"), env("AT"), env("AS"))
        params = {
            "q": query_str,
            "result_type": "recent",
            "count": 100
        }
        twitter_search_url = 'https://api.twitter.com/1.1/search/tweets.json'
        req = twitter.get(twitter_search_url, params=params)

        if req.status_code == 200:
            tweets = json.loads(req.text)['statuses']
    #         print(tweets)
        else:
            return
        
        patternsha256 = re.compile(r'\s([0-9a-f]{64})\s')
        sha256 = [re.findall(patternsha256, t['text'])[0]
                  for t in tweets if re.findall(patternsha256, t["text"])]

        for hs in sha256:
            h = Hash(sha256=hs, name="from twitter", observing=True)
            h.save()
        
        # URLHaus:

        req = requests.get("https://urlhaus-api.abuse.ch/v1/payloads/recent/")

        if req.status_code == 200:
            payloads = req.json()
        else:
            return
        total = 0
        for p in payloads['payloads']:
            if p['virustotal']:
                detection = int(
                    re.match(r'(\d+)[\s]+\/', p['virustotal']['result']).group(1))
                if detection <= 5:
                    h = Hash(sha256=p["sha256_hash"], name="from URLHaus", observing=True)
                    h.save()


