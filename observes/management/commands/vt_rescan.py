from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.core.management.base import BaseCommand
from django.utils.dateparse import parse_datetime
from django.utils.timezone import now
from django.db.models import Avg, Max, Min, Sum

import environ
import json
import requests
import time

from ...models import Hash, Scan, ReAnalyze


# BaseCommandを継承して作成
class Command(BaseCommand):
    # python manage.py help count_entryで表示されるメッセージ
    help = 'get a report of registered hashes from VT'
    
    def handle(self, *args, **kwargs):
        env = environ.Env()
        for h in Hash.objects.all():
            print(h.sha256)

            # obserbing for 2 weeks
            if len(h.detection_of_hash.all())>0:
                first = h.detection_of_hash.all().aggregate(Min('scan_date'))['scan_date__min']
                last = h.detection_of_hash.all().aggregate(Max('scan_date'))['scan_date__max']
                if (last-first).days > 13:
                    continue
            
            headers = {
                "x-apikey": env("VT_API_KEY")
            }
            response = requests.post(
                f'https://www.virustotal.com/api/v3/files/{h.sha256}/analyse', headers=headers)
            
            r = ReAnalyze(
                status=str(response.status_code),
                sha256=h
            )
            r.save()

            print(response.status_code)
            time.sleep(5)
