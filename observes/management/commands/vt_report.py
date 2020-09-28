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
import os

from ...models import Hash, Scan, AvclassResult


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

            r = requests.post(
                f'https://www.virustotal.com/vtapi/v2/file/report?apikey={env("VT_API_KEY")}&resource={h.sha256}&allinfo=true'
            )
            status_code = r.status_code
            if status_code == 200:
                js = r.json()
                engines = js["total"]
                detections = js["positives"]
                scan_date = parse_datetime(js["scan_date"])
                filename = os.path.abspath(os.path.dirname(__name__)) + '/savings/' + h.sha256 + '/log_' + now().strftime('%Y%m%d_%H%M%S') + '.json'
                path = default_storage.save(
                    filename,  ContentFile(json.dumps(js).encode('utf-8'))
                )
                s = Scan(
                    scan_date=scan_date,
                    detections=detections,
                    engines=engines,
                    json_url=path,
                    report=js,
                    status=str(status_code),
                    sha256=h
                )
            else:
                s = Scan(
                    status=str(status_code),
                    sha256=h
                )
            s.save()

            time.sleep(5)
