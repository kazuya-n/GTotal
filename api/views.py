from django.shortcuts import get_object_or_404, render
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseBadRequest
from django.http.response import JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie, csrf_exempt
from django.views.decorators.http import require_http_methods

import json
import re
from observes.models import Hash, Scan


@csrf_exempt
def index(request):
    return JsonResponse(
        {
            "hashes" : Hash.objects.count(),
            "scans": Scan.objects.count()
        }
    )


@csrf_exempt
@require_http_methods(['POST'])
def register(request):
    js = json.loads(request.body)
    print(js)
    if not 'sha256' in js:
        return JsonResponse({'error': 'Bad Request : no sha256 field (400)'}, status=400)
    sha256 = js["sha256"]
    if not re.match(r'[A-Fa-f0-9]{64}', sha256):
        return JsonResponse({'error': 'Bad Request: not match sha256(400)'}, status=400)
    h = Hash(sha256)
    if "name" in js:
        h.name=js['name']
    h.observing=True
    h.save()

    return JsonResponse({'registered':sha256}, status=200)


@csrf_exempt
def list_hash(request):
    hashes = Hash.objects.all()
    res = []
    for h in hashes:
        res.append(
            {
                "hash":h.sha256,
                "date":str(h.create_date)
            }
        )
    return JsonResponse(res, safe=False)


@csrf_exempt
def list_scans(request, sha256):
    sha256 = get_object_or_404(Hash, pk=sha256)
    scans = sha256.detection_of_hash.all()
    res = []
    for s in scans:
        res.append(
            {
                "id":s.id,
                "rescan_date":s.scan_date,
            }
        )
    return JsonResponse(res, safe=False)


@csrf_exempt
def scan_results(request, scan_id):
    s = get_object_or_404(Scan, pk=scan_id)
    avc = s.avclass_result_of_scan.all()[0]
    res = {
        "id":s.id,
        "sha256":s.sha256.sha256,
        "rescan_date":s.scan_date,
        "engines":s.engines,
        "detections": s.detections,
        "raw_results":s.report,
        "avc_results": avc.result
    }
    return JsonResponse(res, safe=False)


@csrf_exempt
def aggregation(request, sha256):   
    hash = get_object_or_404(Hash, pk=sha256)
    avclass = hash.avclass_results_of_hash.values_list('result', flat=True)
    max_avc = get_max_detection(list(avclass))
    return JsonResponse(max_avc, safe=False)


def get_max_detection(reps):
    count = {
        "FILE": {},
        "FAM": {},
        "BEH": {},
        "CLASS": {},
        "UNK": {}
    }
    for ex_rep in reps:
        for k, v in ex_rep.items():
            dets = [v2["name"] for v2 in v]
            temp = [len(dets["av"]) for dets in v]
            max_det = dets[temp.index(max(temp))]
            if max_det in count[k].keys():
                count[k][max_det] += max(temp)
            else:
                count[k][max_det] = max(temp)
        #     print([fam, file, beh, clas, unk])
    fam = max(count["FAM"].items(), key=lambda x: x[1], default=None)
    fil = max(count["FILE"].items(), key=lambda x: x[1], default=None)
    beh = max(count["BEH"].items(), key=lambda x: x[1], default=None)
    clas = max(count["CLASS"].items(), key=lambda x: x[1], default=None)
    unk = max(count["UNK"].items(), key=lambda x: x[1], default=None)
    return fam, fil, beh, clas, unk


# Create your views here.
