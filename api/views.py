from django.shortcuts import get_object_or_404, render
from django.http import HttpResponse, HttpResponseRedirect
from django.http.response import JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie

from observes.models import Hash, Scan

@ensure_csrf_cookie
def index(request):
    return JsonResponse(
        {
            "info" : f"there are # {len(Hash.objects.all())} Hashes"
        }
    )

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


def scan_results(request, scan_id):
    s = get_object_or_404(Scan, pk=scan_id)
    avc = s.avclass_result_of_scan.all()[0]
    res = {
        "id":s.id,
        "sha256":s.sha256.sha256,
        "rescan_date":s.scan_date,
        "engines":s.engines,
        "detections": s.detections,
        "avc_results": avc.result
    }
    return JsonResponse(res, safe=False)




# Create your views here.
