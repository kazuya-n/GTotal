import base64
import io
import json
from statistics import mean

import matplotlib
from dateutil.relativedelta import relativedelta
from django.core import serializers
from django.core.paginator import Paginator
from django.db.models import Count
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.template import loader
from django.urls import reverse
from django.utils import timezone

matplotlib.use('Agg')
import re
import urllib

import matplotlib.pyplot as plt
import numpy as np
import wordcloud

from .forms import HashForm
from .models import Hash, RawReportEntropies, Scan

form = HashForm()

def dashboard(request):
    all_hash_count = Hash.objects.all().count()
    all_scan_count = Scan.objects.all().count()

    today = timezone.now()
    anweekago = today + relativedelta(weeks=-2)

    week_hashes = Hash.objects.filter(create_date__range=[anweekago, today])
    week_results = Scan.objects.filter(create_date__range=[anweekago, today])
    week_avc_rank = week_results.values('avclass_result_of_scan__family').annotate(
        count=Count('sha256')).order_by('-count')[0:10]

    week_hashes_count = week_hashes.extra({'date': 'date(create_date)'}).values(
        'date').annotate(count=Count('sha256'))
    week_results_count = week_results.extra({'date': 'date("create_date")'}).values(
        'date').annotate(count=Count('sha256'))

    template = loader.get_template('observes/dashboard.html')
    context = {
        'form': form,
        'total_hash': all_hash_count,
        'total_scan': all_scan_count,
        'avc_rank' : week_avc_rank,
        'week_hash': week_hashes_count,
        'week_scan': week_results_count
    }
    return HttpResponse(template.render(context, request))

def index(request):
    all_hash_list = Hash.objects.all()
    template = loader.get_template('observes/index.html')
    paginator = Paginator(all_hash_list, 10)
    p = request.GET.get('p')
    p_hash_list = paginator.get_page(p)
    family = [h.avclass_results_of_hash.values('family').annotate(count=Count('family')).order_by('-count').first() for h in p_hash_list]
    context = {
        'latest_hash_list': p_hash_list, 'form':form, 'total':len(all_hash_list), 'family':family
    }
    return HttpResponse(template.render(context, request))

def detail(request, sha256):
    hash = get_object_or_404(Hash, pk=sha256)
    scans = hash.detection_of_hash.all()
    avclass = hash.avclass_results_of_hash.values_list('result', flat=True)
    max_avc = get_max_detection(list(avclass))
    label = [s.scan_date.isoformat() for s in scans]
    dets = [s.detections for s in scans]
    engs = [s.engines for s in scans]
    tokens = []
    entropies = []
    watched = []
    for scan in scans:
        reports = scan.report
        engines = reports["scans"].keys()
        for e in engines:
            if reports["scans"][e]["detected"]:
                res = reports["scans"][e]["result"]
                tokens += re.split("[\.\s\/]",res.rstrip())
                if (e, res) in watched:
                    continue
                raw_ent = RawReportEntropies.objects.filter(engine=e, report=res, entropy__lte = 0.5).first()
                if raw_ent:
                    entropies.append(
                        {
                            'engine':e,
                            'report':res,
                            'entropy':raw_ent.entropy,
                            'vc': json.loads(raw_ent.valuecounts)
                        }
                    )
                watched.append((e, res))
    entropies = sorted(entropies, key=lambda k: k['entropy'])[:10]
    if tokens:
        wc = wordcloud.WordCloud(background_color="white", width=1200, height=800).generate(" ".join(tokens))
    else:
        wc = np.ones((800,1200,3))
    plt.figure(figsize=(8, 6))
    plt.imshow(wc)
    plt.axis("off")

    image = io.BytesIO()
    plt.savefig(image, format='png')
    image.seek(0)  # rewind the data
    string = base64.b64encode(image.read())

    image_64 = 'data:image/png;base64,' + urllib.parse.quote(string)

    pass_dict = {'hash': hash, 'scans': scans, 'label': label, 'dets': dets, 'engs': engs, "wc": image_64, "avc": max_avc,
                 'form': form, 'count': len(scans), 'entropies': entropies}

    return render(request, 'observes/detail.html', pass_dict)

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
