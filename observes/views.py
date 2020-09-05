from django.core.paginator import Paginator
from django.http import HttpResponse, HttpResponseRedirect
from django.template import loader
from django.shortcuts import get_object_or_404, render
from django.urls import reverse

import base64
import io
import json
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import urllib
import re
import wordcloud

from .forms import HashForm
from .models import Hash


def index(request):
    all_hash_list = Hash.objects.all()
    template = loader.get_template('observes/index.html')
    paginator = Paginator(all_hash_list, 10)
    p = request.GET.get('p')
    p_hash_list = paginator.get_page(p)
    context = {
        'latest_hash_list': p_hash_list,
    }
    return HttpResponse(template.render(context, request))

def detail(request, sha256):
    hash = get_object_or_404(Hash, pk=sha256)
    scans = hash.detection_of_hash.all()
    label = [s.scan_date.isoformat() for s in scans]
    dets = [s.detections for s in scans]
    engs = [s.engines for s in scans]
    tokens = []
    for scan in scans:
        reports = scan.report
        engines = reports["scans"].keys()
        for e in engines:
            if reports["scans"][e]["detected"]:
                res = reports["scans"][e]["result"]
                tokens += re.split("[\.\s\/]",res.rstrip())
    wc = wordcloud.WordCloud(background_color="white", width=1200, height=800).generate(" ".join(tokens))
    plt.figure(figsize=(8, 6))
    plt.imshow(wc)
    plt.axis("off")

    image = io.BytesIO()
    plt.savefig(image, format='png')
    image.seek(0)  # rewind the data
    string = base64.b64encode(image.read())

    image_64 = 'data:image/png;base64,' + urllib.parse.quote(string)

    return render(request, 'observes/detail.html', {'hash': hash, 'scans':scans, 'label':label, 'dets':dets, 'engs':engs, "wc":image_64})

def register(request):
    if request.method == 'GET':
        form = HashForm()
        return render(request, 'observes/register.html', {'form': form})
    elif request.method == 'POST':
        form = HashForm(request.POST)
        if form.is_valid():
            h = form.save(commit=False)
            h.observing=True
            h.save()
        return HttpResponseRedirect(reverse('observes:index', ))
