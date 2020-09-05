from django.db import models
from django.utils import timezone


class Hash(models.Model):
    sha256 = models.CharField(max_length=64, primary_key=True, unique=True)
    permalink = models.CharField(max_length=256, null=True, blank=True)
    name = models.CharField(max_length=64, null=True, blank=True)
    create_date = models.DateTimeField('date created', default=timezone.now)
    observing = models.BooleanField('rescan and get repoort with cron')

class Scan(models.Model):
    create_date = models.DateTimeField('date created', default=timezone.now)
    scan_date = models.DateTimeField('scan date', null=True, blank=True)
    detections = models.IntegerField('# of detections', null=True, blank=True)
    engines = models.IntegerField('# of AV engines', null=True, blank=True)
    json_url = models.CharField(
        'url of got json file', max_length=256, null=True, blank=True)
    report = models.JSONField(null=True, blank=True)
    status = models.CharField('status code of API', max_length=3)

    sha256 = models.ForeignKey(Hash, verbose_name='hash', on_delete=models.CASCADE, related_name="detection_of_hash")

class ReAnalyze(models.Model):
    create_date = models.DateTimeField('date created', default=timezone.now)
    status = models.CharField('status code of API', max_length=3)

    sha256 = models.ForeignKey(
        Hash, verbose_name='hash', on_delete=models.CASCADE)
