from django.contrib import admin
from .models import Hash, Scan, ReAnalyze, AvclassResult, RawReportEntropies

admin.site.register(Hash)
admin.site.register(Scan)
admin.site.register(ReAnalyze)
admin.site.register(AvclassResult)
admin.site.register(RawReportEntropies)
# Register your models here.
