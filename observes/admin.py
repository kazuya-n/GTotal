from django.contrib import admin
from .models import Hash, Scan, ReAnalyze, AvclassResult

admin.site.register(Hash)
admin.site.register(Scan)
admin.site.register(ReAnalyze)
admin.site.register(AvclassResult)
# Register your models here.
