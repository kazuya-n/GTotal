from django.contrib import admin
from .models import Hash, Scan, ReAnalyze

admin.site.register(Hash)
admin.site.register(Scan)
admin.site.register(ReAnalyze)

# Register your models here.
