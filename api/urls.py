from django.urls import path
from django.views.decorators.csrf import csrf_exempt

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('register/', views.register, name='register'),
    path('list/', views.list_hash, name='list_hash'),
    path('<str:sha256>/scans/', views.list_scans, name='list_scans'),
    path('<str:sha256>/agg/', views.aggregation, name='list_aggregation'),
    path('<int:scan_id>/results/', views.scan_results, name='scan_results'),
]
