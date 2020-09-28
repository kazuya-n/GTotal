from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('list/', views.list_hash, name='list_hash'),
    path('<str:sha256>/scans/', views.list_scans, name='list_scans'),
    path('<int:scan_id>/results/', views.scan_results, name='scan_results'),
]
