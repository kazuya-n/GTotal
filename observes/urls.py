from django.urls import path

from . import views

app_name = 'observes'
urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('list/', views.index, name='index'),
    # path('register/', views.register, name='register'),
    path('detail/<str:sha256>/', views.detail, name='detail'),
]
