from django.urls import path
from . import views

app_name = "rp"
urlpatterns = [
    path('rp/test/', views.test_connect_issuer, name='test'),
]
