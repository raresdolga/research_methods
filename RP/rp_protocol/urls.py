from django.urls import path
from . import views

app_name = "rp"
urlpatterns = [
    path('rp/test/', views.test_connect_issuer, name='test'),
    path('rp/test_ledger/', views.test_ledger, name='test_l'),
    path('rp/test_auth/', views.example_token_issuer, name='test_auth'),
]
