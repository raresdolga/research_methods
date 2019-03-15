from django.urls import path
from . import views

app_name = "rp"
urlpatterns = [
    # API Paths
    path('', views.home, name='home'),
    path('request_access', views.request_access, name='request_access'),
    path('verify', views.verify_session, name='verify'),


    # Debugging Paths
    path('put', views.put_all, name='put'),
    path('delete', views.delete_all, name='delete'),

    # Testing Paths
    path('test_ledger', views.test_ledger, name='test_l'),
    path('test_auth', views.example_token_issuer, name='test_auth'),
    path('verify_test', views.test_verification, name='verify')
    # path('create_dummy_ap', views.create_new_ap_policy, name='new_ap')
]
