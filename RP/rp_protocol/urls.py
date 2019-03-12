from django.urls import path
from . import views
from rest_framework.urlpatterns import format_suffix_patterns

app_name = "rp"
urlpatterns = [
    # API Paths
    path('', views.home, name='home'),
    path('request_access', views.request_access, name='request_access'),
    path('present', views.present_credentials, name='present_credentials'),

    # Debugging Paths
    path('put', views.put_all, name='put'),
    path('delete', views.delete_all, name='delete'),

    # Testing Paths
    path('test_ledger', views.test_ledger, name='test_l'),
    path('test_auth', views.example_token_issuer, name='test_auth')
]

urlpatterns = format_suffix_patterns(urlpatterns)
