from django.urls import path
from . import views
app_name = "accounts"
urlpatterns = [
	path('', views.login_view, name='login'),
    path('accounts/signup', views.signup, name='signup'),
    path('accounts/get_credential', views.get_credential, name='get_credential'),
    path('accounts/req_cred', views.request_credential, name='req_cred'),
    path('accounts/test_conn', views.test_connect, name='test_conn'),
]
