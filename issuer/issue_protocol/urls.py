from django.urls import path
from . import views
app_name = "accounts"
urlpatterns = [
	path('', views.login_view, name='login'),
    path('accounts/signup', views.signup, name='signup'),
    path('accounts/get_credential', views.get_credential, name='get_credential'),
]
