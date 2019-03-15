from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('<int:credential_id>', views.detail, name='detail'),
    path('login_idp/', views.login_idp, name='login_idp'),
    path('select_policy/', views.select_policy, name='select_policy'),
    path('use_credential/', views.use_credential, name='use_credential')
]