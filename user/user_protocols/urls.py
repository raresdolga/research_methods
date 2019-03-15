from django.urls import path
from . import views
app_name = "user"

urlpatterns = [
    path('', views.index, name="index"),
    path('login/', views.login_view, name="login_view"),
    path('user/front_page/<str:user>', views.front_page, name = "front_page"),
]
