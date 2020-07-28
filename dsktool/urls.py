"""dsktool URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from . import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.index, name='index'),
    # path('isup', views.isup, name='isup'),
    # path('whoami', views.whoami, name='whoami'),
    # path('courses', views.courses, name='courses'),
    # path('users', views.users, name='users'),
    # path('enrollments', views.enrollments, name='enrollments'),
    # path('getusers', views.getusers, name='getusers'),
    # path('get_auth_code', views.get_auth_code, name='get_auth_code'),
    # path('get_access_token', views.get_access_token, name='get_access_token'),
    # path('learnlogout', views.learnlogout, name='learnlogout'),
    # path('notauthorized', views.notauthorized, name='notauthorized')
]

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.index, name='index'),
]


