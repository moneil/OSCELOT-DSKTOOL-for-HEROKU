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
from dsktool import views
from django.conf.urls import url


urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.index, name='index'),
    path('courses', views.courses, name='courses'),
    path('enrollments', views.enrollments, name='enrollments'),
    path('get_auth_code', views.get_auth_code, name='get_auth_code'),
    path('get_access_token', views.get_access_token, name='get_access_token'),
    path('guestusernotallowed', views.guestusernotallowed, name='guestusernotallowed'),
    path('isup', views.isup, name='isup'),
    path('learnlogout', views.learnlogout, name='learnlogout'),
    path('notauthorized', views.notauthorized, name='notauthorized'),
    path('users', views.users, name='users'),
    path('whoami', views.whoami, name='whoami'),

    url(r'^ajax/validate_userIdentifier/$', views.validate_userIdentifier, name='validate_userIdentifier'),
    url(r'^ajax/validate_courseIdentifier/$', views.validate_courseIdentifier, name='validate_courseIdentifier'),
    url(r'^ajax/getCourseMembership/$', views.getCourseMembership, name='getCourseMembership'),
    url(r'^ajax/updateCourseMembership/$', views.updateCourseMembership, name='updateCourseMembership'),
    url(r'^ajax/getCourseMemberships/$', views.getCourseMemberships, name='getCourseMemberships'),
    url(r'^ajax/updateCourseMemberships/$', views.updateCourseMemberships, name='updateCourseMemberships'),
    url(r'^ajax/getUserMemberships/$', views.getUserMemberships, name='getUserMemberships'),
    url(r'^ajax/updateUserMemberships/$', views.updateUserMemberships, name='updateUserMemberships'),

]

handler500 = views.error_500

from django.conf import settings
from django.conf.urls.static import static

urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)