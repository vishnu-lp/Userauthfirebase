from django.conf.urls import url
import views

urlpatterns = [
    url(r'^users/$', views.user_registration),
    url(r'^users/(?P<pk>[0-9]+)/$', views.user_detail),
    url(r'^users/login/$', views.user_login),
    url(r'^users/(?P<pk>[0-9]+)/change_password/$', views.user_change_password),
    url(r'^users/delete/(?P<pk>[0-9]+)/$', views.delete_user)
]
