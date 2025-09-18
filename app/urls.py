from django.urls import path
from . import views

urlpatterns = [
    path("", views.homepage, name="homepage"),
    path("loginpage/", views.loginpage, name="loginpage"),
    path("logout/", views.logoutpage, name="logoutpage"),
    path("inboxpage/", views.inboxpage, name="inboxpage"),
    path("send_message/", views.send_message, name="send_message"),
    path("msgpage/", views.msgpage, name="msgpage"),
]
