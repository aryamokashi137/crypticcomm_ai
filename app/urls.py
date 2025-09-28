from django.urls import path
from . import views

urlpatterns = [
    path("", views.homepage, name="homepage"),
    path("loginpage/", views.loginpage, name="loginpage"),
    path("logout/", views.logoutpage, name="logoutpage"),
    path("inboxpage/", views.inboxpage, name="inboxpage"),
    path("send_message/", views.send_message, name="send_message"),
    path("aboutus/", views.aboutus, name="aboutus"),
    path("profilepage/", views.profilepage, name="profilepage"),
    path("settingspage/", views.settingspage, name="settingspage"),
    path("api/send_file/", views.send_file, name="send_file"),
    path("api/decrypt_message/", views.decrypt_message_api, name="decrypt_message"),

]

