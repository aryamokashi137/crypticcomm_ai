from django.urls import path
from . import views
from .views import get_message_statuses


urlpatterns = [
    path("", views.homepage, name="homepage"),
    path("loginpage/", views.loginpage, name="loginpage"),
    path("logout/", views.logoutpage, name="logoutpage"),
    path("inboxpage/", views.inboxpage, name="inboxpage"),
    path("send_message_api/", views.send_message_api, name="send_message_api"),
    path("aboutus/", views.aboutus, name="aboutus"),
    path("profilepage/", views.profilepage, name="profilepage"),
    path("settingspage/", views.settingspage, name="settingspage"),
    path("api/send_file/", views.send_file, name="send_file"),
    path("api/decrypt_message/", views.decrypt_message_api, name="decrypt_message"),
    path("update_status/<int:message_id>/", views.update_status, name="update_status"),
    path("api/get_hash/<int:message_id>/", views.get_hash, name="get_hash"),
    path("api/messages/statuses/", get_message_statuses, name="get_message_statuses"),



]

