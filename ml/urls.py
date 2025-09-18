from django.urls import path
from .views import classify_view

urlpatterns = [
    path("classify/", classify_view, name="classify"),
]
