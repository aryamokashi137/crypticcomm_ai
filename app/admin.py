from django.contrib import admin
from .models import Message

@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = (
        "id", 
        "sender", 
        "receiver", 
        "classification", 
        "hash_value", 
        "status", 
        "created_at"
    )
    list_filter = ("classification", "status")  
    search_fields = ("sender__username", "receiver__username", "hash_value")
