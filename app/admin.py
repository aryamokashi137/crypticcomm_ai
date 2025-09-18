from django.contrib import admin
from .models import Message

@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = (
        "id", 
        "sender", 
        "receiver", 
        "classification",  # ✅ corrected
        "hash_value", 
        "delivered", 
        "is_read", 
        "created_at"
    )
    list_filter = ("classification", "delivered", "is_read")  # ✅ corrected
    search_fields = ("sender__username", "receiver__username", "hash_value")
