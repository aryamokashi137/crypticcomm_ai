from rest_framework import serializers
from .models import Message

class MessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Message
        fields = [
            "id",
            "sender",
            "receiver",
            "encrypted_text",
            "encryption_algo",
            "key_metadata",
            "hash_value",
            "is_read",
            "delivered",
            "created_at",
        ]
        read_only_fields = ["id", "created_at", "is_read", "delivered"]
