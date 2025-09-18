from django.db import models
from django.contrib.auth.models import User

class Message(models.Model):
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name="sent_messages")
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name="received_messages")
    encrypted_text = models.TextField()
    classification = models.CharField(max_length=20, default="low")
    hash_value = models.CharField(max_length=64, blank=True, null=True)
    private_key = models.TextField(blank=True, null=True)
    delivered = models.BooleanField(default=True)
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Msg from {self.sender} to {self.receiver} ({self.classification})"
