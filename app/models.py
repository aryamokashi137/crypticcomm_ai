from django.db import models
from django.contrib.auth.models import User


from django.db import models
from django.contrib.auth.models import User

class Message(models.Model):
    """
    Stores encrypted messages between users.
    Classification determines encryption strength:
    - low: stored as plaintext
    - medium: AES encrypted (AES key stored in private_key)
    - high: RSA encrypted (RSA private key stored in private_key)

    Status determines tick state:
    - sent: single tick
    - delivered: double tick
    - seen: blue double tick
    """

    CLASSIFICATION_CHOICES = [
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
    ]

    STATUS_CHOICES = [
        ("sent", "Sent"),
        ("delivered", "Delivered"),
        ("seen", "Seen"),
    ]

    sender = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="sent_messages"
    )
    receiver = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="received_messages"
    )
    encrypted_text = models.TextField()  # encrypted content (AES/RSA/plaintext)
    classification = models.CharField(
        max_length=20, choices=CLASSIFICATION_CHOICES, default="low"
    )
    hash_value = models.CharField(
        max_length=64, blank=True, null=True, help_text="Optional SHA-256 hash"
    )
    private_key = models.TextField(
        blank=True,
        null=True,
        help_text="AES key for medium / RSA private key for high",
    )
    status = models.CharField(
        max_length=10,
        choices=[("sent", "Sent"), ("delivered", "Delivered"), ("seen", "Seen")],
        default="sent"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.sender} -> {self.receiver} [{self.status}]"

class EncryptedFile(models.Model):
    """
    Stores encrypted files attached to a Message.
    Encrypted with the same method as the parent message.
    """

    message = models.ForeignKey(
        Message, on_delete=models.CASCADE, related_name="files"
    )
    filename = models.CharField(max_length=255)
    encrypted_data = models.BinaryField()  # store raw encrypted bytes
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"File {self.filename} (Message {self.message.id})"
