from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from .models import Message

# For sending emails
from django.core.mail import send_mail
from django.conf import settings

# For API
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated

# Logging
import traceback
import logging
logger = logging.getLogger(__name__)

# ----------------------------------------------------------------
# Import AI classifier
# ----------------------------------------------------------------
try:
    from ml.model_service import classify_message
    logger.info("Using real AI classifier from ml.model_service")
except Exception as e:
    logger.error("Could not import classifier: %s", e)

    def classify_message(message: str):
        """Fallback if model import fails"""
        return "unknown"


# ----------------------------------------------------------------
# Import Encryption Utils
# ----------------------------------------------------------------
from .encryption_utils import encrypt_message, decrypt_message


# ----------------------------------------------------------------
# Registration / Login / Pages
# ----------------------------------------------------------------
def homepage(request):
    """ Registration page """
    if request.method == 'POST':
        name = request.POST.get('name', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '')
        confirm_password = request.POST.get('confirmPassword', '')

        if not name or not email or not password or not confirm_password:
            messages.error(request, "All fields are required.")
            return render(request, "homepage.html")

        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return render(request, "homepage.html")

        if User.objects.filter(username=name).exists():
            messages.error(request, "Username already taken.")
            return render(request, "homepage.html")

        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already registered.")
            return render(request, "homepage.html")

        user = User.objects.create_user(username=name, email=email, password=password)
        user.save()
        messages.success(request, "Registration successful! Please login.")
        return redirect('loginpage')

    return render(request, 'homepage.html')


def loginpage(request):
    """ Login page """
    if request.method == "POST":
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '')

        if not email or not password:
            messages.error(request, "Please enter both email and password")
            return render(request, "loginpage.html")

        try:
            user_obj = User.objects.get(email=email)
            username = user_obj.username
        except User.DoesNotExist:
            messages.error(request, "Invalid email or password")
            return render(request, "loginpage.html")

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            messages.success(request, f"Welcome {user.first_name or user.username}!")
            return redirect('msgpage')
        else:
            messages.error(request, "Invalid email or password")
            return render(request, "loginpage.html")

    return render(request, "loginpage.html")


@login_required(login_url='loginpage')
def msgpage(request):
    """Message page (protected)"""
    users = User.objects.exclude(id=request.user.id)
    user_emails = list(users.values_list("email", flat=True))

    messages_list = Message.objects.filter(sender=request.user).order_by(
        "-created_at" if hasattr(Message, "created_at") else "-timestamp"
    )

    return render(request, 'msgpage.html', {
        "users": users,
        "user_emails": user_emails,
        "messages": messages_list,
        "message_count": Message.objects.filter(receiver=request.user).count()
    })


@login_required(login_url='loginpage')
def inboxpage(request):
    """Inbox page (protected)"""
    users = User.objects.exclude(id=request.user.id)
    inbox_messages = Message.objects.filter(receiver=request.user).order_by(
        "-created_at" if hasattr(Message, "created_at") else "-timestamp"
    )

    messages_data = []
    for msg in inbox_messages:
        try:
            decrypted_text = decrypt_message(msg.encrypted_text, msg.classification)
        except Exception as e:
            logger.error("Decryption failed for msg %s: %s", msg.id, e)
            decrypted_text = "[Decryption Failed]"

        messages_data.append({
            "sender": msg.sender,
            "text": decrypted_text,
            "hash": getattr(msg, "hash_value", None) or "—",
            "classification": getattr(msg, "classification", "unknown"),
        })

    return render(request, 'inboxpage.html', {
        "users": users,
        "messages_data": messages_data
    })


def logoutpage(request):
    logout(request)
    messages.success(request, "You have been logged out successfully.")
    return redirect('loginpage')


# ----------------------------------------------------------------
# API: send_message
# ----------------------------------------------------------------
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def send_message(request):
    """
    Send classified message and notify receiver by email.
    Body: {
        "receiver": "username/email",
        "message": "...",
        "classification": "high|medium|low"
    }
    """
    try:
        receiver_identifier = request.data.get("receiver")
        plaintext = request.data.get("message")
        hash_value = request.data.get("hash")

        if not receiver_identifier or not plaintext:
            return Response({"error": "receiver and message are required"},
                            status=status.HTTP_400_BAD_REQUEST)

        # Resolve receiver
        try:
            receiver = User.objects.get(email=receiver_identifier) if "@" in receiver_identifier \
                else User.objects.get(username=receiver_identifier)
        except User.DoesNotExist:
            return Response({"error": "Receiver not found"},
                            status=status.HTTP_404_NOT_FOUND)

        sender = request.user

        classification_label = (request.data.get("classification") or "").lower()
        if not classification_label:
            classification_label = classify_message(plaintext).lower()

        if classification_label not in ["high", "medium", "low"]:
            logger.warning(f"Unknown classification '{classification_label}', defaulting to 'low'")
            classification_label = "low"

        # Encrypt message
        encrypted_bundle = encrypt_message(plaintext, classification_label)

        msg = Message.objects.create(
            sender=sender,
            receiver=receiver,
            encrypted_text=encrypted_bundle,
            hash_value=hash_value,
            classification=classification_label,
        )

        # Notify email
        try:
            subject = "🔔 New Secure Message on CrypticComm"
            body = (
                f"Hi {receiver.username},\n\n"
                f"You have received a message from {sender.username}.\n"
                f"Message type: {classification_label}\n\n"
                f"Log in to CrypticComm to view it securely.\n\n"
                f"— CrypticComm"
            )
            send_mail(subject, body, settings.DEFAULT_FROM_EMAIL, [receiver.email], fail_silently=False)
        except Exception as mail_error:
            logger.warning("Email sending failed: %s", mail_error)

        return Response({
            "status": "success",
            "msg": "Message sent successfully!",
            "message_id": msg.id,
            "classification": classification_label
        }, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error("send_message error: %s\n%s", e, traceback.format_exc())
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ----------------------------------------------------------------
# API: inbox
# ----------------------------------------------------------------
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def inbox_api(request):
    try:
        inbox_messages = Message.objects.filter(receiver=request.user).order_by(
            "-created_at" if hasattr(Message, "created_at") else "-timestamp"
        )

        data = []
        for msg in inbox_messages:
            try:
                decrypted_text = decrypt_message(msg.encrypted_text, msg.classification)
            except Exception:
                decrypted_text = "[Decryption Failed]"

            created = getattr(msg, "created_at", None) or getattr(msg, "timestamp", None)
            data.append({
                "id": msg.id,
                "from": msg.sender.username,
                "text": decrypted_text,
                "classification": getattr(msg, "classification", "unknown"),
                "created_at": created,
            })

        return Response(data, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error("Inbox API error: %s\n%s", e, traceback.format_exc())
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
