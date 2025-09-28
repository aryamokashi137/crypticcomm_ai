from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, JsonResponse

from .models import Message, EncryptedFile
from .encryption_utils import encrypt_message, decrypt_message

from django.core.mail import send_mail
from django.conf import settings

from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.db import models
#from ml.classifier import classify_message
from django.db.models import Q
from .encryption_utils import encrypt_message,decrypt_message
from ml.model_service import classify_message
from django.conf import settings


import logging, traceback
logger = logging.getLogger(__name__)

# AI classifier fallback
try:
    from ml.model_service import classify_message
except Exception:
    def classify_message(message: str):
        return "low"

# ----------------- Pages -----------------
def homepage(request):
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
    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("password")

        try:
            user_obj = User.objects.get(email=email)
            username = user_obj.username
        except User.DoesNotExist:
            messages.error(request, "Invalid email or password")
            return render(request, 'loginpage.html')

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            messages.success(request, "Login successful! Redirecting to Inbox...")
            return redirect('inboxpage')
        else:
            messages.error(request, "Invalid email or password")

    return render(request, 'loginpage.html')


@login_required(login_url='loginpage')
def inboxpage(request):
    users = User.objects.exclude(id=request.user.id)
    messages_data = {}

    for user in users:
        # Fetch messages between logged-in user and 'user'
        msgs = Message.objects.filter(
            (Q(sender=request.user) & Q(receiver=user)) |
            (Q(sender=user) & Q(receiver=request.user))
        ).order_by('created_at')  # oldest first for chat display

        messages_data[user.username] = []

        for msg in msgs:
            try:
                # Attempt to decrypt message
                decrypted_text = decrypt_message(
                    msg.encrypted_text,
                    level=msg.classification,
                    private_key_pem=msg.private_key  # only for high
                )
            except Exception as e:
                # If decryption fails, use a placeholder
                decrypted_text = "[Error decrypting message]"

            messages_data[user.username].append({
                "text": decrypted_text,
                "sender": msg.sender.username,
                "timestamp": getattr(msg, 'timestamp', msg.created_at).isoformat(),
                "id": msg.id,
                "classification": msg.classification
            })

    return render(request, "inboxpage.html", {
        "users": users,
        "messages_data": messages_data
    })



# ----------------- API -----------------
logger = logging.getLogger(__name__)

from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.db.models import Q
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.core.mail import send_mail
from django.conf import settings
import traceback, logging

from .models import Message
from .encryption_utils import encrypt_message, decrypt_message
from ml.model_service import classify_message  # ML model

logger = logging.getLogger(__name__)

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def send_message(request):
    """
    API endpoint to send a message:
    - Classifies message confidentiality
    - Encrypts based on level
    - Stores in DB
    - Sends notification email WITHOUT showing message content
    """
    try:
        # --- Get data ---
        receiver_identifier = request.data.get("receiver")
        plaintext = request.data.get("message")
        hash_value = request.data.get("hash", "")

        if not receiver_identifier or not plaintext:
            return Response({"error": "receiver and message are required"}, status=400)

        # --- Resolve receiver ---
        try:
            receiver = User.objects.get(email=receiver_identifier) if "@" in receiver_identifier \
                else User.objects.get(username=receiver_identifier)
        except User.DoesNotExist:
            return Response({"error": "Receiver not found"}, status=404)

        sender = request.user

        # --- Classify message ---
        classification_result = classify_message(plaintext)
        # Use mapped_conf if available
        level = classification_result.get("mapped_conf", "low")

        # --- Encrypt message ---
        encrypted_dict = encrypt_message(plaintext, level)
        bundle = encrypted_dict.get("bundle")
        if isinstance(bundle, dict):
            bundle = bundle.get("bundle")  # handle nested dict
        private_key = encrypted_dict.get("private_key")  # only for high-level messages

        # --- Save message in DB ---
        msg = Message.objects.create(
            sender=sender,
            receiver=receiver,
            encrypted_text=bundle,
            hash_value=hash_value,
            classification=level,
            private_key=private_key
        )

        # --- Send email notification (without showing plaintext) ---
        subject = f"🔔 New Secure Message from {sender.username} on CrypticComm"
        html_message = f"""
        <html>
        <body>
            <p>Hi <b>{receiver.username}</b>,</p>
            <p>You have received a new message from <b>{sender.username}</b>.</p>
            <p>Log in to <a href="http://127.0.0.1:8000/" target="_blank">CrypticComm</a> to view it securely.</p>
            <br>
            <p>— CrypticComm</p>
        </body>
        </html>
        """
        try:
            send_mail(
                subject=subject,
                message=f"You have received a new message from {sender.username}.",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[receiver.email],
                html_message=html_message,
                fail_silently=False
            )
        except Exception as mail_err:
            logger.error(f"Failed to send email: {mail_err}")

        # --- Return API response ---
        return Response({
            "status": "success",
            "msg": "Message sent successfully!",
            "message_id": msg.id,
            "classification": level,
            "classifier": classification_result
        }, status=200)

    except Exception as e:
        logger.error("send_message error: %s\n%s", e, traceback.format_exc())
        return Response({"error": str(e)}, status=500)




import base64

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def send_file(request):
    """
    Handles sending file attachments and notifying the receiver via email.
    """
    try:
        receiver_identifier = request.POST.get("receiver")
        uploaded_file = request.FILES.get("file")

        if not receiver_identifier or not uploaded_file:
            return Response({"error": "receiver and file are required"}, status=400)

        # Resolve receiver
        try:
            receiver = User.objects.get(email=receiver_identifier) if "@" in receiver_identifier \
                else User.objects.get(username=receiver_identifier)
        except User.DoesNotExist:
            return Response({"error": "Receiver not found"}, status=404)

        sender = request.user

        # ----------------- Encrypt file data -----------------
        file_bytes = uploaded_file.read()
        file_b64_str = base64.b64encode(file_bytes).decode('utf-8')   # Convert bytes -> str
        encrypted_dict = encrypt_message(file_b64_str, "low")          # encrypt_message returns dict
        encrypted_data = encrypted_dict.get("ciphertext", "").encode('utf-8')  # Convert to bytes

        # ----------------- Create Message for file -----------------
        file_message = Message.objects.create(
            sender=sender,
            receiver=receiver,
            encrypted_text=f"[File attachment: {uploaded_file.name}]",
            classification="low"
        )

        # ----------------- Save EncryptedFile -----------------
        EncryptedFile.objects.create(
            message=file_message,
            filename=uploaded_file.name,
            encrypted_data=encrypted_data
        )

        # ----------------- Send notification email -----------------
        try:
            subject = "New File Received on CrypticComm"
            html_message = f"""
            <html>
            <body>
                <p>Hi <b>{receiver.username}</b>,</p>
                <p>You have received a file <b>{uploaded_file.name}</b> from <b>{sender.username}</b>.</p>
                <p>Log in to <a href="http://127.0.0.1:8000/" target="_blank">CrypticComm</a> to view/download it securely.</p>
                <br>
                <p>— CrypticComm</p>
            </body>
            </html>
            """
            send_mail(
                subject=subject,
                message=f"You have received a file from {sender.username}.",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[receiver.email],
                html_message=html_message,
                fail_silently=False
            )
        except Exception as mail_error:
            logger.warning("Email sending failed: %s", mail_error)

        return Response({"status": "success", "msg": "File sent successfully!"}, status=200)

    except Exception as e:
        logger.error("send_file error: %s\n%s", e, traceback.format_exc())
        return Response({"error": str(e)}, status=500)
    
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
@login_required
def decrypt_message_view(request):
    """
    Decrypt a single message when the lock icon is clicked.
    Expects POST with:
    {
        "encrypted_text": "...",
        "classification": "low|medium|high",
        "private_key": "... (optional for high)"
    }
    """
    if request.method == "POST":
        import json
        try:
            data = json.loads(request.body)
            encrypted_text = data.get("encrypted_text")
            classification = data.get("classification")
            private_key = data.get("private_key")
            decrypted_text = decrypt_message(encrypted_text, classification, private_key)
            return JsonResponse({"status": "success", "decrypted_text": decrypted_text})
        except Exception as e:
            return JsonResponse({"status": "error", "error": str(e)})
    return JsonResponse({"status": "error", "error": "Invalid request method"})

from django.views.decorators.csrf import csrf_exempt

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def decrypt_message_api(request):
    """
    Decrypt a single message on-demand
    """
    try:
        data = request.data
        encrypted_text = data.get("encrypted_text")
        classification = data.get("classification")
        private_key = data.get("private_key")

        if not encrypted_text or not classification:
            return Response({"status": "error", "error": "Missing data"}, status=400)

        decrypted_text = decrypt_message(encrypted_text, classification, private_key)
        return Response({"status": "success", "decrypted_text": decrypted_text}, status=200)

    except Exception as e:
        return Response({"status": "error", "error": str(e)}, status=500)
    



def logoutpage(request):
    logout(request)
    messages.success(request, "You have been logged out successfully.")
    return redirect('loginpage')


def profilepage(request):
    return render(request, 'profilepage.html')


def settingspage(request):
    return render(request, 'settingspage.html')


def aboutus(request):
    return render(request, 'aboutus.html')


