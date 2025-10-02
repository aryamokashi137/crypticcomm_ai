# app/views.py (only main parts shown; integrate in your file)
from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from .models import Message
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
import traceback, logging, hashlib

from django.db.models import Q
from .encryption_utils import encrypt_message,decrypt_message
from ml.model_service import classify_message
from django.conf import settings

from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.db import models
import base64
import traceback
import logging
from django.conf import settings
from django.core.mail import send_mail
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.contrib.auth.models import User
from .models import Message, EncryptedFile
from app.encryption_utils import encrypt_message  # assuming your encryption util

logger = logging.getLogger(__name__)

# imports from earlier
try:
    from ml.model_service import classify_message
except Exception as e:
    logger.exception("Classifier import failed: %s", e)
    def classify_message(message: str):
        return {"mapped_conf": "low", "encryption": "Fernet", "label_raw": "low_confidential", "index": 0, "probs": []}

from .encryption_utils import encrypt_message, decrypt_message

# ---------- page views ----------
def homepage(request):
    if request.method == "POST":
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
        pass
    return render(request, "homepage.html")

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
     return render(request, "loginpage.html")

@login_required(login_url='loginpage')
def msgpage(request):
    users = User.objects.exclude(id=request.user.id)
    user_emails = list(users.values_list("email", flat=True))
    message_count = Message.objects.filter(receiver=request.user).count()
    return render(request, "msgpage.html", {
        "users": users,
        "user_emails": user_emails,
        "message_count": message_count
    })
@login_required(login_url='loginpage')
def inboxpage(request):
    """
    Pass structured messages_data to template.
    Group messages by conversation partner (other user) so frontend JS can access messagesData[user].
    Include messages where the current user is either sender or receiver.
    """
    users = User.objects.exclude(id=request.user.id)

    # Fetch all messages where the current user is involved (either sender or receiver)
    # Order ascending so messages appear in chronological order within each conversation
    inbox_messages = Message.objects.filter(
        Q(receiver=request.user) | Q(sender=request.user)
    ).order_by("created_at")

    messages_data = {}

    for m in inbox_messages:
        try:
            private_key = getattr(m, "private_key", None)
            # decrypt_message expects (bundle_str, level, private_key)
            plain = decrypt_message(m.encrypted_text, m.classification, private_key)
        except Exception as e:
            logger.exception("Decryption failed for msg %s: %s", getattr(m, "id", "?"), e)
            plain = "[Decryption Failed]"

        # Determine conversation partner (the "other" user)
        # If the current user is the sender, other = receiver; else other = sender
        try:
            sender_username = m.sender.username if m.sender else None
            receiver_username = m.receiver.username if m.receiver else None
        except Exception:
            sender_username = getattr(m, "sender", None)
            receiver_username = getattr(m, "receiver", None)

        if m.sender and m.sender == request.user:
            other_username = receiver_username
        else:
            other_username = sender_username

        # Skip if other participant is missing (defensive)
        if not other_username:
            continue

        # initialize list for this conversation partner
        if other_username not in messages_data:
            messages_data[other_username] = []

        messages_data[other_username].append({
            "id": m.id,
            "sender": sender_username,
            "text": plain,
            "classification": m.classification,
            "hash": getattr(m, "hash_value", None) or "—",
            "created_at": m.created_at.isoformat() if m.created_at else None
        })

    return render(request, "inboxpage.html", {
        "users": users,
        "messages_data": messages_data
    })



def logoutpage(request):
    logout(request)
    messages.success(request, "Logged out")
    return redirect("loginpage")

# ---------- API endpoints ----------
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def send_message_api(request):
    """
    Expects JSON:
    { "receiver": <user id or email or username>, "message": "...", optional "classification": "low|medium|high" }
    """
    try:
        receiver_identifier = request.data.get("receiver")
        plaintext = request.data.get("message")
        frontend_class = (request.data.get("classification") or "").lower()

        if not receiver_identifier or not plaintext:
            return Response({"error": "receiver and message required"}, status=status.HTTP_400_BAD_REQUEST)

        # resolve receiver (try id -> email -> username)
        receiver = None
        if isinstance(receiver_identifier, int) or (isinstance(receiver_identifier, str) and receiver_identifier.isdigit()):
            try:
                receiver = User.objects.get(id=int(receiver_identifier))
            except User.DoesNotExist:
                receiver = None
        if receiver is None and "@" in str(receiver_identifier):
            try:
                receiver = User.objects.get(email=receiver_identifier)
            except User.DoesNotExist:
                receiver = None
        if receiver is None:
            try:
                receiver = User.objects.get(username=receiver_identifier)
            except User.DoesNotExist:
                return Response({"error": "Receiver not found"}, status=status.HTTP_404_NOT_FOUND)

        sender = request.user

        # classification from frontend if provided, else use ML
        if frontend_class in ("low", "medium", "high"):
            mapped_conf = frontend_class
            suggested = None
        else:
            ml_res = classify_message(plaintext)
            mapped_conf = ml_res.get("mapped_conf", "low")
            suggested = ml_res.get("encryption")

        # validate mapped_conf
        if mapped_conf not in ("low", "medium", "high"):
            mapped_conf = "low"

        # encrypt with standard API
        enc = encrypt_message(plaintext, mapped_conf)
        bundle = enc.get("bundle")
        private_key = enc.get("private_key")  # store in DB for high/medium
        algo = enc.get("algo")

        # sha256 hash
        h = hashlib.sha256(plaintext.encode()).hexdigest()

        # ✅ Only use fields that exist in Message model
        msg = Message.objects.create(
            sender=sender,
            receiver=receiver,
            encrypted_text=bundle,
            private_key=private_key,
            classification=mapped_conf,
            hash_value=h,
            status="sent"   # ✅ tick: mark as sent
        )

        # try to email notify
        try:
            subject = "🔔 New Secure Message on CrypticComm"
            body = f"Hi {receiver.username},\nYou have received a message from {sender.username}. Log in to view it."
            send_mail(subject, body, settings.DEFAULT_FROM_EMAIL, [receiver.email], fail_silently=False)
            msg.status = "delivered"   # ✅ tick: mark as delivered if email sent
            msg.save(update_fields=["status"])
        except Exception as e:
            logger.warning("Email notify failed: %s", e)

        return Response({
            "status": "success",
            "msg": "Message sent successfully!",
            "message_id": msg.id,
            "classification": mapped_conf,
            "text": plaintext,  # ✅ return plaintext so UI displays immediately
            "tick": msg.status  # ✅ return tick to frontend
        }, status=status.HTTP_200_OK)

    except Exception as e:
        logger.exception("send_message_api error: %s", e)
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




logger = logging.getLogger(__name__)

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

        # ----------------- Resolve receiver -----------------
        try:
            if "@" in receiver_identifier:
                receiver = User.objects.get(email=receiver_identifier)
            else:
                receiver = User.objects.get(username=receiver_identifier)
        except User.DoesNotExist:
            return Response({"error": "Receiver not found"}, status=404)

        sender = request.user

        # ----------------- Encrypt file data -----------------
        file_bytes = uploaded_file.read()
        file_b64_str = base64.b64encode(file_bytes).decode("utf-8")  # bytes → base64 string
        encrypted_dict = encrypt_message(file_b64_str, "low")        # returns dict
        encrypted_data = encrypted_dict.get("ciphertext", "").encode("utf-8")  # str → bytes

        # ----------------- Create Message for file -----------------
        file_message = Message.objects.create(
            sender=sender,
            receiver=receiver,
            encrypted_text=f"[File attachment: {uploaded_file.name}]",
            classification="low",
            status="sent"   # ✅ tick: mark as sent
        )

        # ----------------- Save EncryptedFile -----------------
        EncryptedFile.objects.create(
            message=file_message,
            filename=uploaded_file.name,
            encrypted_data=encrypted_data
        )

        # ----------------- Send notification email -----------------
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
        try:
            send_mail(
                subject=subject,
                message=f"You have received a file from {sender.username}.",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[receiver.email],
                html_message=html_message,
                fail_silently=False
            )
            file_message.status = "delivered"   # ✅ tick: mark as delivered after email sent
            file_message.save(update_fields=["status"])
        except Exception as mail_error:
            logger.warning("Email sending failed: %s", mail_error)

        return Response({
            "status": "success",
            "msg": "File sent successfully!",
            "message_id": file_message.id,
            "tick": file_message.status  # ✅ return tick for frontend
        }, status=200)

    except Exception as e:
        logger.error("send_file error: %s\n%s", e, traceback.format_exc())
        return Response({"error": str(e)}, status=500)



@api_view(["GET"])
@permission_classes([IsAuthenticated])
def inbox_api(request):
    """
    Return decrypted messages for currently logged-in user (server side decrypt).
    Auto-update 'sent' → 'delivered' for messages fetched by the receiver.
    """
    try:
        inbox_messages = Message.objects.filter(receiver=request.user).order_by("-created_at")

        # 🔄 auto-update any "sent" → "delivered"
        inbox_messages.filter(status="sent").update(status="delivered")

        data = []
        for m in inbox_messages:
            try:
                plain = decrypt_message(m.encrypted_text, m.classification, m.private_key)
            except Exception:
                plain = "[Decryption Failed]"

            data.append({
                "id": m.id,
                "from": m.sender.username,
                "text": plain,
                "classification": m.classification,
                "hash": m.hash_value,
                "created_at": m.created_at.isoformat() if m.created_at else None,
                "status": getattr(m, "status", None)  # ✅ sender will see updated ticks
            })
        return Response(data, status=status.HTTP_200_OK)
    except Exception as e:
        logger.exception("inbox_api error: %s", e)
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


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
    

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def update_status(request, message_id):
    """
    Update message status:
    - 'sent' → 'delivered'
    - mark as 'seen' if requested
    """
    try:
        msg = Message.objects.get(id=message_id, receiver=request.user)

        # Decide new status
        new_status = "delivered"
        if request.data.get("seen") is True:
            new_status = "seen"

        # Update receiver copy
        msg.status = new_status
        msg.save(update_fields=["status"])

        # 🔵 Also update sender copy in DB
        Message.objects.filter(
            id=message_id, sender=msg.sender
        ).update(status=new_status)

        return Response({"status": new_status}, status=status.HTTP_200_OK)

    except Message.DoesNotExist:
        return Response({"error": "Message not found"}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        logger.exception("update_status error: %s", e)
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



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
