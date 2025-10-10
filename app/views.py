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
        # --- Debug logs to check received data ---
        print("Registration POST dict:", dict(request.POST))
        print("Registration raw body:", request.body[:200])

        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '')
        confirm_password = request.POST.get('confirmPassword', '')

        # --- Validation checks ---
        if not username or not email or not password or not confirm_password:
            messages.error(request, "All fields are required.")
            return render(request, "homepage.html")

        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return render(request, "homepage.html")

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already taken.")
            return render(request, "homepage.html")

        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already registered.")
            return render(request, "homepage.html")

        # --- Create user ---
        user = User.objects.create_user(username=username, email=email, password=password)
        user.save()
        messages.success(request, "Registration successful! Please login.")
        return redirect('loginpage')

    # For GET request
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
    Show all other users in chat list even if no messages exist.
    """
    # Fetch all messages where the current user is involved
    inbox_messages = Message.objects.filter(
        Q(receiver=request.user) | Q(sender=request.user)
    ).order_by("created_at")

    messages_data = {}
    chat_usernames = set()  # store users who have messages

    for m in inbox_messages:
        try:
            private_key = getattr(m, "private_key", None)
            plain = decrypt_message(m.encrypted_text, m.classification, private_key)
        except Exception as e:
            logger.exception("Decryption failed for msg %s: %s", getattr(m, "id", "?"), e)
            plain = "[Decryption Failed]"

        # Determine conversation partner
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

        # Skip if other participant is missing
        if not other_username:
            continue

        # Add to chat users set
        chat_usernames.add(other_username)

        # Initialize list for this conversation partner
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

    # Fetch all other users for chat list (exclude self)
    all_users = User.objects.exclude(id=request.user.id)

    # Merge with users who have messages to maintain order
    # users with messages first, then others
    users_with_messages = User.objects.filter(username__in=chat_usernames)
    other_users = all_users.exclude(username__in=chat_usernames)

    users = list(users_with_messages) + list(other_users)

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
            message_type='text' ,
            status="sent" 
        
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



# small helper: decode BinaryField (bytes/memoryview) that contains the bundle (utf-8)
def _bundle_bytes_to_str(enc_bytes):
    # enc_bytes may be bytes, bytearray, memoryview or str
    if isinstance(enc_bytes, memoryview):
        enc_bytes = enc_bytes.tobytes()
    if isinstance(enc_bytes, (bytes, bytearray)):
        return enc_bytes.decode("utf-8")
    return str(enc_bytes)

logger = logging.getLogger(__name__)

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def send_file(request):
    """
    Handles sending file attachments without ML classification.
    Files are encrypted with Fernet and stored in EncryptedFile.
    """
    import base64
    from cryptography.fernet import Fernet
    from .models import EncryptedFile, Message

    try:
        receiver_identifier = request.POST.get("receiver")
        uploaded_file = request.FILES.get("file")

        if not receiver_identifier or not uploaded_file:
            return Response({"error": "receiver and file are required"}, status=400)

        # Resolve receiver
        try:
            if "@" in receiver_identifier:
                receiver = User.objects.get(email=receiver_identifier)
            else:
                receiver = User.objects.get(username=receiver_identifier)
        except User.DoesNotExist:
            return Response({"error": "Receiver not found"}, status=404)

        sender = request.user

        # Encrypt file data using Fernet only
        file_bytes = uploaded_file.read()
        file_b64 = base64.b64encode(file_bytes)
        key_bytes = Fernet.generate_key()
        f = Fernet(key_bytes)
        encrypted_data = f.encrypt(file_b64)
        private_key_str = key_bytes.decode("utf-8")

        # Create a placeholder Message for the file
        file_message = Message.objects.create(
            sender=sender,
            receiver=receiver,
            encrypted_text=f"[File attachment: {uploaded_file.name}]",
            classification="low",  # always low
            private_key=private_key_str,
            message_type='file',
            status="sent"
            
        )

        # Save encrypted file bytes
        EncryptedFile.objects.create(
            message=file_message,
            filename=uploaded_file.name,
            encrypted_data=encrypted_data
        )

        # Send notification email
        try:
            subject = "New File Received on CrypticComm"
            html_message = f"""
            <html><body>
            <p>Hi <b>{receiver.username}</b>,</p>
            <p>You have received a file <b>{uploaded_file.name}</b> from <b>{sender.username}</b>.</p>
            <p>Log in to <a href="http://127.0.0.1:8000/">CrypticComm</a> to view/download it securely.</p>
            </body></html>
            """
            send_mail(
                subject,
                message=f"You have received a file from {sender.username}.",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[receiver.email],
                html_message=html_message,
                fail_silently=False
            )
            file_message.status = "delivered"
            file_message.save(update_fields=["status"])
        except Exception as mail_error:
            logger.warning("Email sending failed: %s", mail_error)

        return Response({
            "status": "success",
            "msg": "File sent successfully!",
            "message_id": file_message.id,
            "tick": file_message.status
        }, status=200)

    except Exception as e:
        logger.error("send_file error: %s", e, exc_info=True)
        return Response({"error": str(e)}, status=500)



def decrypt_file_for_message(message):
    """
    Decrypts the file data for a given Message that represents a file attachment.
    Returns (filename, file_bytes) or an error string.
    """
    import base64
    from cryptography.fernet import Fernet
    from .models import EncryptedFile

    try:
        enc_obj = EncryptedFile.objects.filter(message=message).first()
        if not enc_obj:
            return "[Decryption Failed: Encrypted file not found]"

        if not message.private_key:
            return "[Decryption Failed: Missing private key]"

        f = Fernet(message.private_key.encode("utf-8"))

        enc_data = enc_obj.encrypted_data
        if isinstance(enc_data, memoryview):
            enc_data = enc_data.tobytes()
        if isinstance(enc_data, str):
            enc_data = enc_data.encode("utf-8")

        # decrypt -> base64 bytes
        decrypted_b64 = f.decrypt(enc_data)
        file_bytes = base64.b64decode(decrypted_b64)

        return (enc_obj.filename, file_bytes)
    except Exception as e:
        logger.exception("decrypt_file_for_message failed: %s", e)
        return f"[Decryption Failed: {str(e)}]"



@api_view(["GET"])
@permission_classes([IsAuthenticated])
def inbox_api(request):
    """
    Return decrypted messages for the logged-in user.
    Distinguishes text messages from file messages.
    """
    import base64
    from .models import EncryptedFile, Message

    try:
        inbox_messages = Message.objects.filter(receiver=request.user).order_by("-created_at")
        inbox_messages.filter(status="sent").update(status="delivered")

        data = []
        for m in inbox_messages:
            # Detect file message
            if isinstance(m.encrypted_text, str) and m.encrypted_text.startswith("[File attachment:"):
                result = decrypt_file_for_message(m)
                if isinstance(result, tuple):
                    filename, file_bytes = result
                    file_b64 = base64.b64encode(file_bytes).decode("utf-8")
                    plain = f"[File: {filename}] (Base64 attached)"
                else:
                    plain = result
            else:
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
                "status": getattr(m, "status", None)
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

import base64
from cryptography.fernet import Fernet

import base64
from cryptography.fernet import Fernet

def decrypt_message_api(encrypted_text, classification=None, private_key=None):
    """
    Core decryption helper — decrypts encrypted text or file data using Fernet.
    Works for both normal messages and file attachments.
    """
    import base64
    from cryptography.fernet import Fernet

    try:
        if not private_key:
            raise ValueError("Missing private key for decryption")

        # Initialize Fernet
        fernet = Fernet(private_key.encode())

        # ensure encrypted_text is string
        if isinstance(encrypted_text, bytes):
            encrypted_text = encrypted_text.decode("utf-8")

        # 🔓 Perform decryption
        decrypted_b64 = fernet.decrypt(encrypted_text.encode("utf-8"))

        try:
            # Try decoding as base64 (for files)
            decrypted_data = base64.b64decode(decrypted_b64)
            # Attempt to decode to text if it's readable, else keep raw bytes
            try:
                return decrypted_data.decode("utf-8")
            except UnicodeDecodeError:
                return decrypted_data  # return bytes for binary file content
        except Exception:
            # Not base64 data — return as string
            return decrypted_b64.decode("utf-8")

    except Exception as e:
        return f"[Decryption Failed: {str(e)}]"


    

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def update_status(request, message_id):
    """
    Update message status:
      - If current user is the receiver and sends {"seen": true} -> set status = "seen"
      - Otherwise, if the receiver hits this endpoint without seen flag and the message is "sent",
        update it to "delivered" (used when receiver fetches messages or opens chat)
    Returns: {"status": "<new_status>", "message_id": <id>}
    """
    try:
        msg = Message.objects.get(id=message_id)

        # Only the receiver is allowed to change delivered/seen state
        if msg.receiver != request.user:
            return Response({"error": "Not authorized"}, status=status.HTTP_403_FORBIDDEN)

        # If receiver explicitly marked seen
        if request.data.get("seen") is True:
            new_status = "seen"
        else:
            # Default: move sent -> delivered (if needed)
            if msg.status == "sent":
                new_status = "delivered"
            else:
                new_status = msg.status

        # persist
        msg.status = new_status
        msg.save(update_fields=["status"])

        # Return the new status so frontends can update the UI immediately
        return Response({"status": new_status, "message_id": msg.id}, status=status.HTTP_200_OK)

    except Message.DoesNotExist:
        return Response({"error": "Message not found"}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        logger.exception("update_status error: %s", e)
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_message_statuses(request):
    """
    Return all message IDs and statuses between the current user and ?user=<username>
    Used for polling ticks.
    """
    other_username = request.GET.get("user")
    if not other_username:
        return Response([], status=status.HTTP_200_OK)

    try:
        other_user = User.objects.get(username=other_username)
    except User.DoesNotExist:
        return Response([], status=status.HTTP_200_OK)

    msgs = Message.objects.filter(
        sender__in=[request.user, other_user],
        receiver__in=[request.user, other_user]
    ).values("id", "status")

    return Response(list(msgs), status=status.HTTP_200_OK)


import hashlib

# ---------- 🔐 HASH FEATURE ----------

import hashlib

def generate_hash(text: str) -> str:
    """Generate a SHA-256 hash for the given text."""
    return hashlib.sha256(text.encode()).hexdigest()
 
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_hash(request, message_id):
    """
    Return the SHA-256 hash value of a specific message.
    Accessible only by the sender or receiver of that message.
    """
    try:
        msg = Message.objects.get(id=message_id)

        # Security check: allow only sender or receiver
        if msg.sender != request.user and msg.receiver != request.user:
            return Response({"error": "Not authorized"}, status=status.HTTP_403_FORBIDDEN)

        # If hash not yet computed (rare), recompute on the fly
        if not msg.hash_value:
            try:
                decrypted = decrypt_message(msg.encrypted_text, msg.classification, msg.private_key)
                msg.hash_value = generate_hash(decrypted)
                msg.save(update_fields=["hash_value"])
            except Exception:
                msg.hash_value = "Hash unavailable"

        return Response({"hash": msg.hash_value}, status=status.HTTP_200_OK)
    

    except Message.DoesNotExist:
        return Response({"error": "Message not found"}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        logger.exception("get_hash error: %s", e)
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



def logoutpage(request):
    logout(request)
    messages.success(request, "You have been logged out successfully.")
    return redirect('loginpage')


from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .forms import UserUpdateForm, ProfileUpdateForm

@login_required
def profilepage(request):
    if request.method == 'POST':
        user_form = UserUpdateForm(request.POST, instance=request.user)
        profile_form = ProfileUpdateForm(request.POST, request.FILES, instance=request.user.profile)

        if user_form.is_valid() and profile_form.is_valid():
            user_form.save()
            profile_form.save()
            return redirect('profilepage')
    else:
        user_form = UserUpdateForm(instance=request.user)
        profile_form = ProfileUpdateForm(instance=request.user.profile)

    return render(request, 'profilepage.html', {
        'user_form': user_form,
        'profile_form': profile_form,
    })


def aboutus(request):
    return render(request, 'aboutus.html')


