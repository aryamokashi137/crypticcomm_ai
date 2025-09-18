# ml/views.py
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
import json

# Local model path
MODEL_PATH = "ml/msg_classifier_model"

# Load tokenizer & model from local files only
tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH, local_files_only=True)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH, local_files_only=True)
model.eval()

# Run on CPU for local dev
device = torch.device("cpu")
model.to(device)

# Map model raw labels to application confidentiality
LABEL_TO_CONF = {
    "LABEL_0": "high",
    "LABEL_1": "low",
    "LABEL_2": "medium",
    # add/change if your model uses different LABEL_X names
}

# Encryption text per confidentiality (returned to frontend)
ENCRYPTION_BY_CONF = {
    "high": "RSA + AES Hybrid",
    "medium": "AES-256",
    "low": "Fernet"
}

@csrf_exempt
def classify_view(request):
    """
    Accepts POST (form or JSON) or GET with ?message=...
    Returns JSON:
    {
      "label": "LABEL_0",
      "index": 0,
      "mapped_conf": "high",
      "probs": [0.99, 0.003, 0.005],
      "encryption": "RSA + AES Hybrid"
    }
    """
    try:
        # 1) get message string from POST form, POST JSON, or GET
        message = ""
        if request.method == "POST":
            message = request.POST.get("message", "").strip()
            if not message:
                # try JSON body
                try:
                    body = request.body.decode("utf-8")
                    if body:
                        data = json.loads(body)
                        if isinstance(data, dict):
                            message = (data.get("message") or "").strip()
                except Exception:
                    message = ""
        else:
            message = (request.GET.get("message", "") or "").strip()

        if not message:
            return JsonResponse({"error": "No message provided"}, status=400)

        # 2) tokenize + infer
        inputs = tokenizer(message, return_tensors="pt", truncation=True, padding=True)
        inputs = {k: v.to(device) for k, v in inputs.items()}
        with torch.no_grad():
            outputs = model(**inputs)
            logits = outputs.logits
            probs = torch.nn.functional.softmax(logits, dim=-1)

        pred_index = int(torch.argmax(logits, dim=1).item())
        probs_list = probs.cpu().numpy().tolist()[0]

        # 3) raw label (from model config if available)
        raw_label = None
        if hasattr(model.config, "id2label") and isinstance(model.config.id2label, dict):
            raw_label = model.config.id2label.get(pred_index, f"LABEL_{pred_index}")
        else:
            raw_label = f"LABEL_{pred_index}"

        # 4) map to app-level confidentiality and encryption text
        mapped_conf = LABEL_TO_CONF.get(raw_label, "low")  # default low if unknown
        encryption = ENCRYPTION_BY_CONF.get(mapped_conf, "Fernet")

        # 5) return full debug + mapped response
        return JsonResponse({
            "label": raw_label,
            "index": pred_index,
            "mapped_conf": mapped_conf,
            "probs": probs_list,
            "encryption": encryption
        })
    except Exception as e:
        # return error text so you can see what went wrong
        return JsonResponse({"error": str(e)}, status=500)
