# ml/model_service.py
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
import logging
import os

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

MODEL_PATH = os.path.join(os.path.dirname(__file__), "msg_classifier_model")

# Load tokenizer & model
tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH, local_files_only=True)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH, local_files_only=True)
model.eval()

device = torch.device("cpu")
model.to(device)

# --- Explicit mapping for your model ---
# Based on your old classifier: LABEL_0=high, LABEL_1=low, LABEL_2=medium
LABEL_NAME_TO_CONF = {
    "LABEL_0": "high",
    "LABEL_1": "low",
    "LABEL_2": "medium",
}

# If you ever retrain and know the numeric index order, you can also set:
LABEL_INDEX_ORDER = None
# LABEL_INDEX_ORDER = {0: "high", 1: "low", 2: "medium"}

# stable mapping for substring detection
def _map_label_name_to_conf(label_name: str):
    if not label_name:
        return None
    ln = label_name.lower()
    if "low" in ln:
        return "low"
    if "medium" in ln:
        return "medium"
    if "high" in ln or "sensitive" in ln or "highly" in ln:
        return "high"
    return None

# Log the model label info for debugging at startup
try:
    cfg = getattr(model, "config", None)
    id2label = getattr(cfg, "id2label", None)
    num_labels = getattr(cfg, "num_labels", None)
    logger.debug("Model loaded from %s — num_labels=%s id2label=%s", MODEL_PATH, num_labels, id2label)
except Exception as e:
    logger.exception("Failed to read model config: %s", e)
    id2label = None
    num_labels = None

ENCRYPTION_BY_MAPPED = {
    "low": "Fernet",
    "medium": "AES-GCM",
    "high": "RSA+AES"
}

def classify_message(message: str):
    """
    Robust mapping:
     - Try to map using model.config.id2label (search substrings or explicit LABEL_X map)
     - Else, if LABEL_INDEX_ORDER is set, use that
     - Else fallback to safe default ordering [low, medium, high]
    """
    inputs = tokenizer(message, return_tensors="pt", truncation=True, padding=True)
    inputs = {k: v.to(device) for k, v in inputs.items()}
    with torch.no_grad():
        outputs = model(**inputs)
        logits = outputs.logits
        probs = torch.nn.functional.softmax(logits, dim=-1)

    pred_index = int(torch.argmax(logits, dim=1).item())
    probs_list = probs.cpu().numpy().tolist()[0]

    # 1) get raw label from config if possible
    raw_label_name = None
    cfg = getattr(model, "config", None)
    if cfg and hasattr(cfg, "id2label") and isinstance(cfg.id2label, dict):
        raw_label_name = cfg.id2label.get(pred_index, None)

    if not raw_label_name:
        raw_label_name = f"LABEL_{pred_index}"

    # 2) try mapping
    mapped_conf = _map_label_name_to_conf(raw_label_name)

    # 3) try explicit name mapping
    if not mapped_conf:
        mapped_conf = LABEL_NAME_TO_CONF.get(raw_label_name)

    # 4) try explicit index mapping
    if not mapped_conf and LABEL_INDEX_ORDER and pred_index in LABEL_INDEX_ORDER:
        mapped_conf = LABEL_INDEX_ORDER[pred_index]

    # 5) safe fallback
    if not mapped_conf:
        try:
            nlabels = int(getattr(model.config, "num_labels", len(probs_list)))
        except Exception:
            nlabels = len(probs_list)
        if nlabels == 3:
            default_order = {0: "low", 1: "medium", 2: "high"}
            mapped_conf = default_order.get(pred_index, "low")
        else:
            mapped_conf = "low"

    encryption = ENCRYPTION_BY_MAPPED.get(mapped_conf, "Fernet")

    logger.debug("classify_message -> pred_index=%s raw_label=%s mapped_conf=%s probs=%s",
                 pred_index, raw_label_name, mapped_conf, probs_list)

    return {
        "label_raw": raw_label_name,
        "index": pred_index,
        "mapped_conf": mapped_conf,
        "probs": probs_list,
        "encryption": encryption
    }
