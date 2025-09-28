from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

MODEL_PATH = "ml/msg_classifier_model"

tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH, local_files_only=True)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH, local_files_only=True)
model.eval()

device = torch.device("cpu")
model.to(device)

LABEL_TO_CONF = {
    "LABEL_0": "high",
    "LABEL_1": "low",
    "LABEL_2": "medium",
}

ENCRYPTION_BY_CONF = {
    "high": "RSA + AES Hybrid",
    "medium": "AES-256",
    "low": "Fernet"
}

def classify_message(message: str):
    inputs = tokenizer(message, return_tensors="pt", truncation=True, padding=True)
    inputs = {k: v.to(device) for k, v in inputs.items()}
    with torch.no_grad():
        outputs = model(**inputs)
        logits = outputs.logits
        probs = torch.nn.functional.softmax(logits, dim=-1)

    pred_index = int(torch.argmax(logits, dim=1).item())
    probs_list = probs.cpu().numpy().tolist()[0]

    raw_label = None
    if hasattr(model.config, "id2label") and isinstance(model.config.id2label, dict):
        raw_label = model.config.id2label.get(pred_index, f"LABEL_{pred_index}")
    else:
        raw_label = f"LABEL_{pred_index}"

    mapped_conf = LABEL_TO_CONF.get(raw_label, "low")
    encryption = ENCRYPTION_BY_CONF.get(mapped_conf, "Fernet")

    return {
        "label": raw_label,
        "index": pred_index,
        "mapped_conf": mapped_conf,
        "probs": probs_list,
        "encryption": encryption
    }
