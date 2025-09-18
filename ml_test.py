# ml_test.py
# Place this file in your Django project root and run: python ml_test.py

import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

MODEL_PATH = "ml/msg_classifier_model"   # your local model folder

def print_info(text, tokenizer, model, device):
    print("\n" + "="*60)
    print("INPUT:", repr(text))
    toks = tokenizer(text, return_tensors="pt", truncation=True, padding=True)
    # move to device (CPU)
    toks = {k: v.to(device) for k, v in toks.items()}
    print("Token IDs:", toks["input_ids"].tolist())
    with torch.no_grad():
        outputs = model(**toks)
        logits = outputs.logits
        probs = torch.nn.functional.softmax(logits, dim=-1)
    logits_np = logits.cpu().numpy()
    probs_np = probs.cpu().numpy()
    print("Logits:", logits_np)
    print("Probs:", probs_np)
    pred_index = int(torch.argmax(logits, dim=1).item())
    print("Predicted index:", pred_index)

    # show config mapping if present
    cfg = model.config
    print("Model config.num_labels:", getattr(cfg, "num_labels", None))
    if hasattr(cfg, "id2label"):
        print("Model config.id2label:", cfg.id2label)
    elif hasattr(cfg, "label2id"):
        print("Model config.label2id:", cfg.label2id)
    else:
        print("No id2label/label2id in config.")

    # fallback labels you used
    fallback = ["normal", "sensitive", "highly_confidential"]
    fallback_label = fallback[pred_index] if pred_index < len(fallback) else "UNKNOWN"
    print("Fallback label mapping result:", fallback_label)

if __name__ == "__main__":
    device = torch.device("cpu")
    print("Loading tokenizer and model from:", MODEL_PATH)
    tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH, local_files_only=True)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH, local_files_only=True)
    model.to(device)
    model.eval()

    # Test the exact examples you mentioned
    print_info("23462757", tokenizer, model, device)
    print_info("hello", tokenizer, model, device)
    print("\nDone.")
