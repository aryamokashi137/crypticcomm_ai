from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

# Local path to your unzipped model folder
MODEL_PATH = "ml/msg_classifier_model"

# Load tokenizer and model from local folder
tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)

def classify_message(message: str):
    # Tokenize the message
    inputs = tokenizer(message, return_tensors="pt", truncation=True, padding=True)
    outputs = model(**inputs)

    # Get predicted class index
    predicted_class = torch.argmax(outputs.logits, dim=1).item()

    # Map index → label (update if your model has different labels!)
    labels = ["normal", "sensitive", "highly_confidential"]
    return labels[predicted_class]
