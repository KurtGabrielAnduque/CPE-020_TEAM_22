import numpy as np
import tensorflow as tf
from tensorflow.keras.layers import TextVectorization
import joblib
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

print("Loading model...")
model = tf.keras.models.load_model(
    os.path.join(BASE_DIR, 'model', 'updated_url_detector_model.keras')
)

print("Loading vocabulary...")
vocab = joblib.load(
    os.path.join(BASE_DIR, 'vocab', 'vectorizer_vocab.pkl')
)

# Rebuild vectorizer with saved vocab
vectorize_layer = TextVectorization(
    standardize=None,
    split='character',
    output_mode='int',
    max_tokens=200,
    output_sequence_length=200
)
vectorize_layer.set_vocabulary(vocab)
print("✅ Model and vocab loaded!")

def predict(url, features):
    try:
        url_input    = np.array([url], dtype=object)
        struct_input = np.array([list(features.values())], dtype=np.float32)

        print("url_input shape:", url_input.shape)
        print("struct_input shape:", struct_input.shape)
        print("struct_input dtype:", struct_input.dtype)

        pred = model.predict([url_input, struct_input], verbose=0)[0][0]
        print("Prediction:", pred)

        return {
            "is_phishing": bool(pred > 0.5),
            "confidence":  round(float(pred), 4)
        }
    except Exception as e:
        print("Prediction error:", e)
        return None