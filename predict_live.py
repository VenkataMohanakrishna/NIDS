import pandas as pd
import numpy as np
import joblib
from tensorflow.keras.models import load_model

print("====================================")
print("   Deep Learning NIDS - Live Scan")
print("====================================\n")

# -------------------------------------------------
# Load trained artifacts
# -------------------------------------------------

print("Loading trained artifacts...")

model = load_model("nids_lstm_model.keras")
scaler = joblib.load("nids_scaler.pkl")
label_encoder = joblib.load("nids_label_encoder.pkl")

print("Artifacts loaded successfully\n")

# -------------------------------------------------
# Read flow file
# -------------------------------------------------

print("Reading flow file...")

df = pd.read_csv("live_flows_basic.csv")

print("Flows loaded:", len(df))

# -------------------------------------------------
# Feature alignment
# -------------------------------------------------

feature_columns = scaler.feature_names_in_

for col in feature_columns:
    if col not in df.columns:
        df[col] = 0

df = df[feature_columns]

print("Feature alignment complete\n")

# -------------------------------------------------
# Scaling
# -------------------------------------------------

scaled = scaler.transform(df)

# LSTM reshape
X = scaled.reshape(len(df), 1, scaled.shape[1])

# -------------------------------------------------
# Prediction
# -------------------------------------------------

print("Running intrusion detection...\n")

probs = model.predict(X)

pred_idx = np.argmax(probs, axis=1)

labels = label_encoder.inverse_transform(pred_idx)

# -------------------------------------------------
# Alert filtering + correlation
# -------------------------------------------------

ALERT_THRESHOLD = 0.95
ATTACK_FLOW_THRESHOLD = 3

attack_flows = []
results = []

print("========== Detection Results ==========\n")

for i, label in enumerate(labels):

    confidence = float(probs[i][pred_idx[i]])

    results.append({
        "Flow": i+1,
        "Prediction": label,
        "Confidence": round(confidence,3)
    })

    if label != "BENIGN" and confidence >= ALERT_THRESHOLD:

        attack_flows.append((i+1, label, confidence))

    else:

        print(f"Flow {i+1}: BENIGN | Confidence: {confidence:.3f}")

print("\n----------------------------------")

# -------------------------------------------------
# Attack correlation logic
# -------------------------------------------------

if len(attack_flows) >= ATTACK_FLOW_THRESHOLD:

    print("⚠ NETWORK ATTACK DETECTED\n")

    for flow_id, attack, conf in attack_flows:

        print(f"Flow {flow_id} | Attack: {attack} | Confidence: {conf:.3f}")

else:

    print("No coordinated attack detected")
    print("Suspicious flows ignored as noise")

print("\nDetection completed.")

# -------------------------------------------------
# Save predictions for dashboard
# -------------------------------------------------

results_df = pd.DataFrame(results)

results_df.to_csv("prediction_results.csv", index=False)

print("Prediction results saved to prediction_results.csv")