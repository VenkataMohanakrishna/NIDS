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

ALERT_THRESHOLD = 0.98  # Increased from 0.95 to reduce false positive noise
ATTACK_FLOW_THRESHOLD = 5  # Increased from 3 to require a stronger coordinated attack

# -------------------------------------------------
# Explainable AI Rules (Extracted from training)
# -------------------------------------------------

ATTACK_RULES = {
    "FLOODING": {
        "features": ["Flow Packets/s", "Flow Bytes/s", "Flow IAT Mean", "Flow Duration"],
        "reason": "Extremely high packet and byte rates with very short inter-arrival times, indicating flooding behavior typical of DoS/DDoS attacks.",
        "severity": "HIGH"
    },
    "SCANNING": {
        "features": ["Destination Port", "Flow Duration", "Total Fwd Packets"],
        "reason": "Multiple short-lived connections targeting different ports, consistent with port scanning activity.",
        "severity": "MEDIUM"
    },
    "BOTNET": {
        "features": ["Flow IAT Mean", "Active Mean", "Idle Mean"],
        "reason": "Regular and automated communication patterns with periodic idle-active cycles, suggesting botnet command-and-control behavior.",
        "severity": "CRITICAL"
    },
    "BRUTE_FORCE": {
        "features": ["Total Fwd Packets", "Flow Duration", "Flow Packets/s"],
        "reason": "Repeated connection attempts within a short duration, indicative of brute-force authentication attacks.",
        "severity": "HIGH"
    },
    "WEB_ATTACK": {
        "features": ["Packet Length Mean", "Packet Length Variance", "Flow Duration"],
        "reason": "Abnormal packet size patterns and irregular timing, consistent with application-layer web attacks.",
        "severity": "HIGH"
    },
    "BENIGN": {
        "features": [],
        "reason": "Traffic behavior is consistent with normal network activity and does not exhibit malicious characteristics.",
        "severity": "LOW"
    }
}

def generate_attack_explanation(predicted_label, confidence, original_features_row):
    rule = ATTACK_RULES.get(predicted_label, None)
    if rule is None:
        return {"severity": "UNKNOWN", "reason": "No explanation available.", "key_features": "None"}
    
    feature_values = {}
    for feat in rule["features"]:
        if feat in original_features_row:
            feature_values[feat] = float(round(float(original_features_row[feat]), 3))
    
    feat_str = ", ".join([f"{k}: {v}" for k, v in feature_values.items()]) if feature_values else "N/A"
            
    return {"severity": rule["severity"], "reason": rule["reason"], "key_features": feat_str}

attack_flows = []
results = []

print("========== Detection Results ==========\n")

for i, label in enumerate(labels):
    confidence = float(probs[i][pred_idx[i]])
    
    if label != "BENIGN" and confidence >= ALERT_THRESHOLD:
        attack_flows.append((i+1, label, confidence))
        prediction_final = label
    else:
        # Strict noise filtering: Force low-confidence attacks to BENIGN
        prediction_final = "BENIGN"
        if label != "BENIGN":
            print(f"Flow {i+1}: {label} Ignored (Confidence {confidence:.3f} < {ALERT_THRESHOLD})")
        else:
            print(f"Flow {i+1}: BENIGN | Confidence: {confidence:.3f}")

    # Generate explanation using unscaled feature row
    explanation = generate_attack_explanation(prediction_final, confidence, df.iloc[i])

    results.append({
        "Flow": i+1,
        "Prediction": prediction_final,
        "Confidence": round(float(confidence), 3),
        "Severity": explanation["severity"],
        "Reason": explanation["reason"],
        "Key_Features": explanation["key_features"]
    })

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