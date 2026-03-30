import numpy as np
import pandas as pd
import joblib
from tensorflow.keras.models import load_model
import tensorflow as tf
import os

print("Loading artifacts...")
model = load_model("nids_lstm_model.keras")
scaler = joblib.load("nids_scaler.pkl")
le = joblib.load("nids_label_encoder.pkl")
features = scaler.feature_names_in_

classes = le.classes_
print("Classes:", classes)

import warnings
warnings.filterwarnings('ignore')

print("Optimizing baseline BENIGN flow...")
benign_idx = list(classes).index('BENIGN')
x_var_benign = tf.Variable(np.random.normal(0, 1, size=(1, 1, len(features))).astype(np.float32))
opt_benign = tf.keras.optimizers.Adam(learning_rate=0.1)
target_benign = np.zeros((1, len(classes)), dtype=np.float32)
target_benign[0, benign_idx] = 1.0

for i in range(500):
    with tf.GradientTape() as tape:
        pred = model(x_var_benign)
        loss = tf.keras.losses.categorical_crossentropy(target_benign, pred)
    grads = tape.gradient(loss, x_var_benign)
    opt_benign.apply_gradients([(grads, x_var_benign)])
    if pred[0, benign_idx].numpy() > 0.99:
        break

x_benign_scaled = x_var_benign.numpy().reshape(1, -1)
x_benign_original = scaler.inverse_transform(x_benign_scaled)
print(f"  Reached confidence {model(x_var_benign).numpy()[0, benign_idx]:.4f} for BENIGN base flow")

for target_class_idx, class_name in enumerate(classes):
    if class_name == 'BENIGN':
        continue
    
    print(f"Optimizing for {class_name}...")
    
    while True:
        # Initialize a random input
        x_init = np.random.normal(0, 1, size=(1, 1, len(features))).astype(np.float32)
        x_var = tf.Variable(x_init)
        
        optimizer = tf.keras.optimizers.Adam(learning_rate=0.1)
        
        target_prob = np.zeros((1, len(classes)), dtype=np.float32)
        target_prob[0, target_class_idx] = 1.0
        
        for i in range(500):
            with tf.GradientTape() as tape:
                pred = model(x_var)
                loss = tf.keras.losses.categorical_crossentropy(target_prob, pred)
            
            grads = tape.gradient(loss, x_var)
            optimizer.apply_gradients([(grads, x_var)])
            
            if pred[0, target_class_idx].numpy() > 0.99:
                break

        final_pred = model(x_var).numpy()
        conf = final_pred[0, target_class_idx]
        
        if conf > 0.99:
            print(f"  Reached confidence {conf:.4f} for {class_name}")
            break
        else:
            print(f"  Only reached {conf:.4f}, retrying...")
    
    # Inverse transform to get original feature scales
    x_scaled = x_var.numpy().reshape(1, -1)
    x_original = scaler.inverse_transform(x_scaled)
    
    import random
    num_attack_flows = random.randint(5, 12)
    num_benign_flows = 20 - num_attack_flows
    
    # Create the randomized split of benign vs attack
    # For benign, add slight jitter to original scaled
    benign_rows = []
    for _ in range(num_benign_flows):
        jitter = np.random.normal(0, 0.05, size=x_benign_scaled.shape)
        benign_rows.append(scaler.inverse_transform(x_benign_scaled + jitter)[0])
        
    attack_rows = []
    for _ in range(num_attack_flows):
        # A tiny jitter on the scaled representation (0.01 std deviation) preserves the attack signature 
        # while changing the raw feature values so they aren't identical.
        jitter = np.random.normal(0, 0.02, size=x_scaled.shape)
        attack_rows.append(scaler.inverse_transform(x_scaled + jitter)[0])
        
    df_benign = pd.DataFrame(benign_rows, columns=features)
    df_attack = pd.DataFrame(attack_rows, columns=features)
    
    # Combine and shuffle
    df = pd.concat([df_benign, df_attack]).sample(frac=1).reset_index(drop=True)
    
    filename = f"synthetic_attack_{class_name.lower()}.csv"
    df.to_csv(filename, index=False)
    print(f"  Saved {filename}")

print("Done generating CSVs.")
