import os
import joblib
import numpy as np
import random
import re
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# --- CONFIGURATION ---
MODEL_DIR = "service/"
if not os.path.exists(MODEL_DIR):
    os.makedirs(MODEL_DIR)

print("🚀 Initializing OrgWatch AI Training Hub...")
np.random.seed(42)

# ==========================================
# 1. 0-DAY MALWARE (Static Analysis)
# ==========================================
print("\n[1/4] Training Malware Scanner (0-Day Static Analysis)...")

def generate_malware_dataset(n_samples=5000):
    """
    Features: [Sections, Imports, Exports, Entropy, ImageSize]
    """
    data, labels = [], []
    for _ in range(n_samples):
        if random.random() > 0.5:
            # Malware (Packed/Encrypted)
            data.append([
                random.randint(2, 5),          # Low Sections
                random.randint(0, 15),         # Few Imports (Hidden)
                0,                             # No Exports
                random.uniform(7.2, 7.99),     # High Entropy
                random.randint(15000, 150000)  # Small Payload
            ])
            labels.append(1)
        else:
            # Safe App
            data.append([
                random.randint(4, 10),         # Normal Sections
                random.randint(50, 200),       # Many Imports
                random.randint(0, 10),         # Exports
                random.uniform(4.5, 6.5),      # Normal Entropy
                random.randint(100000, 5000000)# Normal Size
            ])
            labels.append(0)
    return np.array(data), np.array(labels)

X_mal, y_mal = generate_malware_dataset()
clf_mal = RandomForestClassifier(n_estimators=100, max_depth=12)
clf_mal.fit(X_mal, y_mal)
joblib.dump(clf_mal, f"{MODEL_DIR}malware_model.pkl")
print(f"✅ Malware Model Saved. Accuracy: {accuracy_score(y_mal, clf_mal.predict(X_mal))*100:.2f}%")


# ==========================================
# 2. PHISHING DETECTION (Lexical URL Analysis)
# ==========================================
print("\n[2/4] Training Phishing Detection AI...")

def generate_phishing_dataset(n_samples=5000):
    """
    Features: [IP_Present, Length>54, TinyURL, @ Symbol, // Redirect, Dash, Dots, HTTPS_Token, Keywords, Padding... (Total 12)]
    """
    data, labels = [], []
    for _ in range(n_samples):
        if random.random() > 0.5:
            # Phishing URL
            data.append([
                random.choice([0, 1]), # IP
                1,                     # Long
                random.choice([0, 1]), # Shortener
                random.choice([0, 1]), # @
                random.choice([0, 1]), # //
                1,                     # Dash
                1,                     # Dots
                0,                     # Fake HTTPS
                1,                     # Keywords
                0,0,0                  # Padding
            ])
            labels.append(1)
        else:
            # Safe URL
            data.append([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            labels.append(0)
    return np.array(data), np.array(labels)

X_phish, y_phish = generate_phishing_dataset()
clf_phish = RandomForestClassifier(n_estimators=100, max_depth=12)
clf_phish.fit(X_phish, y_phish)
joblib.dump(clf_phish, f"{MODEL_DIR}phishing_model.pkl")
print(f"✅ Phishing Model Saved. Accuracy: {accuracy_score(y_phish, clf_phish.predict(X_phish))*100:.2f}%")


# ==========================================
# 3. BEHAVIORAL ANOMALY (Process Monitoring)
# ==========================================
print("\n[3/4] Training Behavioral Anomaly Engine (Unsupervised)...")

def generate_behavior_baseline(n_samples=2000):
    """Features: [CPU, RAM, Threads, Handles]"""
    rng = np.random.default_rng(42)
    cpu = rng.normal(loc=15, scale=10, size=(n_samples, 1))
    ram = rng.normal(loc=40, scale=10, size=(n_samples, 1))
    thr = rng.normal(loc=50, scale=20, size=(n_samples, 1))
    hnd = rng.normal(loc=200, scale=50, size=(n_samples, 1))
    return np.hstack((cpu, ram, thr, hnd))

X_beh = generate_behavior_baseline()
clf_beh = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
clf_beh.fit(X_beh)
joblib.dump(clf_beh, f"{MODEL_DIR}behavior_model.pkl")
print("✅ Behavior Model Saved (Isolation Forest).")


# ==========================================
# 4. NETWORK INTRUSION DETECTION (NIDS)
# ==========================================
print("\n[4/4] Training Network Intrusion Detection (NIDS)...")

def generate_nids_dataset(n_samples=5000):
    """
    Features: [Duration, Protocol, Src_Bytes, Dst_Bytes, Count, Srv_Count]
    """
    data, labels = [], []
    for _ in range(n_samples):
        rand = random.random()
        if rand > 0.8: # DoS Attack
            data.append([0, 1, 50, 50, 500, 500])
            labels.append(1)
        elif rand > 0.7: # Data Exfiltration
            data.append([500, 1, 50000, 200, 5, 5])
            labels.append(1)
        else: # Normal
            data.append([10, 1, 500, 2000, 10, 10])
            labels.append(0)
    return np.array(data), np.array(labels)

X_nids, y_nids = generate_nids_dataset()
clf_nids = RandomForestClassifier(n_estimators=100, max_depth=12)
clf_nids.fit(X_nids, y_nids)
joblib.dump(clf_nids, f"{MODEL_DIR}nids_model.pkl")
print(f"✅ NIDS Model Saved. Accuracy: {accuracy_score(y_nids, clf_nids.predict(X_nids))*100:.2f}%")

print("\n🎉 ALL SYSTEMS READY. Run 'npm run dev' to start the agent.")