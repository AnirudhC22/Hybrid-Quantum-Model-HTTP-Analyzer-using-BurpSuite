"""
Classical ML Module
- Stage 2: Anomaly detection  (Isolation Forest + One-Class SVM)
- Stage 3: Attack classification (Random Forest + XGBoost + SVM)
"""

import os
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier, VotingClassifier
from sklearn.svm import OneClassSVM, SVC
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from xgboost import XGBClassifier

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "models")

LABEL_ORDER = ["normal", "sqli", "xss", "cmdi", "traversal"]


# ─────────────────────────────────────────────────────────────────────────────
#  Anomaly Detection  (Stage 2)
# ─────────────────────────────────────────────────────────────────────────────

class AnomalyDetector:
    """
    Unsupervised detector trained only on benign traffic.
    Returns True if a request looks anomalous (potential zero-day).
    """

    def __init__(self, contamination: float = 0.05):
        self.scaler   = StandardScaler()
        self.iso      = IsolationForest(contamination=contamination,
                                        n_estimators=200,
                                        random_state=42)
        self.ocsvm    = OneClassSVM(kernel="rbf", nu=contamination, gamma="scale")
        self._fitted  = False

    def fit(self, X_normal: np.ndarray):
        Xs = self.scaler.fit_transform(X_normal)
        self.iso.fit(Xs)
        self.ocsvm.fit(Xs)
        self._fitted = True
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Returns boolean array: True = anomalous."""
        if not self._fitted:
            raise RuntimeError("AnomalyDetector not fitted yet.")
        Xs = self.scaler.transform(X)
        iso_pred  = self.iso.predict(Xs)    # -1 = anomaly
        ocsvm_pred = self.ocsvm.predict(Xs) # -1 = anomaly
        # Flag only if BOTH models call it anomalous (reduces false positives)
        return (iso_pred == -1) & (ocsvm_pred == -1)

    def save(self):
        os.makedirs(MODEL_DIR, exist_ok=True)
        joblib.dump(self, os.path.join(MODEL_DIR, "anomaly_detector.pkl"))

    @staticmethod
    def load() -> "AnomalyDetector":
        return joblib.load(os.path.join(MODEL_DIR, "anomaly_detector.pkl"))


# ─────────────────────────────────────────────────────────────────────────────
#  Attack Classifier  (Stage 3)
# ─────────────────────────────────────────────────────────────────────────────

class AttackClassifier:
    """
    Supervised multi-class classifier.
    Combines Random Forest + XGBoost + SVM via soft-voting ensemble.
    """

    def __init__(self):
        self.scaler  = StandardScaler()
        self.le      = LabelEncoder()
        self.le.classes_ = np.array(LABEL_ORDER)

        rf  = RandomForestClassifier(n_estimators=200, max_depth=12,
                                     min_samples_leaf=2, random_state=42,
                                     n_jobs=-1)
        xgb = XGBClassifier(n_estimators=200, max_depth=6, learning_rate=0.1,
                             use_label_encoder=False, eval_metric="mlogloss",
                             random_state=42, verbosity=0)
        svm = SVC(kernel="rbf", C=10, gamma="scale", probability=True,
                  random_state=42)

        self.ensemble = VotingClassifier(
            estimators=[("rf", rf), ("xgb", xgb), ("svm", svm)],
            voting="soft",
        )
        self._fitted = False

    def fit(self, X: np.ndarray, y_labels: np.ndarray):
        Xs = self.scaler.fit_transform(X)
        y  = self.le.transform(y_labels)
        self.ensemble.fit(Xs, y)
        self._fitted = True
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Returns probability matrix shape (n, n_classes)."""
        if not self._fitted:
            raise RuntimeError("AttackClassifier not fitted yet.")
        return self.ensemble.predict_proba(self.scaler.transform(X))

    def predict(self, X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """Returns (label_strings, confidence_scores)."""
        proba  = self.predict_proba(X)
        idx    = proba.argmax(axis=1)
        labels = self.le.inverse_transform(idx)
        confs  = proba.max(axis=1)
        return labels, confs

    def evaluate(self, X: np.ndarray, y_labels: np.ndarray):
        labels, _ = self.predict(X)
        print(classification_report(y_labels, labels, target_names=LABEL_ORDER))
        print(f"Accuracy: {accuracy_score(y_labels, labels):.4f}")

    def save(self):
        os.makedirs(MODEL_DIR, exist_ok=True)
        joblib.dump(self, os.path.join(MODEL_DIR, "attack_classifier.pkl"))

    @staticmethod
    def load() -> "AttackClassifier":
        return joblib.load(os.path.join(MODEL_DIR, "attack_classifier.pkl"))


# ─────────────────────────────────────────────────────────────────────────────
#  Training script entry point
# ─────────────────────────────────────────────────────────────────────────────

def train(df, feature_extractor_fn):
    """
    Train both models from a labelled DataFrame.

    df must have columns: url, params, headers, method, label
    """
    print("Extracting features …")
    records = df.to_dict("records")
    X       = feature_extractor_fn(records)
    y       = df["label"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    # --- Anomaly detector (train on normal only) ---
    print("\nFitting anomaly detector …")
    X_normal = X_train[y_train == "normal"]
    ad = AnomalyDetector(contamination=0.01)
    ad.fit(X_normal)
    ad.save()
    print("Anomaly detector saved.")

    # --- Attack classifier ---
    print("\nFitting attack classifier (this may take a minute) …")
    ac = AttackClassifier()
    ac.fit(X_train, y_train)
    ac.save()
    print("Attack classifier saved.")

    print("\n=== Test set evaluation ===")
    ac.evaluate(X_test, y_test)

    return ad, ac
