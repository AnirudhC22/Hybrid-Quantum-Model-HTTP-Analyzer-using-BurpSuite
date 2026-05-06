"""
Detection Engine  (v2 — improved ensemble with QML)

Key improvements over v1:
  - QML fires when classical confidence < 85% (was 60%)
  - Weighted ensemble: weights classical and quantum by their confidence
  - Smarter anomaly/classification fusion
"""

import numpy as np
from utils.feature_extractor import extract_features
from models.classical_ml import AnomalyDetector, AttackClassifier
from models.quantum_ml import QuantumClassifier, CONFIDENCE_GATE

BENIGN_LABEL = "normal"


class DetectionEngine:
    """
    Orchestrates the full detection pipeline:
      1. Feature extraction  (30 domain-agnostic features)
      2. Anomaly detection   (unsupervised zero-day gate)
      3. Classical classification  (RF + XGBoost + SVM ensemble)
      4. Quantum escalation  (VQC when classical confidence < 85%)
      5. Weighted ensemble decision

    WHY THE QUANTUM STAGE IS NEEDED:
      The classical ensemble (RF + XGB + SVM) all operate on the same
      feature space with similar inductive biases.  When all three agree
      with high confidence, the verdict is reliable.  But when confidence
      is low (<85%), it means the sample sits in an ambiguous region of
      feature space — possibly a novel attack, an obfuscated payload,
      or an unusual benign request.

      The Variational Quantum Classifier provides a fundamentally
      different decision boundary by operating in a 2^4 = 16 dimensional
      Hilbert space.  This higher-dimensional representation can separate
      classes that are entangled in the original 30-D feature space.

      By ensembling classical + quantum predictions (weighted by their
      respective confidences), we get a more robust final verdict that
      is harder for attackers to evade.
    """

    def __init__(self, use_qml: bool = True):
        self.use_qml  = use_qml
        self.anomaly  = AnomalyDetector.load()
        self.classical = AttackClassifier.load()
        self.qml      = None
        if use_qml:
            try:
                self.qml = QuantumClassifier.load()
            except (FileNotFoundError, Exception) as e:
                print(f"[Engine] QML model not available: {e}")
                self.qml = None

    # ── core ────────────────────────────────────────────────────────────────

    def analyze(self, raw_request: dict) -> dict:
        """
        Analyze a single HTTP request dict.

        Parameters
        ----------
        raw_request : dict
            Keys: url, params, headers, method

        Returns
        -------
        dict with keys:
            is_malicious : bool
            label        : str   attack type or 'normal'
            confidence   : float 0-100 percentage
            stage        : str   which stage produced the verdict
            details      : dict  per-stage outputs
        """
        X = extract_features(raw_request).reshape(1, -1)

        details = {}

        # ── Stage 2: anomaly detection ──────────────────────────────────
        is_anomaly = bool(self.anomaly.predict(X)[0])
        details["anomaly_flag"] = is_anomaly

        # ── Stage 3: classical classification ───────────────────────────
        cl_labels, cl_confs = self.classical.predict(X)
        cl_label = cl_labels[0]
        cl_conf  = float(cl_confs[0])
        details["classical"] = {"label": cl_label, "confidence": cl_conf}

        # ── Stage 4: QML escalation ─────────────────────────────────────
        qml_label, qml_conf = None, None
        used_qml = False

        if self.use_qml and self.qml and cl_conf < CONFIDENCE_GATE:
            try:
                q_labels, q_confs = self.qml.predict(X)
                qml_label = q_labels[0]
                qml_conf  = float(q_confs[0])
                used_qml  = True
                details["quantum"] = {"label": qml_label, "confidence": qml_conf}
            except Exception as e:
                details["quantum_error"] = str(e)

        # ── Stage 5: ensemble decision ──────────────────────────────────
        if used_qml and qml_conf is not None:
            # Weighted ensemble: weight each model by its confidence
            cl_proba  = self.classical.predict_proba(X)[0]
            qml_proba = self.qml.predict_proba(X)[0]

            # Weight: classical gets cl_conf weight, quantum gets qml_conf
            w_cl  = cl_conf
            w_qml = qml_conf
            w_total = w_cl + w_qml
            avg_proba = (w_cl * cl_proba + w_qml * qml_proba) / w_total

            from models.quantum_ml import LABEL_ORDER
            final_idx   = int(avg_proba.argmax())
            final_label = LABEL_ORDER[final_idx]
            final_conf  = float(avg_proba[final_idx])
            stage = "ensemble (classical + quantum)"
        else:
            final_label = cl_label
            final_conf  = cl_conf
            stage = "classical"

        # ── Override: anomaly + classified normal → suspicious ──────────
        if is_anomaly and final_label == BENIGN_LABEL:
            final_label = "suspicious (zero-day?)"
            final_conf  = max(final_conf, 0.65)
            stage       = "anomaly detector"

        is_malicious = final_label != BENIGN_LABEL

        return {
            "is_malicious": is_malicious,
            "label":        final_label,
            "confidence":   round(final_conf * 100, 1),   # as percentage
            "stage":        stage,
            "details":      details,
        }

    def analyze_batch(self, requests: list) -> list:
        return [self.analyze(r) for r in requests]
