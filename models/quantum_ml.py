"""
Quantum ML Module  (Stage 4)
Variational Quantum Classifier using PennyLane.
Only invoked when classical model confidence < CONFIDENCE_GATE (85%).

Why Quantum ML is needed:
  1. COMPLEMENTARY DECISION BOUNDARIES — VQC operates in a quantum Hilbert
     space that can represent decision boundaries exponentially more complex
     than classical hyperplanes.  When the classical ensemble is uncertain
     (confidence < 85%), it means the sample sits near a decision boundary
     where the three classical models disagree.  The quantum circuit, with
     its different inductive bias, can often resolve this disagreement.

  2. KERNEL ADVANTAGE — The angle-encoded VQC implicitly computes a kernel
     function in a 2^N-dimensional Hilbert space (here 2^4 = 16 dims).
     This gives it access to feature interactions that classical models
     with polynomial kernels may miss, especially for obfuscated or
     novel attack patterns that combine features from multiple attack types.

  3. ENSEMBLE DIVERSITY — Combining heterogeneous models (classical trees +
     SVMs + quantum circuits) reduces correlated errors.  The quantum model
     makes fundamentally different errors than classical models because its
     parameterised circuit learns a different representation of the data.

  4. ADVERSARIAL ROBUSTNESS — Attackers who study classical ML defences
     craft payloads to sit exactly on classical decision boundaries.
     The quantum circuit provides an orthogonal defence that is harder
     to reverse-engineer and evade.

Fix: use pnp (pennylane.numpy) throughout the loss function so
     autograd can differentiate through it correctly.
"""

import os
import numpy as np
import joblib
import pennylane as qml
import pennylane.numpy as pnp
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.decomposition import PCA

CONFIDENCE_GATE = 0.85          # was 0.60 — lowered so QML actually fires
N_QUBITS        = 4
N_LAYERS        = 3
N_FEATURES_QML  = N_QUBITS
MAX_ITER        = 100           # was 80 — more iterations for better convergence
LABEL_ORDER     = ["normal", "sqli", "xss", "cmdi", "traversal"]
MODEL_DIR       = os.path.join(os.path.dirname(__file__), "..", "models")

dev = qml.device("default.qubit", wires=N_QUBITS)


# ─────────────────────────────────────────────────────────────────────────────
#  Quantum circuit
# ─────────────────────────────────────────────────────────────────────────────

@qml.qnode(dev, interface="autograd")
def _circuit(inputs, weights):
    """Angle-encoded variational circuit."""
    for i in range(N_QUBITS):
        qml.RY(inputs[i] * np.pi, wires=i)
    for layer in range(N_LAYERS):
        for i in range(N_QUBITS):
            qml.RY(weights[layer, i, 0], wires=i)
            qml.RZ(weights[layer, i, 1], wires=i)
        for i in range(N_QUBITS - 1):
            qml.CNOT(wires=[i, i + 1])
    return qml.expval(qml.PauliZ(0))


# ─────────────────────────────────────────────────────────────────────────────
#  Loss — must use pnp so autograd tracks gradients
# ─────────────────────────────────────────────────────────────────────────────

def _loss(weights, X_batch, y_binary):
    """MSE loss using pnp so PennyLane autograd can differentiate."""
    preds = pnp.stack([_circuit(x, weights) for x in X_batch])
    return pnp.mean((preds - y_binary) ** 2)


# ─────────────────────────────────────────────────────────────────────────────
#  VQC Classifier  (One-vs-Rest)
# ─────────────────────────────────────────────────────────────────────────────

class QuantumClassifier:
    """
    One-vs-Rest VQC classifier.
    Trains one circuit per class; prediction = class with highest score.
    """

    def __init__(self):
        self.pca          = PCA(n_components=N_FEATURES_QML)
        self.scaler       = StandardScaler()
        self.le           = LabelEncoder()
        self.le.classes_  = np.array(LABEL_ORDER)
        self.weights_dict = {}
        self._fitted      = False

    def _train_one(self, X: np.ndarray, y_binary: np.ndarray) -> np.ndarray:
        """Train one binary VQC and return the optimised weights."""
        weights = pnp.random.uniform(
            -np.pi, np.pi, (N_LAYERS, N_QUBITS, 2), requires_grad=True
        )
        # Convert labels to pnp array so autograd is happy
        y_pnp = pnp.array(y_binary, requires_grad=False)

        opt = qml.AdamOptimizer(stepsize=0.05)
        for step in range(MAX_ITER):
            weights, loss = opt.step_and_cost(
                lambda w: _loss(w, X, y_pnp), weights
            )
            if step % 20 == 0:
                print(f"    step {step:3d}  loss={float(loss):.4f}")
        return np.array(weights)

    def fit(self, X: np.ndarray, y_labels: np.ndarray, sample_size: int = 150):
        """Fit OvR VQC on a random subsample for speed."""
        if len(X) > sample_size:
            idx = np.random.choice(len(X), sample_size, replace=False)
            X, y_labels = X[idx], y_labels[idx]

        Xs = self.scaler.fit_transform(X)
        Xp = self.pca.fit_transform(Xs)
        # Normalise to [0, 1] for angle encoding
        mn, mx = Xp.min(0), Xp.max(0)
        Xp = (Xp - mn) / (mx - mn + 1e-8)
        # Store for predict-time normalisation
        self._pca_min = mn
        self._pca_max = mx

        for label in LABEL_ORDER:
            print(f"\n  Training VQC for class '{label}' …")
            y_bin = np.where(y_labels == label, 1.0, -1.0)
            # Convert each row to a pnp array (required_grad=False for inputs)
            X_pnp = [pnp.array(row, requires_grad=False) for row in Xp]
            self.weights_dict[label] = self._train_one(X_pnp, y_bin)

        self._fitted = True
        return self

    def _transform(self, X: np.ndarray) -> list:
        """Scale + PCA + normalise + convert to list of pnp arrays."""
        Xs = self.scaler.transform(X)
        Xp = self.pca.transform(Xs)
        Xp = (Xp - self._pca_min) / (self._pca_max - self._pca_min + 1e-8)
        Xp = np.clip(Xp, 0, 1)
        return [pnp.array(row, requires_grad=False) for row in Xp]

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Returns softmaxed scores, shape (n, n_classes)."""
        if not self._fitted:
            raise RuntimeError("QuantumClassifier not fitted yet.")
        rows = self._transform(X)
        raw  = np.zeros((len(X), len(LABEL_ORDER)))
        for j, label in enumerate(LABEL_ORDER):
            w = self.weights_dict[label]
            raw[:, j] = [float(_circuit(x, w)) for x in rows]
        exp_raw = np.exp(raw - raw.max(axis=1, keepdims=True))
        return exp_raw / exp_raw.sum(axis=1, keepdims=True)

    def predict(self, X: np.ndarray) -> tuple:
        proba  = self.predict_proba(X)
        idx    = proba.argmax(axis=1)
        labels = self.le.inverse_transform(idx)
        confs  = proba.max(axis=1)
        return labels, confs

    def save(self):
        os.makedirs(MODEL_DIR, exist_ok=True)
        joblib.dump(self, os.path.join(MODEL_DIR, "quantum_classifier.pkl"))
        print("Quantum classifier saved.")

    @staticmethod
    def load() -> "QuantumClassifier":
        return joblib.load(os.path.join(MODEL_DIR, "quantum_classifier.pkl"))
