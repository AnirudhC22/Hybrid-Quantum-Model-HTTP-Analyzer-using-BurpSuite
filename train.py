"""
train.py — One-shot training script
Run this before starting api_server.py

Usage:
    python train.py
    python train.py --skip-qml      # skip QML training (faster)
    python train.py --samples 800   # samples per class
"""

import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(__file__))

from data.dataset_generator import generate_dataset
from utils.feature_extractor import batch_extract
from models.classical_ml import train as train_classical
from models.quantum_ml import QuantumClassifier


def main():
    parser = argparse.ArgumentParser(description="Train all detection models")
    parser.add_argument("--skip-qml",  action="store_true",
                        help="Skip quantum model training")
    parser.add_argument("--samples",   type=int, default=600,
                        help="Training samples per class (default 600)")
    parser.add_argument("--qml-sample", type=int, default=100,
                        help="Subsample size for QML training (default 100)")
    args = parser.parse_args()

    print("=" * 60)
    print(" Web Attack Detector — Training Pipeline")
    print("=" * 60)

    # 1. Generate dataset
    print(f"\n[1/3] Generating synthetic dataset ({args.samples} samples/class)…")
    df = generate_dataset(n_per_class=args.samples)
    print(f"      Total samples: {len(df)}")
    print(df["label"].value_counts().to_string())

    # 2. Train classical models
    print("\n[2/3] Training classical ML models…")
    ad, ac = train_classical(df, batch_extract)

    # 3. Train QML (optional)
    if args.skip_qml:
        print("\n[3/3] QML training skipped (--skip-qml flag).")
        print("      Set USE_QML=false when starting api_server.py")
    else:
        print(f"\n[3/3] Training Quantum Classifier (subsample={args.qml_sample})…")
        print("      This uses PennyLane's default.qubit simulator — may take a few minutes.\n")
        records = df.to_dict("records")
        X       = batch_extract(records)
        y       = df["label"].values
        qc = QuantumClassifier()
        qc.fit(X, y, sample_size=args.qml_sample)
        qc.save()

    print("\n" + "=" * 60)
    print(" Training complete! Saved to ./models/")
    print(" Next step: python api_server.py")
    print("=" * 60)


if __name__ == "__main__":
    main()
