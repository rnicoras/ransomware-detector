from __future__ import annotations
import sys
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)
import joblib

DATASET_DIR = Path("C:/Users/User/Desktop/napierone")
FEATURES_CSV = DATASET_DIR / "features.csv"
MODEL_OUTPUT = Path(__file__).parent.parent / "models" / "ransomware_detector.joblib"
FEATURE_COLUMNS = ["entropy", "filesize", "chi_square", "magicbyte"]

def main():
    if not FEATURES_CSV.exists():
        print(f"Features file not found {FEATURES_CSV}")
        sys.exit(1)

    df = pd.read_csv(FEATURES_CSV)
    print(f"Loaded {len(df)} samples")
    print(f"Benign: {len(df[df['label'] == 0])}")
    print(f"Ransomware: {len(df[df['label'] == 1])}")
    x = df[FEATURE_COLUMNS].values # features
    y = df["label"].values # labels
    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=42, stratify=y)
    print(f"Train: {len(x_train)}")
    print(f"Test: {len(x_test)}")
    print("Start training")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(x_train, y_train)
    print("Finished training")

    # evaluate on test set
    y_pred = model.predict(x_test)
    accuracy = accuracy_score(y_test, y_pred) # out of all files tested how many did the model get right
    precision = precision_score(y_test, y_pred) # how many files did the model classify correctly as ransomware
    recall = recall_score(y_test, y_pred) # how many ransomware files did the model catch
    f1 = f1_score(y_test, y_pred) # harmonic mean of precision and recall
    cm = confusion_matrix(y_test, y_pred) 
    print("Test set results")
    print(f"Accuracy {accuracy:.4f}")
    print(f"Precision {precision:.4f}")
    print(f"Recall {recall:.4f}")
    print(f"F1 {f1:.4f}")
    print("\n Confusion matrix: ")
    print(f"TN={cm[0][0]} FP={cm[0][1]}")
    print(f"FN={cm[1][0]} TP={cm[1][1]}")
    print(f"\n{classification_report(y_test, y_pred, target_names=['benign', 'ransomware'])}")
    print("Cross validation")
    cv_scores = cross_val_score(model, x, y, cv=5, scoring="f1")
    print(f"F1 scores: {[f'{score:.4f}' for score in cv_scores]}")
    print(f"Mean F1: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
    print("Feature importance")
    for name, importance in sorted(zip(FEATURE_COLUMNS, model.feature_importances_), key=lambda x: x[1], reverse=True):
        print(f"{name:15s} {importance:.4f} ({importance * 100:.1f}%)")

    MODEL_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_OUTPUT)
    print(f"Model saved to {MODEL_OUTPUT}")

if __name__ == "__main__":
    main()