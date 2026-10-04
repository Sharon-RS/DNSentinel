"""
DNSentinel Phase 6D: Machine Learning Model Architectures and Serialization.

Implements model training, feature vector extraction (ML30 vs ML31),
probability calibration interfaces, and joblib artifact serialization.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import joblib

from experiments.ml.causal_extractor import CausalMLFeatureExtractor


ML30_FEATURE_NAMES: List[str] = CausalMLFeatureExtractor.FEATURE_NAMES[:30]
ML31_FEATURE_NAMES: List[str] = CausalMLFeatureExtractor.FEATURE_NAMES[:]


def extract_feature_matrix(
    records: List[Dict[str, Any]],
    feature_names: List[str]
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Extracts a 2D numpy feature matrix X and 1D label array y from JSONL records.
    """
    X = np.zeros((len(records), len(feature_names)), dtype=np.float64)
    y = np.zeros(len(records), dtype=np.int64)

    for i, r in enumerate(records):
        f_dict = r["features"]
        y[i] = int(r["label"])
        for j, fname in enumerate(feature_names):
            X[i, j] = float(f_dict.get(fname, 0.0))

    return X, y


class DNSentinelClassifier:
    """
    Encapsulates a supervised Random Forest classifier for DNSentinel.
    Configured deterministically with random_state=42.
    """

    def __init__(
        self,
        name: str,
        feature_names: List[str],
        n_estimators: int = 100,
        max_depth: Optional[int] = 12,
        min_samples_split: int = 5,
        min_samples_leaf: int = 2,
        random_state: int = 42,
    ):
        self.name = name
        self.feature_names = feature_names
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            min_samples_split=min_samples_split,
            min_samples_leaf=min_samples_leaf,
            random_state=random_state,
            n_jobs=1,  # Strict single-thread determinism
        )
        self.is_fitted = False

    def fit(self, X: np.ndarray, y: np.ndarray) -> "DNSentinelClassifier":
        """Fits the underlying Random Forest model."""
        self.model.fit(X, y)
        self.is_fitted = True
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """
        Returns predicted probability for positive class (malicious, label=1).
        """
        if not self.is_fitted:
            raise RuntimeError(f"Model {self.name} is not fitted yet.")
        probs = self.model.predict_proba(X)
        if probs.shape[1] == 2:
            return probs[:, 1]
        elif probs.shape[1] == 1:
            # Degenerate single-class edge case
            only_class = self.model.classes_[0]
            return np.ones(len(X)) if only_class == 1 else np.zeros(len(X))
        return probs[:, 1]

    def predict(self, X: np.ndarray, threshold: float = 0.5) -> np.ndarray:
        """Binary predictions using specified decision threshold."""
        prob_positive = self.predict_proba(X)
        return (prob_positive >= threshold).astype(np.int64)

    def get_feature_importances(self) -> Dict[str, float]:
        """Returns mapping of feature names to Gini importance scores."""
        if not self.is_fitted:
            raise RuntimeError(f"Model {self.name} is not fitted yet.")
        importances = self.model.feature_importances_
        return {
            name: round(float(imp), 6)
            for name, imp in sorted(
                zip(self.feature_names, importances),
                key=lambda x: x[1],
                reverse=True
            )
        }

    def save(self, filepath: Path) -> None:
        """Serializes fitted model and feature metadata to disk."""
        filepath.parent.mkdir(parents=True, exist_ok=True)
        artifact = {
            "name": self.name,
            "feature_names": self.feature_names,
            "is_fitted": self.is_fitted,
            "model": self.model,
        }
        joblib.dump(artifact, filepath)

    @classmethod
    def load(cls, filepath: Path) -> "DNSentinelClassifier":
        """Loads serialized model artifact."""
        artifact = joblib.load(filepath)
        clf = cls(name=artifact["name"], feature_names=artifact["feature_names"])
        clf.is_fitted = artifact["is_fitted"]
        clf.model = artifact["model"]
        return clf


def build_and_train_ml30(
    train_records: List[Dict[str, Any]],
    random_state: int = 42
) -> DNSentinelClassifier:
    """Trains the ML30 model (30 raw causal features, excluding behavior_score)."""
    X_train, y_train = extract_feature_matrix(train_records, ML30_FEATURE_NAMES)
    clf = DNSentinelClassifier(
        name="ML30_RandomForest",
        feature_names=ML30_FEATURE_NAMES,
        random_state=random_state
    )
    clf.fit(X_train, y_train)
    return clf


def build_and_train_ml31(
    train_records: List[Dict[str, Any]],
    random_state: int = 42
) -> DNSentinelClassifier:
    """Trains the ML31 model (all 31 causal features, including behavior_score)."""
    X_train, y_train = extract_feature_matrix(train_records, ML31_FEATURE_NAMES)
    clf = DNSentinelClassifier(
        name="ML31_RandomForest",
        feature_names=ML31_FEATURE_NAMES,
        random_state=random_state
    )
    clf.fit(X_train, y_train)
    return clf
