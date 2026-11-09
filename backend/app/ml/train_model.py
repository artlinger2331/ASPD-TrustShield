"""
Training pipeline for TrustShield URL classification.
<<<<<<< HEAD
Supports Logistic Regression and Random Forest models with data cleaning,
deduplication, conflict resolution, stratified train/val/test splits,
full evaluation metrics, and ModelRegistry persistence.
=======
Supports Logistic Regression and Random Forest models with stratified
train/val/test splits, full evaluation metrics, and ModelRegistry persistence.
>>>>>>> 9b735eb99fcfab11611f7f8da03c77f43357eb91
"""

import argparse
import csv
<<<<<<< HEAD
from dataclasses import asdict, dataclass
=======
>>>>>>> 9b735eb99fcfab11611f7f8da03c77f43357eb91
import logging
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from app.ml.feature_extractor import FeatureSchemaV1, extract_features_vector
from app.ml.model_registry import ModelMetadata, ModelRegistry

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


<<<<<<< HEAD
@dataclass
class DataHygieneReport:
    raw_records: int
    clean_records: int
    duplicates_removed: int
    conflicts_dropped: int
    invalid_dropped: int
    class_distribution: Dict[str, int]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def load_dataset_from_csv(
    csv_path: Union[str, Path],
) -> Tuple[List[str], np.ndarray, DataHygieneReport]:
    """
    Loads, cleans, and deduplicates URLs and binary labels from CSV file.
    Resolves duplicate URLs and discards conflicting labels.
=======
def load_dataset_from_csv(csv_path: Union[str, Path]) -> Tuple[List[str], np.ndarray]:
    """
    Loads URLs and binary labels from CSV file.
    Accepted label formats:
      - 0, 1
      - "0", "1"
      - "benign", "legitimate" -> 0
      - "phishing", "malicious", "suspicious" -> 1
>>>>>>> 9b735eb99fcfab11611f7f8da03c77f43357eb91
    """
    path = Path(csv_path)
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found at {path}")

<<<<<<< HEAD
    raw_records = 0
    invalid_dropped = 0
    duplicates_removed = 0
    conflicts_dropped = 0

    url_map: Dict[str, Tuple[str, int]] = {}
    conflict_keys: set = set()
=======
    urls: List[str] = []
    labels: List[int] = []
>>>>>>> 9b735eb99fcfab11611f7f8da03c77f43357eb91

    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames or "url" not in reader.fieldnames or "label" not in reader.fieldnames:
            raise ValueError(f"CSV must contain 'url' and 'label' columns, got {reader.fieldnames}")

        for row_idx, row in enumerate(reader):
<<<<<<< HEAD
            raw_records += 1
=======
>>>>>>> 9b735eb99fcfab11611f7f8da03c77f43357eb91
            url_str = (row.get("url") or "").strip()
            raw_label = (row.get("label") or "").strip().lower()

            if not url_str:
<<<<<<< HEAD
                invalid_dropped += 1
=======
>>>>>>> 9b735eb99fcfab11611f7f8da03c77f43357eb91
                continue

            if raw_label in ("0", "benign", "legitimate", "safe"):
                label_val = 0
            elif raw_label in ("1", "phishing", "malicious", "suspicious", "threat"):
                label_val = 1
            else:
                try:
                    label_val = 1 if int(raw_label) > 0 else 0
                except ValueError:
<<<<<<< HEAD
                    invalid_dropped += 1
                    continue

            norm_key = url_str.rstrip("/")
            if norm_key in conflict_keys:
                conflicts_dropped += 1
                continue

            if norm_key in url_map:
                existing_url, existing_label = url_map[norm_key]
                if existing_label == label_val:
                    duplicates_removed += 1
                else:
                    logger.warning(
                        "Conflicting labels detected for URL '%s' (row %d: %d vs existing: %d). Dropping URL.",
                        url_str,
                        row_idx + 2,
                        label_val,
                        existing_label,
                    )
                    del url_map[norm_key]
                    conflict_keys.add(norm_key)
                    conflicts_dropped += 2
            else:
                url_map[norm_key] = (url_str, label_val)

    clean_urls: List[str] = [item[0] for item in url_map.values()]
    clean_labels: List[int] = [item[1] for item in url_map.values()]

    if not clean_urls:
        raise ValueError(f"No valid records remained in {csv_path} after data cleaning")

    y = np.array(clean_labels, dtype=int)
    class_0_count = int(np.sum(y == 0))
    class_1_count = int(np.sum(y == 1))

    hygiene_report = DataHygieneReport(
        raw_records=raw_records,
        clean_records=len(clean_urls),
        duplicates_removed=duplicates_removed,
        conflicts_dropped=conflicts_dropped,
        invalid_dropped=invalid_dropped,
        class_distribution={"benign (0)": class_0_count, "phishing (1)": class_1_count},
    )

    return clean_urls, y, hygiene_report


def extract_dataset_features(urls: List[str]) -> np.ndarray:
    """Extracts 20 features for each URL in urls list into a numpy array."""
    vectors: List[List[float]] = []
=======
                    raise ValueError(f"Invalid label '{raw_label}' at row {row_idx + 2}")

            urls.append(url_str)
            labels.append(label_val)

    if not urls:
        raise ValueError(f"No valid records found in {csv_path}")

    return urls, np.array(labels, dtype=int)


def extract_dataset_features(urls: List[str]) -> np.ndarray:
    """Extracts 42 features for each URL in urls list into a numpy array."""
    vectors: List[List[Union[int, float]]] = []
>>>>>>> 9b735eb99fcfab11611f7f8da03c77f43357eb91
    for url in urls:
        vec = extract_features_vector(url)
        vectors.append(vec)
    return np.array(vectors, dtype=float)


def compute_dataset_metrics(model: Any, X: np.ndarray, y: np.ndarray) -> Dict[str, Any]:
    """Computes accuracy, precision, recall, f1, roc-auc, and confusion matrix."""
    if len(y) == 0:
        return {}

    preds = model.predict(X)
    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(X)[:, 1]
    else:
        probs = preds.astype(float)

    acc = accuracy_score(y, preds)
    prec = precision_score(y, preds, zero_division=0)
    rec = recall_score(y, preds, zero_division=0)
    f1 = f1_score(y, preds, zero_division=0)

    try:
<<<<<<< HEAD
=======
        # ROC AUC requires at least two classes in y
>>>>>>> 9b735eb99fcfab11611f7f8da03c77f43357eb91
        if len(np.unique(y)) > 1:
            roc_auc = roc_auc_score(y, probs)
        else:
            roc_auc = 1.0 if np.all(preds == y) else 0.5
    except Exception:
        roc_auc = 0.5

    cm = confusion_matrix(y, preds, labels=[0, 1])
    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])

    return {
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1_score": round(float(f1), 4),
        "roc_auc": round(float(roc_auc), 4),
        "confusion_matrix": {
            "true_negative": tn,
            "false_positive": fp,
            "false_negative": fn,
            "true_positive": tp,
        },
        "sample_count": int(len(y)),
    }


def train_url_classifier(
    csv_path: Union[str, Path],
    model_type: str = "logistic_regression",
    version: str = "v1.0.0",
    model_name: str = "url_classifier",
    test_size: float = 0.15,
    val_size: float = 0.15,
    random_state: int = 42,
    output_dir: Optional[Union[str, Path]] = None,
    hyperparameters: Optional[Dict[str, Any]] = None,
<<<<<<< HEAD
    set_as_production: bool = False,
) -> Tuple[Any, ModelMetadata]:
    """
    Trains a URL classifier from CSV dataset, calculates full metrics,
    and registers it in the ModelRegistry.
    """
    urls, y, hygiene_report = load_dataset_from_csv(csv_path)

    X = extract_dataset_features(urls)

=======
) -> Tuple[Any, ModelMetadata]:
    """
    Trains a URL classifier from CSV dataset and saves it to the model registry.
    """
    urls, y = load_dataset_from_csv(csv_path)
    logger.info("Loaded %d samples (Benign: %d, Phishing: %d)", len(y), int(np.sum(y == 0)), int(np.sum(y == 1)))

    X = extract_dataset_features(urls)
    logger.info("Extracted %d features for %d samples", X.shape[1], X.shape[0])

    # 1. Stratified Train / Val / Test Split
    # Total test+val proportion
>>>>>>> 9b735eb99fcfab11611f7f8da03c77f43357eb91
    combined_eval_size = test_size + val_size
    if combined_eval_size >= 0.8:
        raise ValueError("test_size + val_size must be less than 0.8 of the dataset")

    X_train_full, X_test, y_train_full, y_test = train_test_split(
        X,
        y,
        test_size=test_size,
        stratify=y,
        random_state=random_state,
    )

<<<<<<< HEAD
=======
    # Relative val size from train_full
>>>>>>> 9b735eb99fcfab11611f7f8da03c77f43357eb91
    rel_val_size = val_size / (1.0 - test_size)
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_full,
        y_train_full,
        test_size=rel_val_size,
        stratify=y_train_full,
        random_state=random_state,
    )

<<<<<<< HEAD
=======
    logger.info(
        "Dataset splits -> Train: %d, Val: %d, Test: %d",
        len(y_train),
        len(y_val),
        len(y_test),
    )

    # 2. Pipeline Definition
>>>>>>> 9b735eb99fcfab11611f7f8da03c77f43357eb91
    hyperparameters = hyperparameters or {}
    model_type_clean = model_type.lower().replace("-", "_")

    if model_type_clean in ("logistic_regression", "logreg", "lr"):
        c_param = float(hyperparameters.get("C", 1.0))
        max_iter = int(hyperparameters.get("max_iter", 1000))
        resolved_params = {
            "C": c_param,
<<<<<<< HEAD
=======
            "penalty": "l2",
>>>>>>> 9b735eb99fcfab11611f7f8da03c77f43357eb91
            "solver": "lbfgs",
            "max_iter": max_iter,
            "random_state": random_state,
        }
        pipeline = Pipeline(
            [
                ("scaler", StandardScaler()),
                ("classifier", LogisticRegression(**resolved_params)),
            ]
        )
        resolved_model_type = "LogisticRegression"

    elif model_type_clean in ("random_forest", "rf"):
        n_estimators = int(hyperparameters.get("n_estimators", 100))
        max_depth = int(hyperparameters.get("max_depth", 8))
        resolved_params = {
            "n_estimators": n_estimators,
            "max_depth": max_depth,
            "min_samples_leaf": 2,
            "random_state": random_state,
        }
        pipeline = Pipeline(
            [
                ("classifier", RandomForestClassifier(**resolved_params)),
            ]
        )
        resolved_model_type = "RandomForestClassifier"
    else:
        raise ValueError(f"Unsupported model_type '{model_type}'. Choose 'logistic_regression' or 'random_forest'.")

<<<<<<< HEAD
    pipeline.fit(X_train, y_train)

=======
    # 3. Model Training
    pipeline.fit(X_train, y_train)

    # 4. Evaluation
>>>>>>> 9b735eb99fcfab11611f7f8da03c77f43357eb91
    metrics = {
        "train": compute_dataset_metrics(pipeline, X_train, y_train),
        "val": compute_dataset_metrics(pipeline, X_val, y_val),
        "test": compute_dataset_metrics(pipeline, X_test, y_test),
    }

<<<<<<< HEAD
=======
    logger.info(
        "Evaluation summary [Test Set] -> Accuracy: %.3f, F1: %.3f, ROC-AUC: %.3f",
        metrics["test"]["accuracy"],
        metrics["test"]["f1_score"],
        metrics["test"]["roc_auc"],
    )

    # 5. Metadata Creation & Registry Storage
>>>>>>> 9b735eb99fcfab11611f7f8da03c77f43357eb91
    metadata = ModelMetadata(
        model_name=model_name,
        version=version,
        model_type=resolved_model_type,
        feature_schema_version=FeatureSchemaV1.VERSION,
        feature_names=FeatureSchemaV1.feature_names(),
        feature_count=FeatureSchemaV1.feature_count(),
        hyperparameters=resolved_params,
        metrics=metrics,
        decision_threshold=0.5,
        notes=f"Trained on {csv_path} with {resolved_model_type}",
    )
<<<<<<< HEAD
    metadata.metrics["data_hygiene"] = hygiene_report.to_dict()
=======
>>>>>>> 9b735eb99fcfab11611f7f8da03c77f43357eb91

    registry = ModelRegistry(storage_dir=output_dir)
    registry.save_model(pipeline, metadata)

<<<<<<< HEAD
    if set_as_production:
        registry.set_production_model(version=version, model_name=model_name)

=======
>>>>>>> 9b735eb99fcfab11611f7f8da03c77f43357eb91
    return pipeline, metadata


def main():
    parser = argparse.ArgumentParser(description="Train TrustShield URL Phishing Classifier")
    parser.add_argument(
        "--data",
        type=str,
        default=str(Path(__file__).resolve().parent / "datasets" / "sample_urls.csv"),
        help="Path to training CSV file containing 'url' and 'label'",
    )
    parser.add_argument(
        "--model",
        type=str,
        choices=["logistic_regression", "random_forest"],
        default="logistic_regression",
        help="Model architecture to train",
    )
    parser.add_argument(
        "--version",
        type=str,
        default="v1.0.0",
        help="Semantic model version (e.g. v1.0.0)",
    )
    parser.add_argument(
        "--model-name",
        type=str,
        default="url_classifier",
        help="Registered model name identifier",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Directory to save model artifacts",
    )
<<<<<<< HEAD
    parser.add_argument(
        "--production",
        action="store_true",
        help="Set this trained model as the active production model",
    )
=======
>>>>>>> 9b735eb99fcfab11611f7f8da03c77f43357eb91

    args = parser.parse_args()

    try:
        pipeline, metadata = train_url_classifier(
            csv_path=args.data,
            model_type=args.model,
            version=args.version,
            model_name=args.model_name,
            output_dir=args.output_dir,
<<<<<<< HEAD
            set_as_production=args.production,
=======
>>>>>>> 9b735eb99fcfab11611f7f8da03c77f43357eb91
        )
        print(f"Successfully trained {metadata.model_name} ({metadata.version})")
        print(f"Test Accuracy: {metadata.metrics['test']['accuracy']}")
        print(f"Test ROC-AUC:  {metadata.metrics['test']['roc_auc']}")
    except Exception as e:
        logger.exception("Training failed: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
