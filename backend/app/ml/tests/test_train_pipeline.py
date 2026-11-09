"""
Unit tests for the TrustShield URL model training pipeline.
"""

from pathlib import Path
import pytest

from app.ml.model_registry import ModelRegistry
from app.ml.train_model import (
    load_dataset_from_csv,
    train_url_classifier,
)

SAMPLE_CSV = Path(__file__).resolve().parent.parent / "datasets" / "sample_urls.csv"


def test_load_dataset_from_csv():
    """Verify loading and parsing of the sample benchmark CSV."""
    urls, labels = load_dataset_from_csv(SAMPLE_CSV)

    assert len(urls) == 60
    assert len(labels) == 60
    assert sum(labels == 0) == 30
    assert sum(labels == 1) == 30


def test_train_logistic_regression(tmp_path: Path):
    """Verify full training pipeline with Logistic Regression."""
    pipeline, metadata = train_url_classifier(
        csv_path=SAMPLE_CSV,
        model_type="logistic_regression",
        version="v1.0.0-test-lr",
        model_name="test_url_classifier",
        test_size=0.15,
        val_size=0.15,
        output_dir=tmp_path,
    )

    assert metadata.model_type == "LogisticRegression"
    assert metadata.version == "v1.0.0-test-lr"
    assert metadata.feature_count == 42

    for split in ("train", "val", "test"):
        assert split in metadata.metrics
        split_metrics = metadata.metrics[split]
        assert "accuracy" in split_metrics
        assert "precision" in split_metrics
        assert "recall" in split_metrics
        assert "f1_score" in split_metrics
        assert "roc_auc" in split_metrics
        assert "confusion_matrix" in split_metrics
        assert split_metrics["accuracy"] >= 0.7

    registry = ModelRegistry(storage_dir=tmp_path)
    loaded_pipe, loaded_meta = registry.load_model(version="v1.0.0-test-lr", model_name="test_url_classifier")
    assert loaded_meta.version == "v1.0.0-test-lr"
    assert loaded_pipe is not None


def test_train_random_forest(tmp_path: Path):
    """Verify full training pipeline with Random Forest."""
    pipeline, metadata = train_url_classifier(
        csv_path=SAMPLE_CSV,
        model_type="random_forest",
        version="v1.0.0-test-rf",
        model_name="test_rf_classifier",
        test_size=0.15,
        val_size=0.15,
        output_dir=tmp_path,
    )

    assert metadata.model_type == "RandomForestClassifier"
    assert metadata.metrics["test"]["accuracy"] >= 0.7


def test_train_invalid_model_type(tmp_path: Path):
    """Verify error handling on unsupported model architecture."""
    with pytest.raises(ValueError, match="Unsupported model_type"):
        train_url_classifier(
            csv_path=SAMPLE_CSV,
            model_type="quantum_neural_net",
            output_dir=tmp_path,
        )
