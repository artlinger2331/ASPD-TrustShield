"""
Unit tests for the TrustShield URL model training pipeline.
Verifies data loading, cleaning, deduplication, conflict resolution,
model training, metrics computation, and production model saving.
"""

from pathlib import Path
import pytest

<<<<<<< .merge_file_4c6dhP
from app.ml.feature_extractor import FeatureSchemaV1
=======
>>>>>>> .merge_file_mGt7Zr
from app.ml.model_registry import ModelRegistry
from app.ml.train_model import (
    DataHygieneReport,
    load_dataset_from_csv,
    train_url_classifier,
)

SAMPLE_CSV = Path(__file__).resolve().parent.parent / "datasets" / "sample_urls.csv"


def test_load_dataset_from_csv():
    """Verify loading, parsing, and hygiene report for clean sample CSV."""
    urls, labels, hygiene = load_dataset_from_csv(SAMPLE_CSV)

    assert len(urls) == 60
    assert len(labels) == 60
    assert sum(labels == 0) == 30
    assert sum(labels == 1) == 30
    assert isinstance(hygiene, DataHygieneReport)
    assert hygiene.clean_records == 60
    assert hygiene.duplicates_removed == 0
    assert hygiene.conflicts_dropped == 0


def test_data_cleaning_and_deduplication(tmp_path: Path):
    """Verify deduplication of identical URLs and dropping of conflicting labels."""
    test_csv = tmp_path / "messy_urls.csv"
    content = """url,label
https://google.com,0
https://google.com,0
https://github.com,0
http://paypal-fake.xyz/login,1
http://paypal-fake.xyz/login,1
http://conflicted-site.com,0
http://conflicted-site.com,1
,0
   ,1
"""
    test_csv.write_text(content, encoding="utf-8")

    urls, labels, hygiene = load_dataset_from_csv(test_csv)

    # Clean records should be: google.com (0), github.com (0), paypal-fake.xyz/login (1)
    assert len(urls) == 3
    assert len(labels) == 3
    assert hygiene.duplicates_removed == 2  # 1 google duplicate, 1 paypal duplicate
    assert hygiene.conflicts_dropped == 2  # conflicted-site.com records dropped
    assert hygiene.invalid_dropped == 2  # empty/whitespace rows dropped
    assert hygiene.clean_records == 3


def test_train_logistic_regression(tmp_path: Path):
    """Verify full training pipeline with Logistic Regression and production promotion."""
    pipeline, metadata = train_url_classifier(
        csv_path=SAMPLE_CSV,
        model_type="logistic_regression",
        version="v1.0.0-test-lr",
        model_name="test_url_classifier",
        test_size=0.15,
        val_size=0.15,
        output_dir=tmp_path,
        set_as_production=True,
    )

    assert metadata.model_type == "LogisticRegression"
    assert metadata.version == "v1.0.0-test-lr"
<<<<<<< .merge_file_4c6dhP
    assert metadata.feature_count == FeatureSchemaV1.feature_count()
    assert "data_hygiene" in metadata.metrics

<<<<<<< Updated upstream
=======
    assert metadata.feature_count == 42

    # Check metrics existence
>>>>>>> .merge_file_mGt7Zr
=======
    # Check metrics existence
>>>>>>> Stashed changes
    for split in ("train", "val", "test"):
        assert split in metadata.metrics
        split_metrics = metadata.metrics[split]
        assert "accuracy" in split_metrics
        assert "precision" in split_metrics
        assert "recall" in split_metrics
        assert "f1_score" in split_metrics
        assert "roc_auc" in split_metrics
        assert "confusion_matrix" in split_metrics
<<<<<<< .merge_file_4c6dhP
        assert split_metrics["accuracy"] >= 0.7

<<<<<<< Updated upstream
=======
        assert split_metrics["accuracy"] >= 0.7  # Clean benchmark performance

    # Verify model is reloadable from registry
>>>>>>> .merge_file_mGt7Zr
=======
    # Verify model is reloadable as production from registry
>>>>>>> Stashed changes
    registry = ModelRegistry(storage_dir=tmp_path)
    loaded_pipe, loaded_meta = registry.load_production_model(model_name="test_url_classifier")
    assert loaded_meta.version == "v1.0.0-test-lr"
    assert loaded_meta.is_production is True
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
