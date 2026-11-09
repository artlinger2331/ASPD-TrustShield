"""
Unit tests for the TrustShield URL prediction interface and attribution engine.
"""

from pathlib import Path
import pytest

from app.ml.feature_extractor import FeatureSchemaV1
from app.ml.model_registry import ModelRegistry
from app.ml.predict import URLClassifier, URLPredictionResult
from app.ml.train_model import train_url_classifier

SAMPLE_CSV = Path(__file__).resolve().parent.parent / "datasets" / "sample_urls.csv"


@pytest.fixture(scope="module")
def trained_models(tmp_path_factory):
    """Fixture that trains both Logistic Regression and Random Forest models once for predictor tests."""
    temp_dir = tmp_path_factory.mktemp("ml_models")
    registry = ModelRegistry(storage_dir=temp_dir)

    pipe_lr, meta_lr = train_url_classifier(
        csv_path=SAMPLE_CSV,
        model_type="logistic_regression",
        version="v1.0.0-lr",
        model_name="url_classifier",
        output_dir=temp_dir,
    )

    pipe_rf, meta_rf = train_url_classifier(
        csv_path=SAMPLE_CSV,
        model_type="random_forest",
        version="v1.0.0-rf",
        model_name="url_classifier_rf",
        output_dir=temp_dir,
    )

    return {
        "registry": registry,
        "lr_model": pipe_lr,
        "lr_meta": meta_lr,
        "rf_model": pipe_rf,
        "rf_meta": meta_rf,
    }


def test_predictor_logistic_regression_benign(trained_models):
    """Verify inference on a known benign URL using Logistic Regression."""
    classifier = URLClassifier(
        model=trained_models["lr_model"],
        metadata=trained_models["lr_meta"],
    )

    url = "https://www.google.com/search?q=machine+learning"
    result = classifier.predict(url)

    assert isinstance(result, URLPredictionResult)
    assert result.url == url
    assert result.label == "benign"
    assert result.is_phishing is False
    assert 0.0 <= result.probability < 0.5
    assert 0.0 <= result.confidence <= 1.0
    assert result.model_version == "v1.0.0-lr"
    assert result.feature_schema_version == FeatureSchemaV1.VERSION

    assert len(result.top_contributing_features) > 0
    top = result.top_contributing_features[0]
    assert top.feature_name in result.raw_features
    assert isinstance(top.description, str) and len(top.description) > 0


def test_predictor_logistic_regression_phishing(trained_models):
    """Verify inference on a known phishing URL using Logistic Regression."""
    classifier = URLClassifier(
        model=trained_models["lr_model"],
        metadata=trained_models["lr_meta"],
    )

    url = "http://paypal-security-update.account-verification.xyz/login.php?verify=1"
    result = classifier.predict(url)

    assert result.label == "phishing"
    assert result.is_phishing is True
    assert result.probability >= 0.5
    assert result.confidence > 0.0

    feature_names = [f.feature_name for f in result.top_contributing_features]
    assert any(name in feature_names for name in ["suspicious_tld", "suspicious_keyword_count", "brand_keyword_count", "uses_https", "num_dots"])


def test_predictor_random_forest(trained_models):
    """Verify inference with Random Forest architecture."""
    classifier = URLClassifier(
        model=trained_models["rf_model"],
        metadata=trained_models["rf_meta"],
    )

    url = "http://chase-online-banking-auth.top/signin.html"
    result = classifier.predict(url)

    assert result.label == "phishing"
    assert result.is_phishing is True
    assert len(result.top_contributing_features) > 0


def test_prediction_result_to_dict(trained_models):
    """Verify JSON-serializable dictionary output."""
    classifier = URLClassifier(
        model=trained_models["lr_model"],
        metadata=trained_models["lr_meta"],
    )

    res = classifier.predict("https://wikipedia.org")
    d = res.to_dict()

    assert isinstance(d, dict)
    assert d["label"] == "benign"
    assert "top_contributing_features" in d
    assert isinstance(d["top_contributing_features"], list)
    assert len(d["top_contributing_features"]) > 0
    assert "feature_name" in d["top_contributing_features"][0]
    assert "description" in d["top_contributing_features"][0]
    assert "raw_features" in d
    assert len(d["raw_features"]) == FeatureSchemaV1.feature_count()
