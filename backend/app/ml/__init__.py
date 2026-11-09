"""
TrustShield Machine Learning URL Classification Subsystem.
Provides feature extraction, versioned schemas, model registry, training, and inference.
"""

from app.ml.feature_extractor import (
    FeatureDefinition,
    FeatureSchemaV1,
    extract_features,
    extract_features_vector,
)
from app.ml.model_registry import ModelMetadata, ModelRegistry
from app.ml.predict import TopFeatureContribution, URLClassifier, URLPredictionResult

__all__ = [
    "FeatureDefinition",
    "FeatureSchemaV1",
    "extract_features",
    "extract_features_vector",
    "ModelMetadata",
    "ModelRegistry",
    "TopFeatureContribution",
    "URLClassifier",
    "URLPredictionResult",
]
