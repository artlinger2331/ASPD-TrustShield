"""
Model Registry for TrustShield ML.
Manages versioned model artifacts, metadata tracking, and validation.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple, Union

import joblib

from app.ml.feature_extractor import FeatureSchemaV1

logger = logging.getLogger(__name__)

DEFAULT_MODELS_DIR = Path(__file__).resolve().parent / "models"


@dataclass
class ModelMetadata:
    model_name: str
    version: str
    model_type: str
    feature_schema_version: str = FeatureSchemaV1.VERSION
    feature_names: List[str] = field(default_factory=lambda: list(FeatureSchemaV1.FEATURE_NAMES))
    feature_count: int = len(FeatureSchemaV1.FEATURE_NAMES)
    hyperparameters: Dict[str, Any] = field(default_factory=dict)
    metrics: Dict[str, Any] = field(default_factory=dict)
    decision_threshold: float = 0.5
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ModelMetadata":
        return cls(
            model_name=data.get("model_name", "url_classifier"),
            version=data.get("version", "v1.0.0"),
            model_type=data.get("model_type", "Unknown"),
            feature_schema_version=data.get("feature_schema_version", FeatureSchemaV1.VERSION),
            feature_names=data.get("feature_names", list(FeatureSchemaV1.FEATURE_NAMES)),
            feature_count=data.get("feature_count", len(FeatureSchemaV1.FEATURE_NAMES)),
            hyperparameters=data.get("hyperparameters", {}),
            metrics=data.get("metrics", {}),
            decision_threshold=data.get("decision_threshold", 0.5),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
            notes=data.get("notes"),
        )


class ModelRegistry:
    """Handles persistence, retrieval, and listing of versioned ML models."""

    def __init__(self, storage_dir: Optional[Union[str, Path]] = None):
        self.storage_dir = Path(storage_dir) if storage_dir else DEFAULT_MODELS_DIR
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def _get_paths(self, model_name: str, version: str) -> Tuple[Path, Path]:
        base_name = f"{model_name}_{version}"
        model_path = self.storage_dir / f"{base_name}.joblib"
        meta_path = self.storage_dir / f"{base_name}.meta.json"
        return model_path, meta_path

    def save_model(
        self,
        model: Any,
        metadata: Union[ModelMetadata, Dict[str, Any]],
    ) -> Tuple[Path, Path]:
        """
        Saves a trained model pipeline (.joblib) and its metadata (.meta.json).
        """
        if isinstance(metadata, dict):
            meta_obj = ModelMetadata.from_dict(metadata)
        else:
            meta_obj = metadata

        model_path, meta_path = self._get_paths(meta_obj.model_name, meta_obj.version)

        joblib.dump(model, model_path)

        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta_obj.to_dict(), f, indent=2)

        logger.info(
            "Model %s (%s) saved successfully to %s",
            meta_obj.model_name,
            meta_obj.version,
            model_path,
        )
        return model_path, meta_path

    def list_models(self, model_name: Optional[str] = None) -> List[ModelMetadata]:
        """Lists all registered models in storage directory."""
        results: List[ModelMetadata] = []
        if not self.storage_dir.exists():
            return results

        for meta_file in sorted(self.storage_dir.glob("*.meta.json")):
            try:
                with open(meta_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    meta = ModelMetadata.from_dict(data)
                    if model_name is None or meta.model_name == model_name:
                        results.append(meta)
            except Exception as e:
                logger.warning("Failed to parse metadata file %s: %s", meta_file, e)

        return results

    def _find_latest_version(self, model_name: str) -> Optional[str]:
        models = self.list_models(model_name=model_name)
        if not models:
            return None

        def sort_key(m: ModelMetadata):
            match = re.match(r"v?(\d+)\.(\d+)(?:\.(\d+))?", m.version)
            if match:
                major = int(match.group(1))
                minor = int(match.group(2))
                patch = int(match.group(3) or 0)
                return (major, minor, patch, m.created_at)
            return (0, 0, 0, m.created_at)

        models.sort(key=sort_key, reverse=True)
        return models[0].version

    def load_model(
        self,
        version: Optional[str] = None,
        model_name: str = "url_classifier",
    ) -> Tuple[Any, ModelMetadata]:
        """
        Loads the specified model version. If version is None, loads the latest version.
        Raises FileNotFoundError if model is not registered.
        """
        if version is None:
            version = self._find_latest_version(model_name)
            if version is None:
                raise FileNotFoundError(f"No registered models found for '{model_name}' in {self.storage_dir}")

        model_path, meta_path = self._get_paths(model_name, version)
        if not model_path.exists():
            raise FileNotFoundError(f"Model file not found at {model_path}")
        if not meta_path.exists():
            raise FileNotFoundError(f"Metadata file not found at {meta_path}")

        with open(meta_path, "r", encoding="utf-8") as f:
            meta_data = json.load(f)
        metadata = ModelMetadata.from_dict(meta_data)

        model = joblib.load(model_path)
        return model, metadata

    def get_metadata(
        self,
        version: Optional[str] = None,
        model_name: str = "url_classifier",
    ) -> Optional[ModelMetadata]:
        """Returns metadata for a specific or latest model."""
        try:
            _, meta = self.load_model(version=version, model_name=model_name)
            return meta
        except FileNotFoundError:
            return None

    def delete_model(self, version: str, model_name: str = "url_classifier") -> bool:
        """Deletes model binary and metadata file."""
        model_path, meta_path = self._get_paths(model_name, version)
        deleted = False
        if model_path.exists():
            model_path.unlink()
            deleted = True
        if meta_path.exists():
            meta_path.unlink()
            deleted = True
        return deleted
