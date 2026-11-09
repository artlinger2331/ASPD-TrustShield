"""
Prediction interface with feature attribution for TrustShield ML.
Computes classification label, probability, confidence, and top contributing
features for URL threat detection.
"""

from dataclasses import asdict, dataclass
import logging
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np

from app.ml.feature_extractor import (
    FeatureSchemaV1,
    extract_features,
    extract_features_vector,
)
from app.ml.model_registry import ModelMetadata, ModelRegistry

logger = logging.getLogger(__name__)


@dataclass
class TopFeatureContribution:
    feature_name: str
    feature_value: Union[int, float]
    contribution: float  # Signed attribution score (+ pushes phishing, - pushes benign)
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class URLPredictionResult:
    url: str
    label: str  # "phishing" or "benign"
    is_phishing: bool
    probability: float  # Phishing probability in [0.0, 1.0]
    confidence: float  # Confidence margin in [0.0, 1.0]
    model_version: str
    feature_schema_version: str
    top_contributing_features: List[TopFeatureContribution]
    raw_features: Dict[str, Union[int, float]]

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res["top_contributing_features"] = [f.to_dict() for f in self.top_contributing_features]
        return res


FEATURE_HUMAN_DESCRIPTIONS = {
    "url_length": "Overall URL length",
    "hostname_length": "Hostname length",
    "path_length": "Path length",
    "query_length": "Query string length",
    "num_dots": "Dot frequency in URL",
    "num_hyphens": "Hyphen count (common in spoofed domains)",
    "num_underscores": "Underscore count",
    "num_slashes": "Forward slash frequency",
    "num_question_marks": "Query indicator frequency",
    "num_equal_signs": "Query parameter count",
    "num_at_symbols": "Embedded @ credential syntax",
    "num_percent_signs": "Percent-encoded hexadecimal characters",
    "num_digits": "Total numeric digit count",
    "digit_ratio": "Proportion of numbers to letters",
    "uppercase_ratio": "Proportion of uppercase letters",
    "vowel_ratio": "Vowel ratio in hostname (DGA indicator)",
    "url_entropy": "Shannon entropy / randomness of URL string",
    "hostname_entropy": "Shannon entropy of hostname",
    "is_ip_address": "Direct IP address used instead of domain name",
    "has_custom_port": "Non-standard port number specified",
    "num_subdomains": "Excessive subdomain hierarchy depth",
    "num_query_params": "Number of query parameters",
    "is_https": "Absence of HTTPS transport encryption",
    "path_depth": "Directory nesting depth",
    "has_double_slash_in_path": "Double forward slash in path (redirect obfuscation)",
    "has_punycode": "Punycode (xn--) internationalized homoglyph indicator",
    "sensitive_word_count": "Presence of targeted phishing/credential keywords",
    "brand_in_subdomain": "Targeted brand name embedded inside subdomain",
    "suspicious_tld": "High-abuse top-level domain extension",
    "tld_in_path": "Misleading domain suffix located inside URL path",
    "domain_age_days": "Newly registered domain age",
    "days_to_expiry": "Domain registration expiration timeline",
    "is_private_whois": "WHOIS registration privacy shielding",
    "num_dns_records": "DNS record density",
    "has_mx_records": "Absence of mail exchange (MX) DNS records",
    "has_txt_records": "Absence of TXT/SPF authentication records",
    "ttl_value": "Abnormally low DNS TTL (fast-flux indicator)",
    "redirect_count": "Multiple HTTP redirection hops",
    "has_cross_domain_redirect": "Cross-domain redirection destination",
    "uses_shortener": "URL shortening service masking destination",
    "http_status_code": "Unexpected HTTP response status code",
    "response_time_ms": "Abnormal server response latency",
}


class URLClassifier:
    """Production prediction service with model versioning and explainable attribution."""

    def __init__(
        self,
        model: Optional[Any] = None,
        metadata: Optional[ModelMetadata] = None,
        version: Optional[str] = None,
        model_name: str = "url_classifier",
        registry: Optional[ModelRegistry] = None,
    ):
        self.registry = registry or ModelRegistry()
        if model is not None and metadata is not None:
            self.model = model
            self.metadata = metadata
        else:
            self.model, self.metadata = self.registry.load_model(version=version, model_name=model_name)

        self.feature_names = self.metadata.feature_names or FeatureSchemaV1.feature_names()
        self.decision_threshold = float(self.metadata.decision_threshold or 0.5)

    def _compute_attributions(
        self,
        X_vec: np.ndarray,
        feature_dict: Dict[str, Union[int, float]],
        is_phishing: bool,
        top_k: int = 5,
    ) -> List[TopFeatureContribution]:
        """
        Computes top contributing features using model coefficients or importances.
        """
        contributions: List[Tuple[str, float, float]] = []

        classifier = getattr(self.model, "named_steps", {}).get("classifier", self.model)
        scaler = getattr(self.model, "named_steps", {}).get("scaler", None)

        if hasattr(classifier, "coef_"):
            coefs = classifier.coef_[0]
            if scaler is not None and hasattr(scaler, "mean_") and hasattr(scaler, "scale_"):
                norm_x = (X_vec - scaler.mean_) / np.where(scaler.scale_ == 0, 1.0, scaler.scale_)
                raw_contributions = coefs * norm_x
            else:
                raw_contributions = coefs * X_vec

            for i, name in enumerate(self.feature_names):
                val = feature_dict.get(name, 0.0)
                contrib = float(raw_contributions[i])
                contributions.append((name, val, contrib))

        elif hasattr(classifier, "feature_importances_"):
            importances = classifier.feature_importances_
            for i, name in enumerate(self.feature_names):
                val = feature_dict.get(name, 0.0)
                direction = 1.0 if float(val) > 0 else -1.0
                contrib = float(importances[i]) * direction
                contributions.append((name, val, contrib))
        else:
            for name in self.feature_names[:top_k]:
                val = feature_dict.get(name, 0.0)
                contributions.append((name, val, 0.0))

        if is_phishing:
            contributions.sort(key=lambda item: item[2], reverse=True)
        else:
            contributions.sort(key=lambda item: item[2], reverse=False)

        top_features: List[TopFeatureContribution] = []
        for name, val, contrib in contributions[:top_k]:
            desc = FEATURE_HUMAN_DESCRIPTIONS.get(name, f"Feature signal '{name}'")
            top_features.append(
                TopFeatureContribution(
                    feature_name=name,
                    feature_value=round(float(val), 4) if isinstance(val, (int, float)) else val,
                    contribution=round(float(contrib), 4),
                    description=desc,
                )
            )

        return top_features

    def predict(
        self,
        url: str,
        context: Optional[Dict[str, Any]] = None,
        top_k_features: int = 5,
    ) -> URLPredictionResult:
        """
        Runs model inference on a URL string with optional pre-fetched context.
        """
        feature_dict = extract_features(url, context=context)
        feature_vector = np.array([[feature_dict[name] for name in self.feature_names]], dtype=float)

        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(feature_vector)[0]
            phishing_prob = float(probs[1])
        else:
            pred = self.model.predict(feature_vector)[0]
            phishing_prob = 1.0 if pred > 0 else 0.0

        is_phishing = phishing_prob >= self.decision_threshold
        label = "phishing" if is_phishing else "benign"

        confidence = round(abs(phishing_prob - self.decision_threshold) * 2.0, 4)
        phishing_prob_rounded = round(phishing_prob, 4)

        top_features = self._compute_attributions(
            X_vec=feature_vector[0],
            feature_dict=feature_dict,
            is_phishing=is_phishing,
            top_k=top_k_features,
        )

        return URLPredictionResult(
            url=url,
            label=label,
            is_phishing=is_phishing,
            probability=phishing_prob_rounded,
            confidence=confidence,
            model_version=self.metadata.version,
            feature_schema_version=self.metadata.feature_schema_version,
            top_contributing_features=top_features,
            raw_features=feature_dict,
        )
