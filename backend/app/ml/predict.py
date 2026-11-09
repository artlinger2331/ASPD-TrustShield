"""
Prediction interface with feature attribution for TrustShield ML.
Computes classification label, probability, confidence, and top contributing
features for URL threat detection with thread-safe prediction caching.
"""

from dataclasses import asdict, dataclass
import logging
import threading
import time

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res["top_contributing_features"] = [f.to_dict() for f in self.top_contributing_features]
        return res


FEATURE_HUMAN_DESCRIPTIONS = {
    "url_length": "Overall URL length in characters",
    "domain_length": "Domain / hostname character length",
    "num_dots": "Dot frequency in URL",
    "num_hyphens": "Hyphen count (common in spoofed domains)",
    "num_digits": "Total numeric digit count",
    "num_special_chars": "Special character count (@, _, %, =, ?, etc.)",
    "num_subdomains": "Excessive subdomain hierarchy depth",
    "domain_age_days": "Newly registered domain age",
    "has_ip_address": "Direct IP address used instead of domain name",
    "uses_https": "Absence of HTTPS transport encryption",
    "suspicious_keyword_count": "Presence of targeted phishing/credential keywords",
    "brand_keyword_count": "Targeted brand name embedded in hostname/subdomains",
    "suspicious_tld": "High-abuse top-level domain extension",
    "is_url_shortener": "URL shortening service masking destination",
    "redirect_count": "Multiple HTTP redirection hops",
    "domain_entropy": "Shannon entropy / randomness of domain string",
    "char_repetition_max": "Abnormally long consecutive character repetition run",
    "path_depth": "Directory nesting depth in URL path",
    "query_param_count": "Number of query parameters",
    "has_embedded_credentials": "Embedded credentials syntax (user:pass@host)",
}


class PredictionCache:
    """Thread-safe TTL in-memory cache for URL predictions."""

    def __init__(self, default_ttl_seconds: int = 3600):
        self._cache: Dict[str, Tuple[float, URLPredictionResult]] = {}
        self._lock = threading.Lock()
        self.default_ttl = default_ttl_seconds

    def _make_key(self, url: str, model_version: str) -> str:
        return f"{model_version}::{url.strip().lower()}"

    def get(self, url: str, model_version: str) -> Optional[URLPredictionResult]:
        key = self._make_key(url, model_version)
        with self._lock:
            entry = self._cache.get(key)
            if not entry:
                return None
            timestamp, result = entry
            if time.time() - timestamp > self.default_ttl:
                del self._cache[key]
                return None
            # Return fresh dataclass copy marked cached=True
            cached_res = URLPredictionResult(
                url=result.url,
                label=result.label,
                is_phishing=result.is_phishing,
                probability=result.probability,
                confidence=result.confidence,
                model_version=result.model_version,
                feature_schema_version=result.feature_schema_version,
                top_contributing_features=result.top_contributing_features,
                raw_features=result.raw_features,
                cached=True,
            )
            return cached_res

    def set(self, url: str, model_version: str, result: URLPredictionResult) -> None:
        key = self._make_key(url, model_version)
        with self._lock:
            self._cache[key] = (time.time(), result)

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()

    def size(self) -> int:
        with self._lock:
            return len(self._cache)


GLOBAL_PREDICTION_CACHE = PredictionCache()


class URLClassifier:
    """Production prediction service with model versioning and explainable attribution."""

    def __init__(
        self,
        model: Optional[Any] = None,
        metadata: Optional[ModelMetadata] = None,
        version: Optional[str] = None,
        model_name: str = "url_classifier",
        registry: Optional[ModelRegistry] = None,
        use_production: bool = True,
        cache: Optional[PredictionCache] = None,
        else:
            self.model, self.metadata = self.registry.load_model(version=version, model_name=model_name)

        self.feature_names = self.metadata.feature_names or FeatureSchemaV1.feature_names()
        self.decision_threshold = float(self.metadata.decision_threshold or 0.5)
        self.cache = cache or GLOBAL_PREDICTION_CACHE
        classifier = getattr(self.model, "named_steps", {}).get("classifier", self.model)
        scaler = getattr(self.model, "named_steps", {}).get("scaler", None)

        if hasattr(classifier, "coef_"):
            coefs = classifier.coef_[0]
            if scaler is not None and hasattr(scaler, "mean_") and hasattr(scaler, "scale_"):
=======
                # Scaled linear model
>>>>>>> 9b735eb99fcfab11611f7f8da03c77f43357eb91
                norm_x = (X_vec - scaler.mean_) / np.where(scaler.scale_ == 0, 1.0, scaler.scale_)
                raw_contributions = coefs * norm_x
            else:
                raw_contributions = coefs * X_vec

            for i, name in enumerate(self.feature_names):
<<<<<<< HEAD
                if i < len(raw_contributions):
                    val = feature_dict.get(name, 0.0)
                    contrib = float(raw_contributions[i])
                    contributions.append((name, val, contrib))

        elif hasattr(classifier, "feature_importances_"):
            importances = classifier.feature_importances_
            for i, name in enumerate(self.feature_names):
                if i < len(importances):
                    val = feature_dict.get(name, 0.0)
                    direction = 1.0 if float(val) > 0 else -1.0
                    contrib = float(importances[i]) * direction
                    contributions.append((name, val, contrib))
        else:
            for name in self.feature_names[:top_k]:
                val = feature_dict.get(name, 0.0)
                contributions.append((name, val, 0.0))

=======
        # Sort:
        # If predicted phishing, prioritize highest positive contributions (+ pushing toward phishing).
        # If predicted benign, prioritize highest negative contributions (- pushing toward benign).
>>>>>>> 9b735eb99fcfab11611f7f8da03c77f43357eb91
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
<<<<<<< HEAD
        metadata: Optional[Dict[str, Any]] = None,
        top_k_features: int = 5,
        use_cache: bool = True,
    ) -> URLPredictionResult:
        """
        Runs model inference on a URL string with optional pre-fetched scan metadata.
        Returns cached prediction if available and use_cache is True.
        """
        # 1. Check cache (cache key based on URL and model version)
        if use_cache and not metadata:
            cached_result = self.cache.get(url, self.metadata.version)
            if cached_result:
                return cached_result

        # 2. Extract features
        feature_dict = extract_features(url, metadata=metadata)
        feature_vector = np.array([[feature_dict[name] for name in self.feature_names]], dtype=float)

        # 3. Probability computation
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

        # 4. Attributions
        top_features = self._compute_attributions(
            X_vec=feature_vector[0],
            feature_dict=feature_dict,
            is_phishing=is_phishing,
            top_k=top_k_features,
        )

        result = URLPredictionResult(
            url=url,
            label=label,
            is_phishing=is_phishing,
            probability=phishing_prob_rounded,
            confidence=confidence,
            model_version=self.metadata.version,
            feature_schema_version=self.metadata.feature_schema_version,
            top_contributing_features=top_features,
            raw_features=feature_dict,
            cached=False,
        )

        # 5. Store in cache
        if use_cache:
            self.cache.set(url, self.metadata.version, result)

        return result
