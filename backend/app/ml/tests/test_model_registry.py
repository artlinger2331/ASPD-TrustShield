"""
Unit tests for the TrustShield Model Registry.
Tests saving, loading, listing, deleting, and production model management.
    dummy_model = LogisticRegression()
    dummy_model.classes_ = [0, 1]

    metadata = ModelMetadata(
        model_name="test_classifier",
        version="v1.0.0",
        model_type="LogisticRegression",
        feature_schema_version=FeatureSchemaV1.VERSION,
        feature_names=FeatureSchemaV1.feature_names(),
        feature_count=FeatureSchemaV1.feature_count(),
        hyperparameters={"C": 1.0},
        metrics={"test": {"accuracy": 0.95}},
    )

    model_path, meta_path = registry.save_model(dummy_model, metadata)

    assert model_path.exists()
    assert meta_path.exists()

    loaded_model, loaded_meta = registry.load_model(version="v1.0.0", model_name="test_classifier")
    assert loaded_meta.version == "v1.0.0"
    assert loaded_meta.model_name == "test_classifier"
    assert loaded_meta.feature_count == 20
    assert loaded_meta.metrics["test"]["accuracy"] == 0.95
    assert hasattr(loaded_model, "classes_")


def test_model_registry_production_management(tmp_path: Path):
    """Verify explicit production promotion and retrieval."""
    registry = ModelRegistry(storage_dir=tmp_path)
    dummy_model = LogisticRegression()

    meta_v1 = ModelMetadata("prod_test", "v1.0.0", "LogisticRegression")
    registry.save_model(dummy_model, meta_v1)

    meta_v2 = ModelMetadata("prod_test", "v2.0.0", "LogisticRegression")
    registry.save_model(dummy_model, meta_v2)

    registry.set_production_model("v1.0.0", model_name="prod_test")
    assert registry.get_production_version("prod_test") == "v1.0.0"

    _, prod_meta = registry.load_production_model("prod_test")
    assert prod_meta.version == "v1.0.0"
    assert prod_meta.is_production is True

    registry.set_production_model("v2.0.0", model_name="prod_test")
    assert registry.get_production_version("prod_test") == "v2.0.0"


def test_model_registry_load_latest_fallback(tmp_path: Path):
    """Verify loading the latest version when version=None and no production pointer."""
    registry = ModelRegistry(storage_dir=tmp_path)
    dummy_model = LogisticRegression()

    meta_v1 = ModelMetadata("url_classifier", "v1.0.0", "LogisticRegression")
    registry.save_model(dummy_model, meta_v1)

    meta_v2 = ModelMetadata("url_classifier", "v1.2.0", "LogisticRegression")
    registry.save_model(dummy_model, meta_v2)

    _, loaded_meta = registry.load_model(version=None, model_name="url_classifier")
    assert loaded_meta.version == "v1.2.0"


def test_model_registry_list_models(tmp_path: Path):
    """Verify listing registered models."""
    registry = ModelRegistry(storage_dir=tmp_path)
    dummy_model = LogisticRegression()

    registry.save_model(dummy_model, ModelMetadata("model_a", "v1.0.0", "LogisticRegression"))
    registry.save_model(dummy_model, ModelMetadata("model_b", "v1.0.0", "RandomForestClassifier"))

    all_models = registry.list_models()
    assert len(all_models) == 2

    a_models = registry.list_models(model_name="model_a")
    assert len(a_models) == 1
    assert a_models[0].model_name == "model_a"


def test_model_registry_not_found(tmp_path: Path):
    """Verify exception when loading non-existent model."""
    registry = ModelRegistry(storage_dir=tmp_path)
    with pytest.raises(FileNotFoundError):
        registry.load_model(version="v9.9.9", model_name="non_existent")


def test_model_registry_delete(tmp_path: Path):
    """Verify deleting a registered model."""
    registry = ModelRegistry(storage_dir=tmp_path)
    dummy_model = LogisticRegression()

    meta = ModelMetadata("to_delete", "v1.0.0", "LogisticRegression")
    registry.save_model(dummy_model, meta)

    assert len(registry.list_models(model_name="to_delete")) == 1
    deleted = registry.delete_model(version="v1.0.0", model_name="to_delete")
    assert deleted is True
    assert len(registry.list_models(model_name="to_delete")) == 0
