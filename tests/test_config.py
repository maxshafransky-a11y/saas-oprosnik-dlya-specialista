import importlib
import sys
from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

ROOT = Path(__file__).parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

config = importlib.import_module("app.config")
Settings = config.Settings

RUNTIME_DATABASE_URL = (
    "postgresql+psycopg://health_app:health_app_dev_only@127.0.0.1:55432/health_intake"
)
OWNER_DATABASE_URL = (
    "postgresql+psycopg://health_owner:health_owner_dev_only@127.0.0.1:55432/health_intake"
)


def make_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "database_url": RUNTIME_DATABASE_URL,
        "database_owner_url": OWNER_DATABASE_URL,
        **overrides,
    }
    return Settings(**values)


def test_app_secret_key_is_secretstr_with_dev_only_default() -> None:
    settings = make_settings(app_env="development")
    secret = settings.app_secret_key.get_secret_value()

    assert Settings.model_fields["app_secret_key"].annotation is SecretStr
    assert "dev-only" in secret.lower()
    assert len(secret) >= 32
    assert secret not in repr(settings)
    assert secret not in str(settings)


@pytest.mark.parametrize("app_env", ["production", "staging"])
def test_production_like_environments_reject_dev_only_default(app_env: str) -> None:
    with pytest.raises(ValidationError) as error:
        make_settings(app_env=app_env)

    assert "dev-only" not in str(error.value).lower()
    assert "dev-only" not in repr(error.value).lower()


def test_production_accepts_explicit_secret_without_revealing_it() -> None:
    secret = "production-secret-" + "x" * 32
    settings = make_settings(app_env="production", app_secret_key=SecretStr(secret))

    assert settings.app_secret_key.get_secret_value() == secret
    assert secret not in repr(settings)
    assert secret not in str(settings)


def test_storage_settings_keep_credentials_secret() -> None:
    access_key = "storage-access-key"
    secret_key = "storage-secret-key"
    settings = make_settings(
        storage_bucket="private-health",
        storage_endpoint_url="https://s3.example.test",
        storage_region="ru-1",
        storage_access_key_id=SecretStr(access_key),
        storage_secret_access_key=SecretStr(secret_key),
    )

    assert settings.storage_bucket == "private-health"
    assert settings.storage_endpoint_url == "https://s3.example.test"
    assert settings.storage_region == "ru-1"
    assert settings.storage_access_key_id.get_secret_value() == access_key
    assert settings.storage_secret_access_key.get_secret_value() == secret_key
    assert access_key not in repr(settings)
    assert secret_key not in repr(settings)


def test_short_secret_is_rejected_without_revealing_value() -> None:
    secret = "short-secret-value"

    with pytest.raises(ValidationError) as error:
        make_settings(app_secret_key=SecretStr(secret))

    assert secret not in str(error.value)
    assert secret not in repr(error.value)


def test_env_example_names_dev_only_secret_contract() -> None:
    source = (Path(__file__).parents[1] / ".env.example").read_text(encoding="utf-8")

    assert "APP_SECRET_KEY=" in source
    assert "dev-only" in source.lower()
