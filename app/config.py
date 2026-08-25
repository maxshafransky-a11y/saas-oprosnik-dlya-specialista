from functools import lru_cache

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEV_ONLY_APP_SECRET_KEY = "dev-only-app-secret-key-not-for-production-change-me"
MIN_APP_SECRET_KEY_LENGTH = 32


class Settings(BaseSettings):
    app_env: str = "development"
    database_url: SecretStr
    database_owner_url: SecretStr
    app_secret_key: SecretStr = Field(
        default=SecretStr(DEV_ONLY_APP_SECRET_KEY),
        validate_default=True,
    )
    storage_bucket: str = ""
    storage_endpoint_url: str | None = None
    storage_region: str | None = None
    storage_access_key_id: SecretStr | None = None
    storage_secret_access_key: SecretStr | None = None

    @field_validator("app_secret_key")
    @classmethod
    def validate_app_secret_key(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value()) < MIN_APP_SECRET_KEY_LENGTH:
            raise ValueError("APP_SECRET_KEY must be at least 32 characters")
        return value

    @model_validator(mode="after")
    def reject_dev_secret_outside_development(self) -> "Settings":
        if (
            self.app_env.strip().casefold() in {"production", "staging"}
            and self.app_secret_key.get_secret_value() == DEV_ONLY_APP_SECRET_KEY
        ):
            raise ValueError("APP_SECRET_KEY must be explicitly configured for production/staging")
        return self

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        hide_input_in_errors=True,
        extra="ignore",
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
