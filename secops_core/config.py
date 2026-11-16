"""Configurações centrais do secops_core."""

import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configurações globais com suporte a .env e defaults seguros."""

    sqlite_db_path: str = "data/secops.db"
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2"
    api_base_url: str = "http://localhost:8000"

    # Configurações de Detectores
    zscore_threshold: float = 3.0
    iforest_contamination: float = 0.05
    iforest_n_estimators: int = 100
    iforest_random_state: int = 42

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @property
    def sqlite_db_full_path(self) -> Path:
        """Retorna o Path absoluto/resolvido para o banco SQLite."""
        path = Path(self.sqlite_db_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        return path


settings = Settings()
