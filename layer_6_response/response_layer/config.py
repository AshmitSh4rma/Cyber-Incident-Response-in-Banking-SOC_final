import os
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    elasticsearch_url: str = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
    ollama_url: str = os.getenv("OLLAMA_URL", "http://localhost:11434")
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379")
    postgres_url: str = os.getenv("POSTGRES_URL", "postgresql+asyncpg://admin:admin@localhost:5432/response_layer")
    
    ollama_model: str = os.getenv("OLLAMA_MODEL", "llama3.1")
    hitl_timeout_seconds: int = int(os.getenv("HITL_TIMEOUT_SECONDS", "300"))
    
    # Pydantic v2 style: class-based Config is deprecated.
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
