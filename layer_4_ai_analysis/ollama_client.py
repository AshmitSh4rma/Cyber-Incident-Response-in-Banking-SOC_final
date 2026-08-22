# ollama_client.py — full replacement

import requests
from langchain_ollama import OllamaLLM

OLLAMA_BASE_URL    = "http://localhost:11434"
OLLAMA_MODEL       = "mistral"
OLLAMA_TEMPERATURE = 0

# ── Cached singletons ──
_CLIENT: OllamaLLM | None = None
_CONNECTION_STATUS: dict | None = None


def get_ollama_client() -> OllamaLLM:
    global _CLIENT
    if _CLIENT is None:
        _CLIENT = OllamaLLM(
            base_url=OLLAMA_BASE_URL,
            model=OLLAMA_MODEL,
            temperature=OLLAMA_TEMPERATURE,
        )
    return _CLIENT


def check_ollama_connection(force_recheck: bool = False) -> dict:
    """
    Checks connection ONCE per process lifetime unless force_recheck=True.
    Call with force_recheck=True at pipeline startup only.
    """
    global _CONNECTION_STATUS
    if _CONNECTION_STATUS is not None and not force_recheck:
        return _CONNECTION_STATUS

    try:
        response = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=5)
        if response.status_code == 200:
            models = response.json().get("models", [])
            model_names = [m.get("name", "") for m in models]
            model_available = any(OLLAMA_MODEL in name for name in model_names)

            if model_available:
                _CONNECTION_STATUS = {"connected": True, "model": OLLAMA_MODEL, "error": None}
            else:
                _CONNECTION_STATUS = {
                    "connected": False,
                    "model": OLLAMA_MODEL,
                    "error": f"Model {OLLAMA_MODEL} not found. Available: {model_names}"
                }
        else:
            _CONNECTION_STATUS = {
                "connected": False,
                "model": OLLAMA_MODEL,
                "error": f"Ollama returned {response.status_code}"
            }
    except Exception as e:
        _CONNECTION_STATUS = {"connected": False, "model": OLLAMA_MODEL, "error": str(e)}

    return _CONNECTION_STATUS


def run_inference(prompt: str) -> dict:
    try:
        client = get_ollama_client()  # now returns cached instance
        response = client.invoke(prompt)

        if not response or len(response.strip()) < 10:
            return {"success": False, "response": None, "error": "Empty model response"}

        return {"success": True, "response": response, "error": None}

    except Exception as e:
        return {"success": False, "response": None, "error": str(e)}
