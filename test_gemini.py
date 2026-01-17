try:
    from google import genai
except Exception:
    try:
        import google.generativeai as genai
    except Exception:
        import pytest

        pytest.skip("google genai/generativeai not installed", allow_module_level=True)
import os
from dotenv import load_dotenv

load_dotenv()

if not hasattr(genai, "Client"):
    import pytest

    pytest.skip("Installed GenAI package does not expose `Client` interface; skipping.", allow_module_level=True)

client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

print("\n=== Available Models ===\n")

for m in client.models.list():
    methods = getattr(m, "supported_generation_methods", []) or []
    if "generateContent" in methods:
        print(m.name, "→", methods)

