from google import genai
import os
from dotenv import load_dotenv

load_dotenv()

client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

print("\n=== Available Models ===\n")

for m in client.models.list():
    if "generateContent" in (m.supported_generation_methods or []):
        print(m.name, "→", m.supported_generation_methods)

