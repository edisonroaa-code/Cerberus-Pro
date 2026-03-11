import os
import asyncio
from google import genai
import logging
from dotenv import load_dotenv

load_dotenv()

async def test_models():
    api_key = os.getenv("GEMINI_API_KEY", "")
    if not api_key:
        print("GEMINI_API_KEY not found in .env!")
        return

    client = genai.Client(api_key=api_key)
    
    # Selected models from the previous listing that look promising for 2026
    models_to_try = [
        "gemini-3-flash-preview",
        "gemini-3.1-pro-preview",
        "gemini-2.5-flash-lite",
        "gemini-flash-latest",
        "gemini-pro-latest",
        "deep-research-pro-preview-12-2025"
    ]

    print("\n--- Testing 2026-era advanced models ---")
    for model_name in models_to_try:
        try:
            print(f"Testing '{model_name}'...", end=" ", flush=True)
            response = await asyncio.to_thread(
                client.models.generate_content,
                model=model_name,
                contents="ping",
            )
            print("WORKING")
            print(f"!!! SUCCESS !!! Use: {model_name}")
            return model_name
        except Exception as e:
            text = str(e)
            if "404" in text:
                print("404")
            elif "429" in text:
                print("429 (Rate Limit)")
            else:
                print(f"FAIL: {text[:80]}...")

if __name__ == "__main__":
    asyncio.run(test_models())
