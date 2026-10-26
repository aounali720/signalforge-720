"""Optional AI concept art. Never fabricate an image of a real security incident."""
from __future__ import annotations
import base64
import os
import requests


def openai_concept_image(topic: str, *, session: requests.Session | None = None) -> bytes:
    key = os.getenv("OPENAI_API_KEY", "").strip()
    if not key:
        raise ValueError("OPENAI_API_KEY is required for optional AI concept art")
    prompt = ("Create a tasteful, editorial cyber threat intelligence visual for a LinkedIn article. "
              "Modern restrained photography-inspired still life: physical network cables, dark glass, subtle side lighting, "
              "credible real-world texture, strong composition, no neon hackers, no robots, no code rain, no UI screens, "
              "no text or logos. Conceptual artwork only, not depicting any actual breach or named organization. "
              f"Story topic: {topic[:250]}")
    sess = session or requests.Session()
    resp = sess.post("https://api.openai.com/v1/images/generations",
                     headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                     json={"model": os.getenv("OPENAI_IMAGE_MODEL", "gpt-image-1"),
                           "prompt": prompt, "size": "1536x1024", "n": 1}, timeout=180)
    resp.raise_for_status()
    data = resp.json()["data"][0]
    if "b64_json" in data:
        return base64.b64decode(data["b64_json"], validate=True)
    raise RuntimeError("Image API did not return base64 image data; check model availability")
