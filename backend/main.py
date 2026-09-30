import joblib
from typing import List
from fastapi import File, UploadFile, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from PIL import Image
from pyzbar.pyzbar import decode
import io

app = FastAPI(title="PSH - Phishing URL Detector")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MODEL_PATH = "models/model.pkl"

try:
    model = joblib.load(MODEL_PATH)
    print("Pre-trained phishing model loaded successfully.")
except Exception as e:
    print(f"Error loading model: {e}")
    model = None


class URLPayload(BaseModel):
    url: str


def check_risk_signals(url: str) -> List[str]:
    """
    Additional rule-based risk signals, shown alongside the model's result.
    Note: these are separate, supplementary checks — not a direct readout
    of the SVM model's internal decision process.
    """
    signals = []
    url_lower = url.lower()

    if any(keyword in url_lower for keyword in ["login", "verify", "secure", "account", "update", "banking", "password", "confirm"]):
        signals.append("Contains sensitive authentication keywords (e.g., 'login', 'verify', 'account').")

    if "@" in url or "%" in url:
        signals.append("Contains obfuscation or special redirect symbols ('@' or '%').")

    if not url_lower.startswith("https://"):
        signals.append("Lacks HTTPS security encryption.")

    if any(tld in url_lower for tld in [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work"]):
        signals.append("Uses a top-level domain (TLD) frequently associated with disposable/suspicious links.")

    if len(url) > 75:
        signals.append("URL is abnormally long (>75 characters).")

    return signals


def analyze_url_logic(url: str):
    """Evaluates a URL using the actual trained model — no overrides, no whitelist."""
    if model is None:
        raise HTTPException(status_code=500, detail="ML model is not loaded.")

    # Scope check: this model only understands standard web URLs.
    # Non-web schemes (chrome://, file://, mailto:, etc.) are explicitly
    # marked as "not evaluated" rather than forced into a phishing/legitimate
    # verdict that doesn't actually mean anything for them.
    url_lower = url.strip().lower()
    if not (url_lower.startswith("http://") or url_lower.startswith("https://")):
        return {
            "url": url,
            "is_phishing": False,
            "confidence": 0.0,
            "reasons": ["This system analyzes standard web URLs (http/https) only — this input uses a different format and was not evaluated."],
            "evaluated": False,
        }

    prediction = model.predict([url])[0]
    is_phishing = bool(prediction == 1)

    try:
        confidence = float(model.predict_proba([url])[0][1])
    except AttributeError:
        confidence = 1.0 if is_phishing else 0.0

    signals = check_risk_signals(url)
    reasons = signals if signals else ["No additional lexical risk signals found."]

    return {
        "url": url,
        "is_phishing": is_phishing,
        "confidence": round(confidence, 4),
        "reasons": reasons,
        "evaluated": True,
    }


@app.post("/api/analyze")
async def analyze_url(payload: URLPayload):
    try:
        return analyze_url_logic(payload.url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scan-qr")
async def scan_qr_code(file: UploadFile = File(...)):
    try:
        contents = await file.read()
        image = Image.open(io.BytesIO(contents))
        decoded_objects = decode(image)

        if not decoded_objects:
            raise HTTPException(status_code=400, detail="No QR code found in image.")

        url = decoded_objects[0].data.decode("utf-8")
        if not url:
            raise HTTPException(status_code=400, detail="QR code did not contain a URL.")

        return analyze_url_logic(url)

    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"QR scanning error: {str(e)}")