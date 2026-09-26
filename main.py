from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import requests

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class SpeechCheckRequest(BaseModel):
    text: str

@app.post("/check-speech")
def check_speech(req: SpeechCheckRequest):
    response = requests.post(
        "https://api.languagetool.org/v2/check",
        data={
            "text": req.text,
            "language": "de-DE",
        }
    )
    result = response.json()

    errors = []
    for match in result.get("matches", []):
        errors.append({
            "wrong_part": req.text[match["offset"]: match["offset"] + match["length"]],
            "message": match["message"],
            "suggestions": [r["value"] for r in match.get("replacements", [])][:3]
        })

    return {
        "original_text": req.text,
        "errors": errors,
        "error_count": len(errors)
    }