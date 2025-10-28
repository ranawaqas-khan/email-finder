# app/finder.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from app.verifier import verify_email
import asyncio, re, logging

app = FastAPI(
    title="Email Finder",
    version="1.0",
    description="Generates possible email patterns and verifies them using SMTP logic."
)

# Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

# ---------------------------
# Models
# ---------------------------
class FindRequest(BaseModel):
    full_name: str
    domain: str

class FindResponse(BaseModel):
    found: Optional[str]
    attempts: List[dict]

# ---------------------------
# Helper to generate email patterns
# ---------------------------
def generate_patterns(full_name: str, domain: str) -> List[str]:
    full_name = re.sub(r"[^a-zA-Z\s]", "", full_name).lower().strip()
    parts = full_name.split()
    if not parts:
        return []

    first = parts[0]
    last = parts[-1] if len(parts) > 1 else ""
    fi, li = first[0], (last[0] if last else "")

    patterns = [
        f"{first}@{domain}",
        f"{first}{last}@{domain}",
        f"{first}.{last}@{domain}",
        f"{fi}{last}@{domain}",
        f"{first}{li}@{domain}",
        f"{last}.{first}@{domain}",
        f"{last}{first}@{domain}",
        f"{fi}.{last}@{domain}",
        f"{first}_{last}@{domain}",
        f"{last}@{domain}",
    ]
    return list(dict.fromkeys(patterns))  # remove duplicates

# ---------------------------
# Routes
# ---------------------------
@app.get("/")
def home():
    return {
        "message": "🚀 Email Finder API is Live!",
        "endpoints": ["/find"]
    }

@app.post("/find", response_model=FindResponse)
async def find_email(req: FindRequest):
    full_name, domain = req.full_name.strip(), req.domain.strip()
    if not full_name or not domain:
        raise HTTPException(status_code=400, detail="Full name and domain required")

    patterns = generate_patterns(full_name, domain)
    if not patterns:
        raise HTTPException(status_code=400, detail="Could not generate email patterns")

    logger.info(f"Generated {len(patterns)} patterns for {full_name}@{domain}")

    attempts = []
    found = None

    for email in patterns:
        logger.info(f"Verifying {email}")
        result = await asyncio.to_thread(verify_email, email)
        attempts.append(result)

        if result.get("Deliverable") and result.get("Status") == "valid":
            found = email
            break

    return {"found": found, "attempts": attempts}
