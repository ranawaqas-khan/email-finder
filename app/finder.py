# app/finder.py
"""
Email Finder API
----------------
Generates common email address patterns from a full name and domain,
then verifies them using the same verification logic as bounsov2/verifier.py.

Order of verification (stops when first valid email is found):
    first@domain
    last@domain
    f.last@domain
    first.last@domain
    first.l@domain
    firstlast@domain
    lastfirst@domain
    fl@domain
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
from app.verifier import verify_email
import asyncio
import re
import logging

# ---------------------------
# FastAPI App Setup
# ---------------------------
app = FastAPI(
    title="Email Finder",
    version="1.0.0",
    description="Generates possible email patterns and verifies them using SMTP logic.",
)

# ---------------------------
# Logging Setup
# ---------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

# ---------------------------
# Request/Response Models
# ---------------------------
class FindRequest(BaseModel):
    full_name: str
    domain: str

class FindResponse(BaseModel):
    found: Optional[str]

# ---------------------------
# Pattern Generator
# ---------------------------
def generate_patterns(full_name: str, domain: str):
    """
    Generate and return email patterns in defined order.
    """
    full_name = re.sub(r"[^a-zA-Z\s]", "", full_name).lower().strip()
    parts = full_name.split()
    if not parts:
        return []

    first = parts[0]
    last = parts[-1] if len(parts) > 1 else ""
    fi = first[0] if first else ""
    li = last[0] if last else ""

    patterns = [
        f"{first}@{domain}",          # first
        f"{last}@{domain}",           # last
        f"{fi}.{last}@{domain}",      # f.last
        f"{first}.{last}@{domain}",   # first.last
        f"{first}.{li}@{domain}",     # first.l
        f"{first}{last}@{domain}",    # firstlast
        f"{last}{first}@{domain}",    # lastfirst
        f"{fi}{li}@{domain}",         # fl
    ]

    # remove duplicates, keep order
    return list(dict.fromkeys([p for p in patterns if "@" in p]))

# ---------------------------
# Routes
# ---------------------------
@app.get("/")
def home():
    return {
        "message": "🚀 Email Finder API is Live!",
        "endpoint": "/find",
        "example": {
            "full_name": "John Doe",
            "domain": "example.com"
        }
    }

@app.post("/find", response_model=FindResponse)
async def find_email(req: FindRequest):
    """
    Generate email patterns, verify each one sequentially,
    and return the first valid (deliverable) email found.
    """
    full_name = req.full_name.strip()
    domain = req.domain.strip()

    if not full_name or not domain:
        raise HTTPException(status_code=400, detail="Full name and domain are required")

    # Generate patterns
    patterns = generate_patterns(full_name, domain)
    if not patterns:
        raise HTTPException(status_code=400, detail="Could not generate email patterns")

    logger.info(f"Generated {len(patterns)} patterns for '{full_name}' @ '{domain}'")

    # Verify each pattern until a valid one is found
    for email in patterns:
        logger.info(f"Verifying {email}")
        result = await asyncio.to_thread(verify_email, email)

        if result.get("Deliverable") and result.get("Status") == "valid":
            logger.info(f"✅ Found valid email: {email}")
            return {"found": email}

    # If none are valid
    logger.info("❌ No valid email found")
    return {"found": None}
