# app/finder.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, List
import asyncio
import re
import logging

from app.verifier import verify_email  # same logic you already have

app = FastAPI(
    title="Email Finder",
    version="1.0.0",
    description="Generates email patterns and verifies sequentially; returns first valid only."
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger("email_finder")


# ---------------------------
# Models
# ---------------------------
class FindRequest(BaseModel):
    full_name: str
    domain: str


class FindResponse(BaseModel):
    found: Optional[str]


# ---------------------------
# Helpers
# ---------------------------
NAME_CLEAN_RE = re.compile(r"[^a-zA-Z\s]+")
DOMAIN_CLEAN_RE = re.compile(r"[^a-z0-9.\-]")

def clean_name(name: str) -> List[str]:
    """Keep letters and spaces, split into tokens, lowercase."""
    cleaned = NAME_CLEAN_RE.sub("", name or "").strip().lower()
    parts = [p for p in cleaned.split() if p]
    return parts

def clean_domain(domain: str) -> str:
    """Lowercase, drop leading @, remove illegal characters."""
    d = (domain or "").strip().lower()
    if d.startswith("@"):
        d = d[1:]
    # strip anything not allowed in a basic domain string
    d = DOMAIN_CLEAN_RE.sub("", d)
    if "." not in d or not d:
        raise HTTPException(status_code=400, detail="Invalid domain")
    return d

def generate_patterns(full_name: str, domain: str) -> List[str]:
    """Exactly the 8 patterns in the specified order, deduped, skipping ones that need a missing last name."""
    parts = clean_name(full_name)
    if not parts:
        return []
    first = parts[0]
    last = parts[-1] if len(parts) > 1 else ""
    fi = first[0] if first else ""
    li = last[0] if last else ""

    # Required order:
    patterns = [
        f"{first}@{domain}",                                   # first@domain
        *( [f"{last}@{domain}"] if last else [] ),            # last@domain
        *( [f"{fi}.{last}@{domain}"] if last and fi else [] ),# f.last@domain
        *( [f"{first}.{last}@{domain}"] if last else [] ),    # first.last@domain
        *( [f"{first}.{li}@{domain}"] if li else [] ),        # first.l@domain
        *( [f"{first}{last}@{domain}"] if last else [] ),     # firstlast@domain
        *( [f"{last}{first}@{domain}"] if last else [] ),     # lastfirst@domain
        *( [f"{fi}{li}@{domain}"] if fi and li else [] ),     # fl@domain
    ]

    # De-duplicate while preserving order
    seen = set()
    ordered = []
    for p in patterns:
        if p not in seen:
            seen.add(p)
            ordered.append(p)
    return ordered


# ---------------------------
# Routes
# ---------------------------
@app.get("/")
def home():
    return {"message": "🚀 Email Finder API is Live!", "endpoints": ["/find"]}


@app.post("/find", response_model=FindResponse)
async def find_email(req: FindRequest):
    full_name = (req.full_name or "").strip()
    domain = clean_domain(req.domain)

    patterns = generate_patterns(full_name, domain)
    if not patterns:
        raise HTTPException(status_code=400, detail="Could not generate email patterns (need at least a first name).")

    logger.info(f"Trying {len(patterns)} pattern(s) for '{full_name}' @ {domain}: {patterns}")

    for email in patterns:
        try:
            result = await asyncio.to_thread(verify_email, email)
        except Exception as e:
            logger.error(f"Verifier error for {email}: {e}")
            # continue to next pattern on transient errors
            continue

        if result and result.get("Deliverable") and result.get("Status") == "valid":
            logger.info(f"FOUND valid email: {email}")
            return {"found": email}

    # none validated as deliverable
    return {"found": None}
