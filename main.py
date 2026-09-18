import hmac
import hashlib
import logging
from dotenv import load_dotenv
import os
from typing import Annotated
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from fastapi import FastAPI, Header, HTTPException
import httpx

load_dotenv()

# uvicorn configures its own loggers but leaves the root logger without a handler,
# so a __name__ logger would fall through to logging.lastResort (bare stderr, no level/timestamp)
logger = logging.getLogger("uvicorn.error")

app = FastAPI()

ARI_SIGNING_SECRET = os.environ.get("ARI_SIGNING_SECRET") or ""
ARI_WEBHOOK_URL = os.environ.get("ARI_WEBHOOK_URL") or ""
AIRTABLE_SECRET = os.environ.get("AIRTABLE_SECRET") or ""


# these should be what airtable sends
class Maker(BaseModel):
    email: str
    name: str
    slack_id: str
    hackatime_id: str | None = None
    program_hours: float | None = None

class Ari(BaseModel):
    external_id: str
    maker: Maker
    title: str
    description: str
    repo_url: str
    demo_url: str
    thumbnail_url: str
    hackatime_projects: list[str]
    evidence: list[str] = ["commits", "elapsed"]


# placeholder for now
# max lengths mirror resolution's projectSubmissionSchema (zod) so we don't reject what the
# upstream form already accepted. min_length=1 covers every field ari marks REQUIRED, since
# airtable sends "" for a blank cell and ari 422s on those; demo_url counts as required
# because we never send `track`, which defaults to software.
class IncomingSubmission(BaseModel):
    # without stripping, `${First Name} ${Last Name}` on two blank cells arrives as " "
    # and satisfies min_length=1
    model_config = ConfigDict(str_strip_whitespace=True)

    external_id: str = Field(min_length=1, max_length=255)
    maker_email: str = Field(min_length=1, max_length=254)
    maker_name: str = Field(min_length=1, max_length=200)
    maker_slack_id: str = Field(min_length=1, max_length=50)
    maker_hackatime_id: str | None = Field(default=None, max_length=100)
    maker_program_hours: float | None = Field(default=None, ge=0)
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=2000)
    repo_url: str = Field(min_length=1, max_length=2000)
    demo_url: str = Field(min_length=1, max_length=2000)
    thumbnail_url: str = Field(min_length=1, max_length=2000)
    hackatime_projects: list[Annotated[str, Field(max_length=200)]] = Field(max_length=50)

    @field_validator("hackatime_projects")
    @classmethod
    def drop_blank_projects(cls, projects: list[str]) -> list[str]:
        return [stripped for p in projects if (stripped := p.strip())]

    @model_validator(mode="after")
    def require_evidence(self):
        # ari 422s unless a ship has hackatime projects, journals or program-added time.
        # we never send journals, so those are the only two sources available here.
        if not self.hackatime_projects and not self.maker_program_hours:
            raise ValueError(
                "ship needs a hackatime project or program hours; ari rejects one with neither"
            )
        return self

    def to_ari(self) -> Ari:
        return Ari(
            external_id=self.external_id,
            maker=Maker(
                email=self.maker_email,
                name=self.maker_name,
                slack_id=self.maker_slack_id,
                hackatime_id=self.maker_hackatime_id,
                program_hours=self.maker_program_hours,
            ),
            title=self.title,
            description=self.description,
            repo_url=self.repo_url,
            demo_url=self.demo_url,
            thumbnail_url=self.thumbnail_url,
            hackatime_projects=self.hackatime_projects,
        )


@app.post("/update")
def handle_project_update(
    submission: IncomingSubmission,
    airtable_token: Annotated[str | None, Header()] = None,
):
    # make sure that it's actually airtable making the req and not somebody else.
    # AIRTABLE_SECRET must be non-empty and match via constant-time compare, otherwise
    # an unset secret (or a missing header) would let the check pass by accident.
    if (
        not AIRTABLE_SECRET
        or not airtable_token
        or not hmac.compare_digest(airtable_token.encode(), AIRTABLE_SECRET.encode())
    ):
        raise HTTPException(401)
    # try:
    #     extracted_repo_url = tldextract.extract(submission.repo_url)
    #     if extracted_repo_url.top_domain_under_public_suffix != "github.com"
    # we'll just let ari handle it! some people use diff git forges so. we're also assuming ari isn't going to get XSSed or anything
    ari_submission = submission.to_ari()

    if not ARI_SIGNING_SECRET or not ARI_WEBHOOK_URL:
        raise HTTPException(500)

    raw = ari_submission.model_dump_json(exclude_none=True).encode("utf-8")

    raw_signed = hmac.new(
        ARI_SIGNING_SECRET.encode(),
        raw,
        hashlib.sha256
    ).hexdigest()

    try:
        request = httpx.post(
            ARI_WEBHOOK_URL,
            content=raw,
            headers = {
                "Content-Type": "application/json",
                "X-Ari-Signature": raw_signed
            },
            timeout=10.0
        )
        request.raise_for_status()
    except Exception:
        logger.exception("failed to forward submission %s to Ari", ari_submission.external_id)
        raise HTTPException(502, detail="failed to forward submission to Ari")
        


    


    

    

    

# {
#   
# }
    




# load_dotenv()

# SECRET = os.environ.get("ARI-SIGNING-SECRET")  # or os.environ["SECRET"]

# signature = hmac.new(
#     SECRET.encode(),      # HMAC key needs to be bytes
#     data,                 # message, already bytes from the "rb" read
#     hashlib.sha256
# ).hexdigest()             # lowercase hex string, same as xxd -p output

# print(signature)