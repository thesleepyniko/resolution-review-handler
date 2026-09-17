import hmac
import hashlib
from dotenv import load_dotenv
import os
from typing import Annotated
from pydantic import BaseModel
from fastapi import FastAPI, Header, HTTPException
import httpx

load_dotenv()

app = FastAPI()

ARI_SIGNING_SECRET = os.environ.get("ARI_SIGNING_SECRET") or ""
ARI_WEBHOOK_URL = os.environ.get("ARI_WEBHOOK_URL") or ""


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
class IncomingSubmission(BaseModel):
    external_id: str
    maker_email: str
    maker_name: str
    maker_slack_id: str
    maker_hackatime_id: str | None = None
    title: str
    description: str
    repo_url: str
    demo_url: str
    thumbnail_url: str
    hackatime_projects: list[str]

    def to_ari(self) -> Ari:
        return Ari(
            external_id=self.external_id,
            maker=Maker(
                email=self.maker_email,
                name=self.maker_name,
                slack_id=self.maker_slack_id,
                hackatime_id=self.maker_hackatime_id,
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
    if airtable_token != os.environ.get("AIRTABLE_SECRET"): # make sure that it's actually airtable making the req and not somebody else
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

    request = httpx.post(
        ARI_WEBHOOK_URL,
        content=raw,
        headers = {
            "Content-Type": "application/json",
            "X-Ari-Signature": raw_signed
        }
    )

    try:
        request.raise_for_status()
    except Exception as e:  # noqa: E722
        raise HTTPException(502, detail=str(e))
        


    


    

    

    

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