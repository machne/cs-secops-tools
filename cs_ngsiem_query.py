"""
cs_ngsiem_query.py
------------------
Connects to CrowdStrike Next-Gen SIEM via OAuth2 and runs a
LogScale/Humio query job, then sends results to Google SecOps.

Endpoints used:
    POST /humio/api/v1/repositories/<repo>/queryjobs      — initiate search
    GET  /humio/api/v1/repositories/<repo>/queryjobs/<id> — poll + get results

Secrets (injected by Cloud Run via Secret Manager):
    CS_CLIENT_ID       = CrowdStrike OAuth2 client ID
    CS_CLIENT_SECRET   = CrowdStrike OAuth2 client secret
    CS_BASE_URL        = https://api.laggar.gcw.crowdstrike.com
    CS_REPOSITORY      = search-all
    SECOPS_SA_KEY      = SecOps service account JSON
    SECOPS_CUSTOMER_ID = SecOps customer ID GUID
"""

import os
import time
import json
import requests
from dotenv import load_dotenv
from datetime import datetime, timezone
from google.oauth2 import service_account
import google.auth.transport.requests

load_dotenv()

# ── Config ────────────────────────────────────────────────────────────────────
CLIENT_ID     = os.getenv("CS_CLIENT_ID")
CLIENT_SECRET = os.getenv("CS_CLIENT_SECRET")
BASE_URL      = os.getenv("CS_BASE_URL", "https://api.crowdstrike.com").rstrip("/")
REPOSITORY    = os.getenv("CS_REPOSITORY", "search-all")

# Query
SEARCH_NAME    = "inventory"
LSQL_QUERY     = "groupBy(ComputerName) | sort(count, order=desc)"
LOOKBACK_HOURS = 24
LOG_TYPE       = "CS_EDR"

# Polling
POLL_INTERVAL = 5
MAX_WAIT      = 120

# SecOps
# SecOps
SECOPS_INGEST_URL = "https://malachiteingestion-pa.googleapis.com/v2/udmevents:batchCreate"
SECOPS_SCOPES = [
    "https://www.googleapis.com/auth/malachite-ingestion",
    "https://www.googleapis.com/auth/cloud-platform"
]
#SECOPS_INGEST_URL = "https://malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate"
#SECOPS_SCOPES = [
#    "https://www.googleapis.com/auth/malachite-ingestion",
#    "https://www.googleapis.com/auth/cloud-platform"
#]


# ── Step 1: CrowdStrike OAuth2 ────────────────────────────────────────────────
def get_cs_token() -> str:
    resp = requests.post(
        f"{BASE_URL}/oauth2/token",
        data={"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=15,
    )
    if resp.status_code not in (200, 201):
        raise RuntimeError(f"CS auth failed — HTTP {resp.status_code}: {resp.text[:300]}")
    token = resp.json().get("access_token")
    if not token:
        raise ValueError("No access_token in OAuth2 response")
    print("[+] CS authenticated")
    return token


# ── Step 2: Submit query job ──────────────────────────────────────────────────
def submit_query(token: str) -> str:
    resp = requests.post(
        f"{BASE_URL}/humio/api/v1/repositories/{REPOSITORY}/queryjobs",
        json={
            "queryString": LSQL_QUERY,
            "start":       f"{LOOKBACK_HOURS}h",
            "end":         "now",
            "timeZone":    "America/New_York",
        },
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type":  "application/json",
            "Accept":        "application/json",
        },
        timeout=15,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"Submit failed — HTTP {resp.status_code}: {resp.text[:500]}")
    job_id = resp.json().get("id")
    if not job_id:
        raise ValueError("No job ID returned")
    print(f"[+] Query submitted — ID: {job_id}")
    return job_id


# ── Step 3: Poll until done ───────────────────────────────────────────────────
def poll_job(token: str, job_id: str) -> dict:
    url     = f"{BASE_URL}/humio/api/v1/repositories/{REPOSITORY}/queryjobs/{job_id}"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    elapsed = 0

    while elapsed < MAX_WAIT:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code != 200:
            raise RuntimeError(f"Poll failed — HTTP {resp.status_code}: {resp.text[:300]}")
        data = resp.json()
        if data.get("cancelled"):
            raise RuntimeError("Query job was cancelled")
        if data.get("done"):
            print(f"[+] Query complete — {len(data.get('events', []))} events")
            return data
        time.sleep(POLL_INTERVAL)
        elapsed += POLL_INTERVAL

    raise TimeoutError(f"Query did not complete within {MAX_WAIT}s")


# ── Step 4: SecOps ingestion ──────────────────────────────────────────────────
def get_secops_token() -> str:
    sa_info = json.loads(os.getenv("SECOPS_SA_KEY", "{}"))
    if not sa_info:
        raise EnvironmentError("Missing SECOPS_SA_KEY")
    creds = service_account.Credentials.from_service_account_info(
        sa_info, scopes=SECOPS_SCOPES
    )
    creds.refresh(google.auth.transport.requests.Request())
    print("[+] SecOps authenticated")
    return creds.token


def send_to_secops(events: list):
    customer_id = os.getenv("SECOPS_CUSTOMER_ID")
    if not customer_id:
        raise EnvironmentError("Missing SECOPS_CUSTOMER_ID")

    token = get_secops_token()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    udm_events = []
    for row in events:
        hostname = (
            row.get("ComputerName")
            or row.get("hostname")
            or row.get("_field")
            or "unknown"
        )
        count = str(
            row.get("_count")
            or row.get("count")
            or row.get("value")
            or "0"
        )
        udm_events.append({
            "metadata": {
                "eventTimestamp": now,
                "eventType": "GENERIC_EVENT",
                "productName": "CrowdStrike NG-SIEM",
                "vendorName": "CrowdStrike",
                "description": f"search_name={SEARCH_NAME} count={count}"
            },
            "principal": {
                "hostname": hostname
            }
        })

    resp = requests.post(
        "https://malachiteingestion-pa.googleapis.com/v2/udmevents:batchCreate",
        json={
            "customerId": customer_id,
            "events":     udm_events
        },
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type":  "application/json"
        },
        timeout=30
    )

    if resp.status_code != 200:
        raise RuntimeError(f"SecOps ingest failed — HTTP {resp.status_code}: {resp.text}")

    print(f"[+] Sent {len(udm_events)} UDM events to SecOps")

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    missing = [k for k, v in {
        "CS_CLIENT_ID":     CLIENT_ID,
        "CS_CLIENT_SECRET": CLIENT_SECRET,
        "CS_BASE_URL":      BASE_URL,
    }.items() if not v]
    if missing:
        raise EnvironmentError(f"Missing env vars: {', '.join(missing)}")

    token  = get_cs_token()
    job_id = submit_query(token)
    data   = poll_job(token, job_id)
    send_to_secops(data.get("events", []))


if __name__ == "__main__":
    main()