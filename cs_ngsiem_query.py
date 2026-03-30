"""
cs_ngsiem_query.py
------------------
Connects to CrowdStrike Next-Gen SIEM via OAuth2 and runs a
LogScale/Humio query job using the correct Humio API endpoints.

Endpoints used:
    POST /humio/api/v1/repositories/<repo>/queryjobs      — initiate search
    GET  /humio/api/v1/repositories/<repo>/queryjobs/<id> — poll + get results

.env file expected keys:
    CS_CLIENT_ID       = your OAuth2 client ID
    CS_CLIENT_SECRET   = your OAuth2 client secret
    CS_BASE_URL        = https://api.laggar.gcw.crowdstrike.com
    CS_REPOSITORY      = search-all
    SECOPS_SA_KEY      = service account JSON (injected by Cloud Run)
    SECOPS_CUSTOMER_ID = SecOps customer ID GUID
"""

import os
import time
import json
import requests
from dotenv import load_dotenv
from google.oauth2 import service_account
import google.auth.transport.requests

load_dotenv()

# ── Config ────────────────────────────────────────────────────────────────────
CLIENT_ID     = os.getenv("CS_CLIENT_ID")
CLIENT_SECRET = os.getenv("CS_CLIENT_SECRET")
BASE_URL      = os.getenv("CS_BASE_URL", "https://api.crowdstrike.com").rstrip("/")
REPOSITORY    = os.getenv("CS_REPOSITORY", "search-all")

# Query
LSQL_QUERY     = "groupBy(ComputerName) | sort(count, order=desc)"
LOOKBACK_HOURS = 24

# Polling
POLL_INTERVAL = 5
MAX_WAIT      = 120

# SecOps
SECOPS_INGEST_URL = "https://malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate"
SECOPS_SCOPES = [
    "https://www.googleapis.com/auth/malachite-ingestion",
    "https://www.googleapis.com/auth/cloud-platform"
]


# ── Step 1: OAuth2 ────────────────────────────────────────────────────────────
def get_token() -> str:
    url  = f"{BASE_URL}/oauth2/token"
    resp = requests.post(
        url,
        data={
            "client_id":     CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=15,
    )
    if resp.status_code not in (200, 201):
        print(f"[!] Auth failed — HTTP {resp.status_code}: {resp.text[:300]}")
        resp.raise_for_status()

    token = resp.json().get("access_token")
    if not token:
        raise ValueError("No access_token in OAuth2 response")
    print("[+] Authenticated successfully")
    return token


# ── Step 2: Submit query job ──────────────────────────────────────────────────
def submit_query(token: str) -> str:
    url = f"{BASE_URL}/humio/api/v1/repositories/{REPOSITORY}/queryjobs"

    payload = {
        "queryString": LSQL_QUERY,
        "start":       f"{LOOKBACK_HOURS}h",
        "end":         "now",
        "timeZone":    "America/New_York",
    }

    resp = requests.post(
        url,
        json=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type":  "application/json",
            "Accept":        "application/json",
        },
        timeout=15,
    )

    if resp.status_code != 200:
        print(f"[!] Submit failed — HTTP {resp.status_code}: {resp.text[:500]}")
        resp.raise_for_status()

    job_id = resp.json().get("id")
    if not job_id:
        print(f"[!] No job ID in response: {resp.json()}")
        raise ValueError("No job ID returned")

    print(f"[+] Query job submitted — ID: {job_id}")
    return job_id


# ── Step 3: Poll until done ───────────────────────────────────────────────────
def poll_job(token: str, job_id: str) -> dict:
    url     = f"{BASE_URL}/humio/api/v1/repositories/{REPOSITORY}/queryjobs/{job_id}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept":        "application/json",
    }

    elapsed = 0
    while elapsed < MAX_WAIT:
        resp = requests.get(url, headers=headers, timeout=15)

        if resp.status_code != 200:
            print(f"[!] Poll failed — HTTP {resp.status_code}: {resp.text[:300]}")
            resp.raise_for_status()

        data      = resp.json()
        done      = data.get("done", False)
        cancelled = data.get("cancelled", False)

        event_count = len(data.get("events", []))
        print(f"    done={done}  events_so_far={event_count}  ({elapsed}s elapsed)")

        if cancelled:
            raise RuntimeError("Query job was cancelled")

        if done:
            print(f"[+] Query complete")
            return data

        time.sleep(POLL_INTERVAL)
        elapsed += POLL_INTERVAL

    raise TimeoutError(f"Query did not complete within {MAX_WAIT}s")


# ── Step 4: SecOps ingestion ──────────────────────────────────────────────────
def get_secops_token() -> str:
    sa_key_json = os.getenv("SECOPS_SA_KEY")
    if not sa_key_json:
        raise EnvironmentError("Missing SECOPS_SA_KEY")

    sa_info = json.loads(sa_key_json)
    creds = service_account.Credentials.from_service_account_info(
        sa_info,
        scopes=SECOPS_SCOPES
    )
    auth_req = google.auth.transport.requests.Request()
    creds.refresh(auth_req)
    print("[+] SecOps token obtained successfully")
    return creds.token


def send_to_secops(events: list):
    customer_id = os.getenv("SECOPS_CUSTOMER_ID")
    if not customer_id:
        raise EnvironmentError("Missing SECOPS_CUSTOMER_ID")

    token = get_secops_token()

    log_entries = []
    for row in events:
        hostname = (
            row.get("ComputerName")
            or row.get("hostname")
            or row.get("_field")
            or "unknown"
        )
        count = (
            row.get("_count")
            or row.get("count")
            or row.get("value")
            or "-"
        )
        log_line = f"hostname={hostname} count={count}"
        log_entries.append({"logText": log_line})

    payload = {
        "customerId": customer_id,
        "logType":    "CS_NGSIEM",
        "entries":    log_entries
    }

    print(f"[*] Sending {len(log_entries)} entries to SecOps...")
    print(f"[*] URL: {SECOPS_INGEST_URL}")
    print(f"[*] Customer ID: {customer_id}")

    resp = requests.post(
        SECOPS_INGEST_URL,
        json=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type":  "application/json"
        },
        timeout=30
    )

    if resp.status_code != 200:
        print(f"[!] SecOps ingest failed — HTTP {resp.status_code}")
        print(f"[!] Full response: {resp.text}")
        resp.raise_for_status()

    print(f"[+] Sent {len(log_entries)} entries to SecOps successfully")


# ── Step 5: Display results ───────────────────────────────────────────────────
def display_results(data: dict):
    events = data.get("events", [])

    if not events:
        print("[!] No results returned.")
        return

    for row in events:
        hostname = (
            row.get("ComputerName")
            or row.get("hostname")
            or row.get("_field")
            or "unknown"
        )
        count = (
            row.get("_count")
            or row.get("count")
            or row.get("value")
            or "-"
        )
        print(f"hostname={hostname} count={count}")

    print(f"total_hostnames={len(events)}")
    print("[*] Attempting SecOps ingest...")
    send_to_secops(events)


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    missing = [k for k, v in {
        "CS_CLIENT_ID":     CLIENT_ID,
        "CS_CLIENT_SECRET": CLIENT_SECRET,
        "CS_BASE_URL":      BASE_URL,
    }.items() if not v]

    if missing:
        raise EnvironmentError(f"Missing required .env keys: {', '.join(missing)}")

    print(f"[*] Base URL:   {BASE_URL}")
    print(f"[*] Repository: {REPOSITORY}")
    print(f"[*] Query:      {LSQL_QUERY}")
    print(f"[*] Lookback:   {LOOKBACK_HOURS}hr\n")

    token  = get_token()
    job_id = submit_query(token)
    data   = poll_job(token, job_id)
    display_results(data)


if __name__ == "__main__":
    main()