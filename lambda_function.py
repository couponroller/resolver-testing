# lambda_function.py – ResolverTestLive with S3 logging
import json
import os
import time
import datetime as dt
import socket
import asyncio
import boto3
import botocore.exceptions

from concurrent.futures import ThreadPoolExecutor

import requests
import dns.message
import dns.query
import dns.rdatatype
import dns.exception

PUBLIC_RESOLVERS_URL = "https://public-dns.info/nameserver/us.txt"
BASELINE_DOMAINS = ["google.com", "theinspirationedit.com"]
DEFAULT_TARGET = "example.com"
S3_BUCKET = os.getenv("FAIL_DNS_LOG_BUCKET")  # bucket name via env var
S3_PREFIX = os.getenv("FAIL_DNS_LOG_PREFIX", "failed_queries/")


def _timestamp():
    return dt.datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%SZ")


def get_ptr(ip: str):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def read_public_resolvers():
    rsp = requests.get(PUBLIC_RESOLVERS_URL, timeout=10)
    rsp.raise_for_status()
    return [line.strip() for line in rsp.text.splitlines() if line.strip()]


def query(domain: str, resolver: str, timeout: float = 2.0):
    """Return (success: bool, err_msg: str|None)."""
    try:
        q = dns.message.make_query(domain, dns.rdatatype.A)
        dns.query.udp(q, resolver, timeout=timeout)
        return True, None
    except dns.exception.DNSException as exc:
        return False, str(exc)


async def test_resolver(pool: ThreadPoolExecutor, domain: str, resolver: str):
    loop = asyncio.get_running_loop()
    ok, err = await loop.run_in_executor(pool, query, domain, resolver)
    if ok:
        return None
    # retry once
    ok2, err2 = await loop.run_in_executor(pool, query, domain, resolver)
    if ok2:
        return None
    return {"resolver": resolver, "ptr": get_ptr(resolver), "error": err2 or err}


async def run_checks(target_domain: str):
    resolvers = read_public_resolvers()

    failures: list[dict] = []
    start = time.time()

    with ThreadPoolExecutor(max_workers=64) as pool:
        # baseline domains
        for baseline_domain in BASELINE_DOMAINS:
            tasks = [asyncio.create_task(test_resolver(pool, baseline_domain, r)) for r in resolvers]
            results = await asyncio.gather(*tasks)
            bad = [r for r in results if r]
            if bad:
                raise RuntimeError(
                    f"{len(bad)} resolvers failed baseline domain {baseline_domain}. Aborting.")
        # main target
        tasks = [asyncio.create_task(test_resolver(pool, target_domain, r)) for r in resolvers]
        results = await asyncio.gather(*tasks)
        failures = [r for r in results if r]

    return failures, time.time() - start, len(resolvers)


# ---------- S3 logging ------------------------------------------------------

def write_failures_to_s3(items: list[dict]):
    if not S3_BUCKET:
        print("FAIL_DNS_LOG_BUCKET env var not set; skipping S3 write.")
        return
    key = f"{S3_PREFIX}{_timestamp()}.json"

    client = boto3.client("s3")
    try:
        client.put_object(
            Bucket=S3_BUCKET,
            Key=key,
            Body=json.dumps(items, indent=2).encode(),
            ContentType="application/json",
        )
        print(f"Uploaded {len(items)} failures to s3://{S3_BUCKET}/{key}")
    except botocore.exceptions.BotoCoreError as e:
        print(f"[WARN] Failed to upload failures file to S3: {e}")


# ---------- Lambda entry ----------------------------------------------------

def lambda_handler(event, context):
    """Entry point. Expects optional event {"domain": "target.com"}."""
    target = None
    if isinstance(event, dict):
        target = event.get("domain")
    if not target:
        target = os.getenv("DEFAULT_TARGET", DEFAULT_TARGET)

    failures, elapsed, total = asyncio.run(run_checks(target))

    resp = {
        "target": target,
        "totalResolvers": total,
        "failed": len(failures),
        "elapsedSec": round(elapsed, 2),
    }
    if failures:
        resp["failures"] = failures[:20]  # return just first 20
        write_failures_to_s3(failures)

    print(json.dumps(resp, indent=2))
    return resp
