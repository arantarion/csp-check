#!/usr/bin/env python3

from __future__ import annotations

import argparse
import asyncio
import concurrent.futures
import json
import os
import re
import socket
import sys
from enum import Enum
from functools import partial
from typing import Dict, List, Optional, Set, Tuple

import tldextract

try:
    from dns import resolver
    from dns.resolver import NXDOMAIN, NoAnswer, NoNameservers

    print("DNSpython installed")
    HAVE_DNSPY = True
except Exception:
    HAVE_DNSPY = False

try:
    from whois import whois
    from whois.parser import PywhoisError

    print("pywhois installed")
    HAVE_WHOIS = True
except Exception:
    HAVE_WHOIS = False


# --------------------------
# Domain status enum
# --------------------------
class DomainStatus(str, Enum):
    EXISTS = "exists"
    NXDOMAIN = "nxdomain"
    NOTREGISTERED = "notregistered"
    NOANSWER = "noanswer"
    NONS = "nonameservers"
    OTHER = "other"
    UNKNOWN = "unknown"


# --------------------------
# Source host extraction
# --------------------------
_QUOTE_RE = re.compile(r"^'+|'+$")


def extract_hostname_from_source(item: str) -> Optional[str]:
    if not item:
        return None
    raw = _QUOTE_RE.sub("", item.strip())
    raw_low = raw.lower()

    if raw_low in {"*", "self", "none", "unsafe-inline", "unsafe-eval"}:
        return None
    if raw_low.endswith(":"):
        return None
    if raw_low.startswith(("data:", "blob:", "filesystem:", "mediastream:", "ws:", "wss:")):
        return None
    if raw_low.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")):
        return None

    if raw.startswith("*."):
        raw = raw[2:]
    if "://" in raw:
        try:
            host = raw.split("://", 1)[1].split("/", 1)[0]
            host = host.split("@")[-1]
            host = host.split(":", 1)[0]
            return host.lower() if host else None
        except Exception:
            return None

    if "/" in raw:
        host = raw.split("/", 1)[0]
        host = host.split(":", 1)[0]
        return host.lower() if host else None

    host = raw.split(":", 1)[0]
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*$", host) and raw.endswith(":"):
        return None
    return host.lower() if host else None


# --------------------------
# Extract allowed hosts from an entry
# --------------------------
def allowed_hosts_from_entry(entry: Dict) -> Set[str]:
    hosts = set()

    csp_raw = entry.get("csp_raw")
    if csp_raw:
        for part in (p.strip() for p in csp_raw.split(";")):
            if not part:
                continue
            tokens = [t for t in part.split() if t]
            for tok in tokens[1:]:
                h = extract_hostname_from_source(tok)
                if h:
                    hosts.add(h)
    else:
        policies = entry.get("policies") or []
        for pol in policies:
            if isinstance(pol, dict):
                items = pol.get("items") or pol.get("sources") or []
                for it in items:
                    if isinstance(it, dict):
                        tok = it.get("raw") or it.get("normalized") or None
                    else:
                        tok = it
                    h = extract_hostname_from_source(tok) if tok else None
                    if h:
                        hosts.add(h)
            elif isinstance(pol, str):
                for tok in pol.split()[1:]:
                    h = extract_hostname_from_source(tok)
                    if h:
                        hosts.add(h)
    return hosts


# --------------------------
# FLD helper
# --------------------------
def to_fld(host: str) -> Optional[str]:
    if not host:
        return None
    te = tldextract.extract(host)
    if not te.domain or not te.suffix:
        return None
    return f"{te.domain}.{te.suffix}"


# --------------------------
# DNS + WHOIS resolver (sync core)
# --------------------------
def _resolve_domain_status_sync(
    domain: str, dns_resolvers: Optional[List[str]] = None, dns_timeout: float = 3.0
) -> DomainStatus:
    if not domain:
        return DomainStatus.UNKNOWN

    if not HAVE_DNSPY:
        try:
            socket.getaddrinfo(domain, 80)
            return DomainStatus.EXISTS
        except socket.gaierror:
            return DomainStatus.NXDOMAIN
        except Exception:
            return DomainStatus.OTHER

    r = resolver.Resolver()
    if dns_resolvers:
        r.nameservers = dns_resolvers
    r.lifetime = dns_timeout
    r.timeout = dns_timeout

    try:
        r.resolve(domain, "A")
        return DomainStatus.EXISTS
    except NXDOMAIN:
        status = DomainStatus.NXDOMAIN
    except NoNameservers:
        status = DomainStatus.NONS
    except NoAnswer:
        # try AAAA
        try:
            r.resolve(domain, "AAAA")
            return DomainStatus.EXISTS
        except NXDOMAIN:
            status = DomainStatus.NXDOMAIN
        except NoNameservers:
            status = DomainStatus.NONS
        except NoAnswer:
            status = DomainStatus.NOANSWER
        except Exception:
            status = DomainStatus.OTHER
    except Exception:
        # fallback: try AAAA once
        try:
            r.resolve(domain, "AAAA")
            return DomainStatus.EXISTS
        except NXDOMAIN:
            status = DomainStatus.NXDOMAIN
        except NoNameservers:
            status = DomainStatus.NONS
        except NoAnswer:
            status = DomainStatus.NOANSWER
        except Exception:
            status = DomainStatus.OTHER

    if status in (DomainStatus.NXDOMAIN, DomainStatus.NONS) and HAVE_WHOIS:
        try:
            whois(domain)
        except PywhoisError:
            status = DomainStatus.NOTREGISTERED
        except Exception:
            pass

    return status


# --------------------------
# Async orchestration
# --------------------------
async def build_domain_health_map(
    domains: Set[str], dns_resolvers: Optional[List[str]] = None, concurrency: int = 50, dns_timeout: float = 3.0
) -> Dict[str, DomainStatus]:
    results: Dict[str, DomainStatus] = {}
    loop = asyncio.get_running_loop()
    sem = asyncio.Semaphore(concurrency)
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:

        async def task(d: str):
            async with sem:
                func = partial(_resolve_domain_status_sync, d, dns_resolvers, dns_timeout)
                st = await loop.run_in_executor(pool, func)
                results[d] = st

        await asyncio.gather(*(task(d) for d in domains))
    return results


# --------------------------
# Create reports
# --------------------------
def summarize_orphans(domain_health: Dict[str, DomainStatus], example_hosts: Dict[str, Set[str]]) -> List[Dict]:
    orphans = []
    for fld, status in domain_health.items():
        if status in (DomainStatus.NXDOMAIN, DomainStatus.NOTREGISTERED, DomainStatus.NONS):
            orphans.append(
                {
                    "fld": fld,
                    "status": status.value,
                    "example_hosts": sorted(list(example_hosts.get(fld, set()))),
                }
            )
    return sorted(orphans, key=lambda x: x["fld"])


# --------------------------
# Find affected directives
# --------------------------
def find_affected_directives_in_csp(csp_raw: str, orphan_flds: Set[str]) -> List[Dict]:
    affected = []
    if not csp_raw:
        return affected
    for part in (p.strip() for p in csp_raw.split(";")):
        if not part:
            continue
        tokens = [t for t in part.split() if t]
        if not tokens:
            continue
        directive = tokens[0]
        for tok in tokens[1:]:
            h = extract_hostname_from_source(tok)
            if not h:
                continue
            fld = to_fld(h)
            if fld and fld in orphan_flds:
                rec = {"directive": directive, "domain": fld, "host": h}
                if rec not in affected:
                    affected.append(rec)
    return affected


# --------------------------
# CLI / main
# --------------------------
def build_parser():
    p = argparse.ArgumentParser(description="Flag orphan domains from JSON CSP output")
    p.add_argument("input", help="JSON file produced by CSP parser (list of items)")
    p.add_argument("--resolvers", default="8.8.8.8,1.1.1.1", help="comma-separated DNS resolvers")
    p.add_argument("--concurrency", type=int, default=50, help="concurrency for DNS checks")
    p.add_argument("--dns-timeout", type=float, default=3.0, help="per-resolve timeout (seconds)")
    p.add_argument("--outdir", default=".", help="output directory for reports")
    p.add_argument("--min-count", type=int, default=1, help="minimum occurrences of FLD to include (default 1)")
    return p


async def main_async(args):
    with open(args.input, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, list):
        print("Input must be a JSON array of objects", file=sys.stderr)
        return 2

    example_hosts: Dict[str, Set[str]] = {}
    entries_allowed_hosts: List[Tuple[int, Set[str]]] = []
    all_hosts = []
    for idx, entry in enumerate(data):
        hosts = allowed_hosts_from_entry(entry)
        entries_allowed_hosts.append((idx, hosts))
        for h in hosts:
            all_hosts.append(h)
            fld = to_fld(h)
            if fld:
                example_hosts.setdefault(fld, set()).add(h)

    # build unique FLDs and filter by min-count
    all_flds = [to_fld(h) for h in all_hosts if to_fld(h)]
    fld_counts: Dict[str, int] = {}
    for f in all_flds:
        fld_counts[f] = fld_counts.get(f, 0) + 1
    unique_flds = {f for f, cnt in fld_counts.items() if cnt >= args.min_count}

    print(f"Discovered {len(unique_flds)} unique FLDs to check (from {len(all_hosts)} host tokens).")

    dns_resolvers = [r.strip() for r in args.resolvers.split(",") if r.strip()]
    domain_health = await build_domain_health_map(
        unique_flds, dns_resolvers=dns_resolvers, concurrency=args.concurrency, dns_timeout=args.dns_timeout
    )

    orphans = summarize_orphans(domain_health, example_hosts)
    os.makedirs(args.outdir, exist_ok=True)
    orphans_path = os.path.join(args.outdir, "orphans.json")
    with open(orphans_path, "w", encoding="utf-8") as fh:
        json.dump(orphans, fh, indent=2)
    print(f"Wrote {len(orphans)} orphans to {orphans_path}")

    orphan_flds = {o["fld"] for o in orphans}
    affected_sites = []
    for idx, hosts in entries_allowed_hosts:
        entry = data[idx]
        csp_raw = entry.get("csp_raw")
        affected = find_affected_directives_in_csp(csp_raw, orphan_flds)
        if affected:
            affected_sites.append(
                {
                    "index": idx,
                    "requested_url": entry.get("requested_url"),
                    "fetched_url": entry.get("fetched_url"),
                    "affected_directives": affected,
                }
            )
    affected_path = os.path.join(args.outdir, "affected_sites.json")
    with open(affected_path, "w", encoding="utf-8") as fh:
        json.dump(affected_sites, fh, indent=2)
    print(f"Wrote {len(affected_sites)} affected sites to {affected_path}")

    counts = {}
    for o in orphans:
        counts[o["status"]] = counts.get(o["status"], 0) + 1
    print("Summary by status:", counts)
    return 0


def main():
    p = build_parser()
    args = p.parse_args()
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    sys.exit(main())
