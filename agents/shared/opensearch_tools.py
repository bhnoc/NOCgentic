"""
opensearch_tools.py — Async helper functions for querying OpenSearch.

When OPENSEARCH_INTERNAL_URL is set (e.g. on the EC2 instance) the functions
query OpenSearch directly on port 9200.  Otherwise they fall back to the
public ingestion API at OPENSEARCH_API_URL (default: https://localhost)
using the /v1/ endpoints that are actually exposed.

All httpx clients use verify=False because the server runs a self-signed TLS
certificate.
"""

from __future__ import annotations

import json
import os
import time
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

OPENSEARCH_INTERNAL_URL: str | None = os.getenv("OPENSEARCH_INTERNAL_URL")
OPENSEARCH_API_URL: str = os.getenv("OPENSEARCH_API_URL", "https://localhost")
OPENSEARCH_API_KEY: str = os.getenv("OPENSEARCH_API_KEY", "")

# When running on EC2 we can query OpenSearch directly.
_USE_INTERNAL = bool(OPENSEARCH_INTERNAL_URL)

_BASE_INTERNAL = (OPENSEARCH_INTERNAL_URL or "http://localhost:9200").rstrip("/")
_BASE_PUBLIC   = OPENSEARCH_API_URL.rstrip("/")

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _public_headers() -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if OPENSEARCH_API_KEY:
        headers["X-API-Key"] = OPENSEARCH_API_KEY
    return headers


def _internal_headers() -> dict[str, str]:
    return {"Content-Type": "application/json"}


def _now_ms() -> int:
    return int(time.time() * 1000)


def _range_filter(time_range: dict[str, Any]) -> dict[str, Any]:
    """Build an OpenSearch range query from a time_range dict.

    Accepts keys: hours (int), from/to (ISO8601 strings), or gte/lte (epoch ms).
    """
    if "hours" in time_range:
        hours = int(time_range["hours"])
        return {"range": {"@timestamp": {"gte": f"now-{hours}h", "lte": "now"}}}
    if "gte" in time_range or "from" in time_range:
        gte = time_range.get("gte") or time_range.get("from")
        lte = time_range.get("lte") or time_range.get("to", "now")
        return {"range": {"@timestamp": {"gte": gte, "lte": lte}}}
    # Default: last 24 hours
    return {"range": {"@timestamp": {"gte": "now-24h", "lte": "now"}}}


async def _search_internal(index: str, body: dict[str, Any], size: int = 50) -> list[dict]:
    """Execute an OpenSearch DSL query directly on port 9200."""
    url = f"{_BASE_INTERNAL}/{index}/_search"
    body.setdefault("size", size)
    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        resp = await client.post(url, headers=_internal_headers(), json=body)
        resp.raise_for_status()
        data = resp.json()
        hits = data.get("hits", {}).get("hits", [])
        return [h.get("_source", h) for h in hits]


async def _search_via_api(endpoint: str, params: dict[str, Any] | None = None) -> Any:
    """Query the public ingestion API (limited surface area)."""
    url = f"{_BASE_PUBLIC}{endpoint}"
    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        resp = await client.get(url, headers=_public_headers(), params=params)
        resp.raise_for_status()
        return resp.json()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def query_alerts(
    filters: dict[str, Any],
    time_range: dict[str, Any],
) -> list[dict]:
    """Search IDS/IPS alerts from the paloalto-events index.

    Args:
        filters:    Optional key/value pairs to match (e.g. {"severity": "critical"}).
        time_range: Time window dict.  Keys: hours | from+to | gte+lte.

    Returns:
        List of alert documents.
    """
    if _USE_INTERNAL:
        must: list[dict] = [_range_filter(time_range)]
        for k, v in filters.items():
            must.append({"match": {k: v}})
        body: dict[str, Any] = {
            "query": {"bool": {"must": must}},
            "sort": [{"@timestamp": {"order": "desc"}}],
        }
        return await _search_internal("paloalto-events", body)

    # Public API fallback — /v1/stats contains aggregated alert counts
    try:
        data = await _search_via_api("/v1/stats")
        # Wrap the aggregated stats as a pseudo-alert document so callers
        # always receive a list.
        return [{"source": "stats-api", "data": data, "filters": filters}]
    except httpx.HTTPError as exc:
        logger.warning("query_alerts via public API failed: %s", exc)
        return []


async def query_flows(
    src_ip: str | None,
    dst_ip: str | None,
    port: int | None,
    time_range: dict[str, Any],
) -> list[dict]:
    """Search network flow records from the corelight-events index.

    Args:
        src_ip:     Filter by source IP (optional).
        dst_ip:     Filter by destination IP (optional).
        port:       Filter by destination port (optional).
        time_range: Time window dict.

    Returns:
        List of flow documents.
    """
    if _USE_INTERNAL:
        must: list[dict] = [_range_filter(time_range)]
        if src_ip:
            must.append({"term": {"id.orig_h": src_ip}})
        if dst_ip:
            must.append({"term": {"id.resp_h": dst_ip}})
        if port is not None:
            must.append({"term": {"id.resp_p": port}})
        body: dict[str, Any] = {
            "query": {"bool": {"must": must}},
            "sort": [{"@timestamp": {"order": "desc"}}],
        }
        return await _search_internal("corelight-events", body)

    try:
        data = await _search_via_api("/v1/stats")
        return [{"source": "stats-api", "data": data, "src_ip": src_ip, "dst_ip": dst_ip, "port": port}]
    except httpx.HTTPError as exc:
        logger.warning("query_flows via public API failed: %s", exc)
        return []


async def query_dns(
    domain: str | None,
    client_ip: str | None,
    time_range: dict[str, Any],
) -> list[dict]:
    """Look up DNS events from the corelight-events index.

    Args:
        domain:    Filter by queried domain (optional, wildcard-friendly).
        client_ip: Filter by DNS client IP (optional).
        time_range: Time window dict.

    Returns:
        List of DNS event documents.
    """
    if _USE_INTERNAL:
        must: list[dict] = [
            _range_filter(time_range),
            {"term": {"_index": "corelight-events"}},
            {"exists": {"field": "query"}},  # DNS events have a query field
        ]
        if domain:
            if "*" in domain or "?" in domain:
                must.append({"wildcard": {"query": domain.lower()}})
            else:
                must.append({"match": {"query": domain}})
        if client_ip:
            must.append({"term": {"id.orig_h": client_ip}})
        body: dict[str, Any] = {
            "query": {"bool": {"must": must}},
            "sort": [{"@timestamp": {"order": "desc"}}],
        }
        return await _search_internal("corelight-events", body)

    try:
        data = await _search_via_api("/v1/stats")
        return [{"source": "stats-api", "data": data, "domain": domain, "client_ip": client_ip}]
    except httpx.HTTPError as exc:
        logger.warning("query_dns via public API failed: %s", exc)
        return []


async def enrich_ip(ip: str) -> dict[str, Any]:
    """Retrieve all events for a given IP across all indices.

    Returns a dict with keys: flows, alerts, dns, summary.
    """
    time_range = {"hours": 24}

    if _USE_INTERNAL:
        indices = ["corelight-events", "paloalto-events", "partner-events"]
        must = [
            _range_filter(time_range),
            {
                "bool": {
                    "should": [
                        {"term": {"id.orig_h": ip}},
                        {"term": {"id.resp_h": ip}},
                        {"term": {"src_ip": ip}},
                        {"term": {"dst_ip": ip}},
                        {"term": {"source_ip": ip}},
                    ],
                    "minimum_should_match": 1,
                }
            },
        ]
        body: dict[str, Any] = {
            "query": {"bool": {"must": must}},
            "sort": [{"@timestamp": {"order": "desc"}}],
        }
        results: list[dict] = []
        for idx in indices:
            try:
                hits = await _search_internal(idx, body, size=20)
                results.extend(hits)
            except Exception as exc:
                logger.warning("enrich_ip index=%s error: %s", idx, exc)

        return {
            "ip": ip,
            "total_events": len(results),
            "events": results[:50],
            "summary": f"Found {len(results)} events for {ip} across {len(indices)} indices.",
        }

    # Public API
    try:
        stats = await _search_via_api("/v1/stats")
        return {
            "ip": ip,
            "source": "stats-api",
            "data": stats,
            "summary": f"IP enrichment for {ip} — direct index access not available via public API.",
        }
    except httpx.HTTPError as exc:
        logger.warning("enrich_ip via public API failed: %s", exc)
        return {"ip": ip, "error": str(exc)}


async def get_top_talkers(
    time_range: dict[str, Any],
    limit: int = 10,
) -> list[dict]:
    """Return the top source IPs by event volume.

    Args:
        time_range: Time window dict.
        limit:      Maximum number of IPs to return (default 10).

    Returns:
        List of dicts with keys: ip, count.
    """
    if _USE_INTERNAL:
        body: dict[str, Any] = {
            "size": 0,
            "query": {"bool": {"must": [_range_filter(time_range)]}},
            "aggs": {
                "top_src_ips": {
                    "terms": {
                        "field": "id.orig_h",
                        "size": limit,
                        "order": {"_count": "desc"},
                    }
                }
            },
        }
        url = f"{_BASE_INTERNAL}/corelight-events,paloalto-events,partner-events/_search"
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            resp = await client.post(url, headers=_internal_headers(), json=body)
            resp.raise_for_status()
            data = resp.json()
        buckets = data.get("aggregations", {}).get("top_src_ips", {}).get("buckets", [])
        return [{"ip": b["key"], "count": b["doc_count"]} for b in buckets]

    try:
        data = await _search_via_api("/v1/stats")
        return [{"ip": "N/A", "count": 0, "note": "Direct aggregation not available via public API", "stats": data}]
    except httpx.HTTPError as exc:
        logger.warning("get_top_talkers via public API failed: %s", exc)
        return []


async def search_events(
    query: str,
    index: str,
    time_range: dict[str, Any],
) -> list[dict]:
    """Freeform full-text search across an OpenSearch index.

    Args:
        query:      Lucene / simple query string (e.g. "port scan AND src_ip:*").
        index:      Index name: 'corelight-events', 'paloalto-events', 'partner-events'.
        time_range: Time window dict.

    Returns:
        List of matching documents.
    """
    valid_indices = {"corelight-events", "paloalto-events", "partner-events"}
    if index not in valid_indices:
        raise ValueError(f"Invalid index '{index}'. Must be one of {valid_indices}.")

    if _USE_INTERNAL:
        body: dict[str, Any] = {
            "query": {
                "bool": {
                    "must": [
                        {"query_string": {"query": query, "default_operator": "AND"}},
                        _range_filter(time_range),
                    ]
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}],
        }
        return await _search_internal(index, body)

    try:
        data = await _search_via_api("/v1/stats")
        return [{"source": "stats-api", "query": query, "index": index, "data": data}]
    except httpx.HTTPError as exc:
        logger.warning("search_events via public API failed: %s", exc)
        return []
