"""
Infrastructure intelligence extractor.
Finds private IPs, internal hostnames, cloud metadata endpoints,
and staging/dev domains in JavaScript content.
Classifies each and marks them as report-only (never requests them).
"""

import re
import logging
from typing import List

from ..storage.models import InfrastructureItem
from ..safety.network import classify_url

logger = logging.getLogger("bundlespy.analysis.infrastructure")

RE_IPV4 = re.compile(
    r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    r'(?::\d+)?(?:/[^\s"\'<>]*)?'
)

RE_URL_WITH_HOST = re.compile(
    r'["\x27`](https?://([a-zA-Z0-9.\-]+)(?::\d+)?(?:/[^\s"\'`<>]*)?)["\x27`]'
)

RE_INTERNAL_HOST = re.compile(
    r'["\x27`]((?:https?://)?([a-zA-Z0-9\-]+\.(?:local|internal|corp|lan|intranet|int))'
    r'(?::\d+)?(?:/[^\s"\'`<>]*)?)["\x27`]',
    re.IGNORECASE,
)

CLOUD_METADATA_HOSTS = {
    "169.254.169.254", "metadata.google.internal",
    "metadata.google.com", "instance-data",
}


def _get_line(content: str, pos: int) -> int:
    return content[:pos].count("\n") + 1


def extract_infrastructure(content: str, file_url: str) -> List[InfrastructureItem]:
    items: List[InfrastructureItem] = []
    seen: set = set()

    def add(value: str, classification: str, line_no: int, confidence: float = 0.80) -> None:
        if value in seen:
            return
        seen.add(value)
        items.append(InfrastructureItem(
            value          = value,
            classification = classification,
            source_file    = file_url,
            line_number    = line_no,
            confidence     = confidence,
            action         = "report_only",
        ))

    # IPv4 addresses
    for match in RE_IPV4.finditer(content):
        ip      = match.group(1)
        line_no = _get_line(content, match.start())
        octets  = ip.split(".")
        # Basic validity check
        if not all(0 <= int(o) <= 255 for o in octets):
            continue
        full = match.group(0)

        if ip == "169.254.169.254":
            add(full, "CLOUD_METADATA", line_no, 0.99)
        elif ip.startswith("127.") or ip == "0.0.0.0":
            add(full, "LOOPBACK", line_no, 0.95)
        elif (ip.startswith("10.") or
              ip.startswith("192.168.") or
              (ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31)):
            add(full, "PRIVATE_IP", line_no, 0.92)
        else:
            # Public IP - still interesting
            add(full, "PUBLIC_IP", line_no, 0.70)

    # Internal hostnames
    for match in RE_INTERNAL_HOST.finditer(content):
        value   = match.group(1)
        line_no = _get_line(content, match.start())
        add(value, "INTERNAL_HOSTNAME", line_no, 0.85)

    # URLs classified by the network module
    for match in RE_URL_WITH_HOST.finditer(content):
        url      = match.group(1)
        hostname = match.group(2).lower()
        line_no  = _get_line(content, match.start())

        classification = classify_url(url)

        if classification in ("STAGING", "DEVELOPMENT"):
            add(url, classification, line_no, 0.75)
        elif classification == "CLOUD_METADATA":
            add(url, "CLOUD_METADATA", line_no, 0.99)
        elif hostname in CLOUD_METADATA_HOSTS:
            add(url, "CLOUD_METADATA", line_no, 0.99)

    return items
