"""
Burp Suite Export Module.

Exports discovered endpoints and URLs into Burp Suite compatible formats:
- Burp sitemap XML (importable via Project > Import)
- Simple URL list (usable with Burp Intruder/Scanner)
"""

import xml.etree.ElementTree as ET
from xml.dom import minidom
from typing import List
from base64 import b64encode
from urllib.parse import urlparse

from ..storage.models import ScanResult, Endpoint


def generate_burp_xml(result: ScanResult) -> str:
    """
    Generate Burp Suite sitemap XML from scan results.
    Format compatible with Burp Suite Professional and Community.
    """
    root = ET.Element("items", burpVersion="2024.1", exportTime="BundleSpy Export")

    # Add discovered endpoints
    seen = set()
    all_urls = []

    # From endpoints
    for ep in result.endpoints:
        if ep.url.startswith("http") and ep.url not in seen:
            all_urls.append(ep.url)
            seen.add(ep.url)

    # From JS files
    for js in result.js_files:
        if js.url.startswith("http") and js.url not in seen:
            all_urls.append(js.url)
            seen.add(js.url)

    for url in sorted(all_urls):
        try:
            parsed = urlparse(url)
            item   = ET.SubElement(root, "item")

            ET.SubElement(item, "time").text       = "0"
            ET.SubElement(item, "url").text        = url
            ET.SubElement(item, "host",
                          ip="").text              = parsed.netloc
            ET.SubElement(item, "port").text       = str(parsed.port or (443 if parsed.scheme == "https" else 80))
            ET.SubElement(item, "protocol").text   = parsed.scheme
            ET.SubElement(item, "method").text     = "GET"
            ET.SubElement(item, "path").text       = parsed.path or "/"
            ET.SubElement(item, "extension")
            ET.SubElement(item, "request",
                          base64="true").text      = b64encode(
                f"GET {parsed.path or '/'} HTTP/1.1\r\nHost: {parsed.netloc}\r\n\r\n".encode()
            ).decode()
            ET.SubElement(item, "status").text     = ""
            ET.SubElement(item, "responselength").text = "0"
            ET.SubElement(item, "mimetype").text   = ""
            ET.SubElement(item, "response",
                          base64="true").text      = ""
            ET.SubElement(item, "comment").text    = "Discovered by BundleSpy"
        except Exception:
            continue

    # Pretty print
    raw = ET.tostring(root, encoding="unicode")
    try:
        pretty = minidom.parseString(raw).toprettyxml(indent="  ")
        # Remove the XML declaration added by minidom
        lines = pretty.split("\n")
        return "\n".join(lines[1:])
    except Exception:
        return raw


def generate_url_list(result: ScanResult) -> str:
    """
    Generate a plain URL list for use with Burp Intruder or other tools.
    One URL per line, deduplicated and sorted.
    """
    seen = set()
    urls = []

    for ep in result.endpoints:
        if ep.url.startswith("http") and ep.url not in seen:
            urls.append(ep.url)
            seen.add(ep.url)

    for js in result.js_files:
        if js.url.startswith("http") and js.url not in seen:
            urls.append(js.url)
            seen.add(js.url)

    return "\n".join(sorted(urls))
