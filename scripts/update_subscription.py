#!/usr/bin/env python3
import base64
import collections
import concurrent.futures
import ipaddress
import json
import socket
import time
import urllib.parse
import urllib.request
from pathlib import Path


SOURCE_URL = "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/v2ray-base64.txt"
OUTPUT_DIR = Path("subscriptions")
PLAIN_OUTPUT = OUTPUT_DIR / "shadowrocket-filtered.txt"
BASE64_OUTPUT = OUTPUT_DIR / "shadowrocket-filtered-base64.txt"
SUMMARY_OUTPUT = OUTPUT_DIR / "selection-summary.json"
SELECTED_LIMIT = 80
BUCKET_LIMIT = 3
TCP_TIMEOUT_SECONDS = 2.0


def decode_subscription(content):
    text = content.strip()
    try:
        return base64.b64decode(text + "=" * ((4 - len(text) % 4) % 4)).decode(
            "utf-8", "ignore"
        )
    except Exception:
        return text


def parse_node(link):
    protocol = link.split("://", 1)[0].lower()
    host = ""
    port = None
    name = ""
    sni = ""
    security = ""

    try:
        if protocol == "vmess":
            payload = link.split("://", 1)[1]
            data = json.loads(
                base64.b64decode(payload + "=" * ((4 - len(payload) % 4) % 4)).decode(
                    "utf-8", "ignore"
                )
            )
            host = data.get("add") or ""
            port = int(data.get("port") or 0)
            name = data.get("ps") or ""
            sni = data.get("sni") or data.get("host") or ""
            security = data.get("tls") or ""
        else:
            parsed = urllib.parse.urlsplit(link)
            host = parsed.hostname or ""
            port = parsed.port
            name = urllib.parse.unquote(parsed.fragment or "")
            query = urllib.parse.parse_qs(parsed.query)
            sni = (query.get("sni") or query.get("peer") or query.get("host") or [""])[0]
            security = (query.get("security") or [""])[0]
    except Exception:
        pass

    return {
        "link": link,
        "protocol": protocol,
        "host": host,
        "port": port,
        "name": name,
        "sni": sni,
        "security": security,
    }


def tcp_latency_ms(node):
    start = time.perf_counter()
    try:
        with socket.create_connection(
            (node["host"], node["port"]), timeout=TCP_TIMEOUT_SECONDS
        ):
            return (time.perf_counter() - start) * 1000
    except Exception:
        return None


def endpoint_bucket(host):
    try:
        ip = ipaddress.ip_address(host)
        if ip.version == 4:
            return ".".join(host.split(".")[:3])
        return host.split(":")[0]
    except Exception:
        return host.lower()


def select_nodes(nodes):
    endpoint_nodes = {}
    for node in nodes:
        if not node["host"] or not node["port"]:
            continue
        key = (node["protocol"], node["host"], node["port"])
        if key not in endpoint_nodes or len(node["name"]) > len(endpoint_nodes[key]["name"]):
            endpoint_nodes[key] = node

    unique_nodes = list(endpoint_nodes.values())
    with concurrent.futures.ThreadPoolExecutor(max_workers=80) as executor:
        for node, latency in zip(unique_nodes, executor.map(tcp_latency_ms, unique_nodes)):
            node["tcp_ms"] = latency

    alive_nodes = [node for node in unique_nodes if node["tcp_ms"] is not None]
    protocol_rank = {"trojan": 0, "vless": 1, "vmess": 2, "ss": 3, "hysteria2": 4, "hy2": 4}
    alive_nodes.sort(
        key=lambda node: (node["tcp_ms"], protocol_rank.get(node["protocol"], 9))
    )

    bucket_count = collections.Counter()
    selected = []
    for node in alive_nodes:
        bucket = endpoint_bucket(node["host"])
        if bucket_count[bucket] >= BUCKET_LIMIT:
            continue
        selected.append(node)
        bucket_count[bucket] += 1
        if len(selected) >= SELECTED_LIMIT:
            break

    return unique_nodes, alive_nodes, selected


def main():
    with urllib.request.urlopen(SOURCE_URL, timeout=30) as response:
        content = response.read().decode("utf-8", "ignore")

    decoded = decode_subscription(content)
    links = [line.strip() for line in decoded.replace("\r", "\n").split("\n") if "://" in line]
    nodes = [parse_node(link) for link in links]
    unique_nodes, alive_nodes, selected = select_nodes(nodes)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    plain_content = "\n".join(node["link"] for node in selected) + "\n"
    PLAIN_OUTPUT.write_text(plain_content)
    BASE64_OUTPUT.write_text(base64.b64encode(plain_content.encode()).decode() + "\n")

    summary = {
        "source_url": SOURCE_URL,
        "decoded_links": len(links),
        "parseable_nodes": sum(1 for node in nodes if node["host"] and node["port"]),
        "unique_endpoints": len(unique_nodes),
        "tcp_alive": len(alive_nodes),
        "selected": len(selected),
        "protocols": dict(collections.Counter(node["protocol"] for node in selected)),
        "top10": [
            {
                "ms": round(node["tcp_ms"], 1),
                "protocol": node["protocol"],
                "host": node["host"],
                "port": node["port"],
                "name": node["name"][:80],
            }
            for node in selected[:10]
        ],
    }
    SUMMARY_OUTPUT.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
