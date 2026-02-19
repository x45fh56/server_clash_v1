import requests
import yaml
from urllib.parse import urlparse, parse_qs, unquote
import os

 
os.makedirs("files", exist_ok=True)
OUTPUT_FILE = os.path.join("files", "clash_gpt.yaml")

SOURCE_URL = "https://raw.githubusercontent.com/x45fh56/tgs/refs/heads/main/Servers/Protocols/Categorized_Servers/1_VLESS_REALITY_TCP.txt"


def make_unique(name, existing):
    """Ensure proxy name is unique to prevent duplicate name errors in Clash"""
    original = name
    counter = 1
    while name in existing:
        name = f"{original}_{counter}"
        counter += 1
    return name


def parse_vless(link, existing_names):
    """Parse VLESS link and convert to Clash Meta proxy format"""
    link = link.strip()
    if not link.startswith("vless://"):
        return None

    parsed = urlparse(link)

    uuid_value = parsed.username
    server = parsed.hostname
    port = parsed.port

    params = parse_qs(parsed.query)

    remark = unquote(parsed.fragment) if parsed.fragment else f"{server}:{port}"
    remark = make_unique(remark, existing_names)

    security = params.get("security", ["none"])[0]
    sni = params.get("sni", [server])[0]
    fp = params.get("fp", ["chrome"])[0]
    pbk = params.get("pbk", [None])[0]
    sid = params.get("sid", [None])[0]
    flow = params.get("flow", [""])[0]

    proxy = {
        "name": remark,
        "type": "vless",
        "server": server,
        "port": port,
        "uuid": uuid_value,
        "network": "tcp",
        "udp": True,
        "tls": security in ["tls", "reality"],
        "client-fingerprint": fp,
        "servername": sni,
        "skip-cert-verify": False
    }

    if flow:
        proxy["flow"] = flow

    if security == "reality" and pbk and sid:
        proxy["reality-opts"] = {
            "public-key": pbk,
            "short-id": sid
        }

    return proxy


def main():
    response = requests.get(SOURCE_URL)
    lines = response.text.splitlines()

    proxies = []
    existing_names = set()

    for line in lines:
        proxy = parse_vless(line, existing_names)
        if proxy:
            existing_names.add(proxy["name"])
            proxies.append(proxy)

    config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "AUTO",
                "type": "url-test",
                "url": "https://www.gstatic.com/generate_204",
                "interval": 300,
                "proxies": [p["name"] for p in proxies]
            },
            {
                "name": "SELECT",
                "type": "select",
                "proxies": ["AUTO"] + [p["name"] for p in proxies]
            }
        ],
        "rules": [
            "MATCH,SELECT"
        ]
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)

    print(f"Done! {len(proxies)} servers saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()