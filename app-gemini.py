import requests
import yaml
from urllib.parse import urlparse, parse_qs, unquote
import sys
import os

# Force UTF-8 output for console (useful on Windows)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore

# Create 'files' directory if it doesn't exist
os.makedirs("files", exist_ok=True)
OUTPUT_FILE = os.path.join("files", "clash_gemini.yaml")

# ------------------------------------------------------
# Input settings
# ------------------------------------------------------
SOURCE_URL = "https://raw.githubusercontent.com/x45fh56/tgs/refs/heads/main/Servers/Protocols/Categorized_Servers/1_VLESS_REALITY_TCP.txt"

# ------------------------------------------------------
# Base configuration (inspired by configs.ts and inbounds.ts)
# ------------------------------------------------------
BASE_CONFIG = {
    "mixed-port": 7890,
    "ipv6": True,
    "allow-lan": False,
    "mode": "rule",
    "log-level": "silent",
    "external-controller": "127.0.0.1:9090",
    "external-ui": "ui",
    "external-ui-url": "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip",
    "tun": {
        "enable": True,
        "stack": "mixed",
        "auto-route": True,
        "strict-route": True,
        "auto-detect-interface": True,
        "dns-hijack": ["any:53", "tcp://any:53"],
        "mtu": 9000
    },
    "sniffer": {
        "enable": True,
        "force-dns-mapping": True,
        "parse-pure-ip": True,
        "override-destination": True,
        "sniff": {
            "HTTP": {"ports": [80, 8080, 8880, 2052, 2082, 2086, 2095]},
            "TLS": {"ports": [443, 8443, 2053, 2083, 2087, 2096]}
        }
    },
    "dns": {
        "enable": True,
        "ipv6": True,
        "enhanced-mode": "fake-ip",
        "nameserver": ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"],
        "fallback": ["https://1.0.0.1/dns-query", "https://8.8.4.4/dns-query"],
    }
}

# ------------------------------------------------------
# Helper functions (simulating outbounds.ts logic)
# ------------------------------------------------------

def build_transport(net_type, path, host, service_name, header_type):
    transport = {}
    if path and "?" in path:
        path = path.split("?")[0]
    if not path:
        path = "/"

    if net_type == 'tcp':
        if header_type == 'http':
            transport = {
                "network": "http",
                "http-opts": {
                    "method": "GET",
                    "path": [path],
                    "headers": {"Host": [host]} if host else {}
                }
            }
        else:
            transport = {"network": "tcp"}

    elif net_type == 'ws':
        transport = {
            "network": "ws",
            "ws-opts": {
                "path": path,
                "headers": {"Host": host} if host else {}
            }
        }

    elif net_type == 'grpc':
        transport = {
            "network": "grpc",
            "grpc-opts": {
                "grpc-service-name": service_name
            }
        }
    return transport


def build_tls(security, sni, fp, pbk, sid, alpn):
    if security not in ["tls", "reality"]:
        return {}

    tls_config = {
        "tls": True,
        "servername": sni,
        "client-fingerprint": "random" if fp == "randomized" else fp
    }

    if security == "tls":
        if alpn:
            tls_config["alpn"] = alpn.split(",")
        tls_config["skip-cert-verify"] = True

    elif security == "reality" and pbk and sid:
        tls_config["reality-opts"] = {
            "public-key": pbk,
            "short-id": sid
        }
    
    return tls_config


def parse_vless_bpb_style(link):
    if not link.startswith("vless://"):
        return None

    try:
        parsed = urlparse(link)
        params = parse_qs(parsed.query)
        
        uuid_val = parsed.username
        server = parsed.hostname
        port = parsed.port
        name = unquote(parsed.fragment) if parsed.fragment else "VLESS Node"
        
        security = params.get("security", [""])[0]
        net_type = params.get("type", ["tcp"])[0]
        sni = params.get("sni", [""])[0] or server
        pbk = params.get("pbk", [""])[0]
        sid = params.get("sid", [""])[0]
        fp = params.get("fp", ["chrome"])[0]
        path = params.get("path", ["/"])[0]
        host = params.get("host", [""])[0]
        service_name = params.get("serviceName", [""])[0]
        header_type = params.get("headerType", [""])[0]
        flow = params.get("flow", [""])[0]
        alpn = params.get("alpn", [""])[0]

        tls_settings = build_tls(security, sni, fp, pbk, sid, alpn)
        transport_settings = build_transport(net_type, path, host, service_name, header_type)

        proxy = {
            "name": name,
            "type": "vless",
            "server": server,
            "port": port,
            "uuid": uuid_val,
            "tfo": False,
            "udp": True,
            "ip-version": "ipv4-prefer",
        }

        if flow:
            proxy["flow"] = flow

        proxy.update(tls_settings)
        proxy.update(transport_settings)

        return {k: v for k, v in proxy.items() if v is not None}

    except Exception:
        return None


# ------------------------------------------------------
# Main execution (with duplicate name handling)
# ------------------------------------------------------

if __name__ == "__main__":
    print(f"Downloading from: {SOURCE_URL}")
    try:
        response = requests.get(SOURCE_URL, timeout=15)
        response.raise_for_status()
        links = response.text.splitlines()
    except Exception as e:
        print(f"Failed to download: {e}")
        sys.exit(1)

    proxies = []
    name_counter = {}  # Track duplicate names

    for link in links:
        if link.strip():
            p = parse_vless_bpb_style(link.strip())
            if p:
                original_name = p["name"]
                
                if original_name in name_counter:
                    name_counter[original_name] += 1
                    new_name = f"{original_name}_{name_counter[original_name]}"
                    p["name"] = new_name
                else:
                    name_counter[original_name] = 1
                
                proxies.append(p)

    print(f"Parsed {len(proxies)} proxies.")

    if proxies:
        proxy_names = [p["name"] for p in proxies]
        
        proxy_groups = [
            {
                "name": "✅ Selector",
                "type": "select",
                "proxies": ["💦 Best Ping 🚀"] + proxy_names
            },
            {
                "name": "💦 Best Ping 🚀",
                "type": "url-test",
                "url": "https://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 50,
                "proxies": proxy_names
            }
        ]

        final_config = BASE_CONFIG.copy()
        final_config["proxies"] = proxies
        final_config["proxy-groups"] = proxy_groups
        final_config["rules"] = ["MATCH,✅ Selector"]

        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            yaml.dump(final_config, f, allow_unicode=True, sort_keys=False)
        
        print(f"✅ Config file created: {OUTPUT_FILE}")
        print("Duplicate name issue resolved.")
    else:
        print("❌ No valid servers found.")