import argparse
import os
import sys
import urllib.parse
import urllib.request
from typing import Dict, List, Optional, Tuple

import yaml

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore

DEFAULT_SOURCES: List[str] = [
    "https://raw.githubusercontent.com/x45fh56/tgs/refs/heads/main/Servers/Protocols/Categorized_Servers/1_VLESS_REALITY_TCP.txt",
]

MIXED_PORT          = 7890
ALLOW_LAN           = True
MODE                = "rule"
EXTERNAL_CONTROLLER = "127.0.0.1:9090"
EXTERNAL_UI_URL     = "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip"
PING_URL            = "https://www.gstatic.com/generate_204"
PING_INTERVAL       = 300
PING_TOLERANCE      = 50


def _info(msg: str) -> None:
    print(f"  ✓  {msg}")

def _warn(msg: str) -> None:
    print(f"  ⚠  {msg}", file=sys.stderr)

def _step(msg: str) -> None:
    print(f"\n▶  {msg}")


def fetch_text(url: str, timeout: int = 15) -> Optional[str]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "clash-builder/2.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8")
    except Exception as exc:
        _warn(f"Could not fetch {url}: {exc}")
        return None


def parse_vless_url(line: str) -> Optional[Dict]:
    line = line.strip()
    if not line.startswith("vless://"):
        return None

    if "#" in line:
        url_part, raw_remark = line.split("#", 1)
        remark = urllib.parse.unquote(raw_remark).strip() or f"server-{id(line) & 0xFFFF:04x}"
    else:
        url_part = line
        remark = f"server-{id(line) & 0xFFFF:04x}"

    try:
        parsed = urllib.parse.urlparse(url_part)
        uuid_val, host_port = parsed.netloc.split("@", 1)
        server_raw, port_str = host_port.rsplit(":", 1)
        server = server_raw.strip("[]")
        port = int(port_str)
    except (ValueError, AttributeError) as exc:
        _warn(f"Parse error ({exc}): {line[:70]}")
        return None

    params = urllib.parse.parse_qs(parsed.query)

    if params.get("security", [""])[0].lower() != "reality":
        return None

    pbk = params.get("pbk", [None])[0]
    sni = params.get("sni", [""])[0]
    if not pbk or not sni:
        _warn(f"Missing pbk or sni, skipping: {remark!r}")
        return None

    raw_flow = params.get("flow", [""])[0]
    spx_raw  = params.get("spx",  [""])[0]

    return {
        "_key":  f"{server}:{port}",
        "name":  remark,
        "server": server,
        "port":   port,
        "uuid":   uuid_val,
        "flow":   raw_flow if raw_flow == "xtls-rprx-vision" else None,
        "sni":    sni,
        "fp":     params.get("fp", ["chrome"])[0],
        "pbk":    pbk,
        "sid":    params.get("sid", [""])[0],
        "spx":    urllib.parse.unquote(spx_raw) if spx_raw else None,
    }


def dedup_and_rename(raw: List[Dict]) -> Tuple[List[Dict], int]:
    seen_keys:  set = set()
    seen_names: Dict[str, int] = {}
    result:     List[Dict] = []
    removed = 0

    for p in raw:
        key = p["_key"]
        if key in seen_keys:
            removed += 1
            continue
        seen_keys.add(key)

        base = p["name"]
        if base not in seen_names:
            seen_names[base] = 0
        else:
            seen_names[base] += 1
            p["name"] = f"{base} - {seen_names[base]}"

        result.append(p)

    return result, removed


def build_dns() -> Dict:
    return {
        "enable": True,
        "ipv6": True,
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "listen": "0.0.0.0:53",
        "use-hosts": True,
        "nameserver": [
            "https://1.1.1.1/dns-query",
            "https://8.8.8.8/dns-query",
        ],
        "fallback": [
            "tls://1.0.0.1:853",
            "tls://8.8.4.4:853",
        ],
        "fallback-filter": {
            "geoip": True,
            "geoip-code": "IR",
            "ipcidr": ["240.0.0.0/4", "0.0.0.0/32"],
        },
    }


def build_tun() -> Dict:
    return {
        "enable": True,
        "stack": "mixed",
        "auto-route": True,
        "strict-route": True,
        "auto-detect-interface": True,
        "dns-hijack": ["any:53", "tcp://any:53"],
        "mtu": 9000,
    }


def build_sniffer() -> Dict:
    return {
        "enable": True,
        "force-dns-mapping": True,
        "parse-pure-ip": True,
        "override-destination": True,
        "sniff": {
            "HTTP": {"ports": [80, 8080, 8880, 2052, 2082, 2086, 2095]},
            "TLS":  {"ports": [443, 8443, 2053, 2083, 2087, 2096]},
        },
    }


def build_proxy_entry(p: Dict) -> Dict:
    entry: Dict = {
        "name":               p["name"],
        "type":               "vless",
        "server":             p["server"],
        "port":               p["port"],
        "uuid":               p["uuid"],
        "network":            "tcp",
        "tls":                True,
        "udp":                True,
        "servername":         p["sni"],
        "client-fingerprint": p["fp"],
        "reality-opts": {
            "public-key": p["pbk"],
            "short-id":   p["sid"],
        },
    }
    if p.get("flow"):
        entry["flow"] = p["flow"]
    if p.get("spx"):
        entry["spider-x"] = p["spx"]
    return entry


def build_config(proxies: List[Dict], use_tun: bool, log_level: str) -> Dict:
    names = [p["name"] for p in proxies]

    proxy_groups: List[Dict] = [
        {
            "name": "✅ Selector",
            "type": "select",
            "proxies": ["🚀 Best Ping"] + names + ["DIRECT", "REJECT"],
        },
        {
            "name": "🚀 Best Ping",
            "type": "url-test",
            "url": PING_URL,
            "interval": PING_INTERVAL,
            "tolerance": PING_TOLERANCE,
            "proxies": names,
        },
    ]

    rules = [
        "GEOIP,IR,DIRECT",
        "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
        "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
        "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
        "MATCH,✅ Selector",
    ]

    config: Dict = {
        "mixed-port":          MIXED_PORT,
        "allow-lan":           ALLOW_LAN,
        "mode":                MODE,
        "log-level":           log_level,
        "ipv6":                True,
        "external-controller": EXTERNAL_CONTROLLER,
        "external-ui":         "ui",
        "external-ui-url":     EXTERNAL_UI_URL,
        "profile":             {"store-selected": True, "store-fake-ip": True},
        "dns":                 build_dns(),
        "sniffer":             build_sniffer(),
        "proxies":             [build_proxy_entry(p) for p in proxies],
        "proxy-groups":        proxy_groups,
        "rules":               rules,
    }

    if use_tun:
        config["tun"] = build_tun()

    return config


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Generate a Clash Meta / mihomo config from VLESS-Reality sources."
    )
    p.add_argument("-u", "--urls", nargs="+", metavar="URL",
                   help="Source URLs (overrides built-in defaults)")
    p.add_argument("-o", "--output", default=os.path.join("files", "clash_claude.yaml"),
                   metavar="PATH", help="Output YAML path")
    p.add_argument("--no-tun", action="store_true",
                   help="Disable TUN mode")
    p.add_argument("--log-level",
                   choices=["silent", "error", "warning", "info", "debug"],
                   default="silent", help="Clash log level")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    sources     = args.urls or DEFAULT_SOURCES
    output_path = args.output
    use_tun     = not args.no_tun

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    _step(f"Downloading from {len(sources)} source(s)…")
    all_lines: List[str] = []
    for url in sources:
        text = fetch_text(url)
        if text:
            lines = [l for l in text.splitlines() if l.strip()]
            _info(f"{len(lines):>4} lines  ←  {url}")
            all_lines.extend(lines)
        else:
            _warn(f"Skipped (unreachable): {url}")

    if not all_lines:
        print("\n✗  No source data retrieved. Aborting.")
        sys.exit(1)

    _step("Parsing VLESS-Reality links…")
    raw_proxies: List[Dict] = []
    skipped = 0
    for line in all_lines:
        p = parse_vless_url(line)
        if p:
            raw_proxies.append(p)
        elif line.startswith("vless://"):
            skipped += 1

    _info(f"Parsed:  {len(raw_proxies)} valid")
    if skipped:
        _warn(f"Skipped: {skipped} (non-Reality or missing fields)")

    if not raw_proxies:
        print("\n✗  No valid proxies found. Aborting.")
        sys.exit(1)

    _step("Deduplicating…")
    proxies, removed = dedup_and_rename(raw_proxies)
    _info(f"Unique:  {len(proxies)}  (removed {removed} duplicate server:port entries)")

    _step("Building Clash config…")
    config = build_config(proxies, use_tun=use_tun, log_level=args.log_level)
    _info(f"TUN mode:  {'enabled' if use_tun else 'disabled'}")
    _info(f"Log level: {args.log_level}")
    _info(f"Rules:     GEOIP,IR,DIRECT + LAN ranges + MATCH")

    _step(f"Writing → {output_path}")
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(config, f, allow_unicode=True, sort_keys=False,
                           indent=2, default_flow_style=False)
        _info(f"Done — {os.path.getsize(output_path):,} bytes")
    except OSError as exc:
        print(f"\n✗  Could not write file: {exc}")
        sys.exit(1)

    print(f"\n✅  Config ready: {output_path}")
    print(   "   Compatible with: Clash Meta / mihomo / Stash")


if __name__ == "__main__":
    main()
