#!/usr/bin/env python3
"""
GeoIP Enricher - Geolocate attacker IPs using ip-api.com (free, no key needed)
Rate limited to ~45 req/min to respect free tier.
"""

import json
import time
import sys
import argparse
import urllib.request
import urllib.error

def geolocate_ip(ip):
    """Query ip-api.com for geolocation data."""
    url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org,as"
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            data = json.loads(r.read().decode())
            if data.get("status") == "success":
                return data
    except Exception as e:
        pass
    return None

def enrich(json_path, output_path, max_ips=20):
    with open(json_path) as f:
        data = json.load(f)

    top_ips = [ip for ip, _ in data["top_ips"][:max_ips]]
    geo_data = {}

    print(f"[*] Geolocating top {len(top_ips)} IPs (rate-limited ~1 req/1.5s)...")
    for i, ip in enumerate(top_ips):
        print(f"  [{i+1}/{len(top_ips)}] {ip} ...", end=" ", flush=True)
        result = geolocate_ip(ip)
        if result:
            geo_data[ip] = result
            print(f"{result.get('country','?')} / {result.get('city','?')} / {result.get('isp','?')}")
        else:
            geo_data[ip] = {"error": "lookup failed"}
            print("failed")
        time.sleep(1.4)  # ~43 req/min, safe under 45 limit

    # Merge into main data
    data["geo"] = geo_data

    # Country summary
    country_count = {}
    for ip_info in geo_data.values():
        country = ip_info.get("country", "Unknown")
        country_count[country] = country_count.get(country, 0) + 1
    data["top_countries"] = sorted(country_count.items(), key=lambda x: -x[1])

    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"\n[+] Enriched data saved → {output_path}")
    print("\n🌍 Top Countries:")
    for country, count in data["top_countries"][:10]:
        bar = "█" * count
        print(f"   {country:<25} {count:>3} IPs  {bar}")

def main():
    parser = argparse.ArgumentParser(description="Geolocate top attacker IPs")
    parser.add_argument("json_file", help="analysis.json from analyze.py")
    parser.add_argument("-o", "--output", default="output/analysis_geo.json")
    parser.add_argument("-n", "--max-ips", type=int, default=20,
                        help="Max IPs to geolocate (default: 20)")
    args = parser.parse_args()

    enrich(args.json_file, args.output, args.max_ips)

if __name__ == "__main__":
    main()
