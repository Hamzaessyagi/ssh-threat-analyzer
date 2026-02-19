#!/usr/bin/env python3
"""
GeoIP Service - ipinfo.io
Affiche le pays, la ville et l'ISP de chaque IP attackante
"""

import json
import time
import sys
import argparse
import requests
from typing import Final

# ─── Config ────────────────────────────────────────────────────
API_URL : Final[str] = "https://ipinfo.io"
TOKEN   : Final[str] = "7be1e947db03bd"

def get_country(ip: str) -> dict:
    """Retourne les infos GeoIP d'une IP via ipinfo.io"""
    try:
        response = requests.get(
            f"{API_URL}/{ip}",
            params={"token": TOKEN},
            timeout=5
        )
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def format_ip_info(ip: str, info: dict) -> str:
    """Formate joliment les infos d'une IP pour le terminal."""
    country  = info.get("country",  "??")
    city     = info.get("city",     "Unknown")
    region   = info.get("region",   "")
    org      = info.get("org",      "Unknown ISP")
    hostname = info.get("hostname", "")

    flag = get_flag(country)
    return (f"  {flag}  {ip:<20} "
            f"{country:<5} {city:<20} {org[:35]}")

def get_flag(country_code: str) -> str:
    """Convertit un code pays en emoji drapeau (marche sur Linux/Mac)."""
    if not country_code or len(country_code) != 2:
        return "  "
    try:
        return chr(0x1F1E6 + ord(country_code[0]) - ord('A')) + \
               chr(0x1F1E6 + ord(country_code[1]) - ord('A'))
    except:
        return "  "

def enrich_from_json(json_path: str, output_path: str, max_ips: int = 20):
    """Charge analysis.json, geolocalise les top IPs, sauvegarde enrichi."""
    with open(json_path, encoding="utf-8") as f:
        data = json.load(f)

    top_ips = [ip for ip, _ in data["top_ips"][:max_ips]]

    print(f"\n{'='*65}")
    print(f"  GEOIP LOOKUP - TOP {len(top_ips)} ATTACKER IPs  (ipinfo.io)")
    print(f"{'='*65}")
    print(f"  {'IP':<20} {'CC':<5} {'CITY':<20} {'ORG'}")
    print(f"  {'-'*60}")

    geo_data     = {}
    country_count = {}

    for i, ip in enumerate(top_ips):
        info = get_country(ip)
        geo_data[ip] = info

        country = info.get("country", "Unknown")
        country_count[country] = country_count.get(country, 0) + 1

        # Affichage ligne par ligne
        attempts = dict(data["top_ips"]).get(ip, 0)
        # Retrouve le count depuis top_ips
        for tip, tcount in data["top_ips"]:
            if tip == ip:
                attempts = tcount
                break

        line = format_ip_info(ip, info)
        print(f"{line}  [{attempts} attempts]")

        time.sleep(0.15)  # ipinfo est genereux mais on reste poli

    # Résumé par pays
    print(f"\n{'='*65}")
    print(f"  TOP COUNTRIES")
    print(f"{'='*65}")
    sorted_countries = sorted(country_count.items(), key=lambda x: -x[1])
    for country, count in sorted_countries[:10]:
        bar = "#" * count
        flag = get_flag(country)
        print(f"  {flag} {country:<5} {count:>4} IPs   {bar}")

    # Sauvegarde
    data["geo"]           = geo_data
    data["top_countries"] = sorted_countries

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"\n[+] Enriched data saved -> {output_path}")

def lookup_single(ip: str):
    """Lookup rapide d'une seule IP."""
    print(f"\n[*] Looking up {ip} ...")
    info = get_country(ip)
    print(f"\n  IP       : {ip}")
    print(f"  Country  : {info.get('country','?')} {get_flag(info.get('country',''))}")
    print(f"  City     : {info.get('city','?')}, {info.get('region','?')}")
    print(f"  Org/ISP  : {info.get('org','?')}")
    print(f"  Hostname : {info.get('hostname','?')}")
    print(f"  Timezone : {info.get('timezone','?')}\n")

def main():
    parser = argparse.ArgumentParser(
        description="GeoIP lookup for SSH attackers using ipinfo.io"
    )
    subparsers = parser.add_subparsers(dest="command")

    # Mode 1: enrichir un analysis.json
    enrich_p = subparsers.add_parser("enrich", help="Enrich analysis.json with GeoIP")
    enrich_p.add_argument("json_file", help="Path to analysis.json")
    enrich_p.add_argument("-o", "--output", default="output/analysis_geo.json")
    enrich_p.add_argument("-n", "--max-ips", type=int, default=20)

    # Mode 2: lookup rapide d'une IP
    lookup_p = subparsers.add_parser("lookup", help="Quick lookup of a single IP")
    lookup_p.add_argument("ip", help="IP address to lookup")

    args = parser.parse_args()

    if args.command == "enrich":
        enrich_from_json(args.json_file, args.output, args.max_ips)
    elif args.command == "lookup":
        lookup_single(args.ip)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
