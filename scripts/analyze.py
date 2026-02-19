#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re, sys, json, argparse, os
from collections import Counter, defaultdict
from datetime import datetime

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

FAILED_PASS_RE  = re.compile(r'(\w+ +\d+ \d+:\d+:\d+).*Failed password for (?:invalid user )?(\S+) from (\S+) port')
INVALID_USER_RE = re.compile(r'(\w+ +\d+ \d+:\d+:\d+).*Invalid user (\S+) from (\S+) port')
ACCEPTED_RE     = re.compile(r'(\w+ +\d+ \d+:\d+:\d+).*Accepted \S+ for (\S+) from (\S+) port')
MONTHS = {"Jan":1,"Feb":2,"Mar":3,"Apr":4,"May":5,"Jun":6,"Jul":7,"Aug":8,"Sep":9,"Oct":10,"Nov":11,"Dec":12}

def parse_timestamp(ts_str):
    try:
        parts = ts_str.split()
        month = MONTHS.get(parts[0], 1)
        day   = int(parts[1])
        h, m, s = map(int, parts[2].split(":"))
        return datetime(datetime.now().year, month, day, h, m, s)
    except:
        return None

def analyze_log(filepath):
    ip_counter = Counter(); user_counter = Counter()
    successful_logins = []; timeline = defaultdict(int); ip_users = defaultdict(set)
    total_lines = 0
    print(f"[*] Reading {filepath} ...")
    with open(filepath, "r", errors="replace") as f:
        for line in f:
            total_lines += 1
            m = FAILED_PASS_RE.search(line)
            if m:
                ts, user, ip = m.group(1), m.group(2), m.group(3)
                ip_counter[ip] += 1; user_counter[user] += 1; ip_users[ip].add(user)
                dt = parse_timestamp(ts)
                if dt: timeline[dt.strftime("%Y-%m-%d %H:00")] += 1
                continue
            m = INVALID_USER_RE.search(line)
            if m:
                ts, user, ip = m.group(1), m.group(2), m.group(3)
                ip_counter[ip] += 1; user_counter[user] += 1; ip_users[ip].add(user)
                continue
            m = ACCEPTED_RE.search(line)
            if m:
                successful_logins.append({"ts": m.group(1), "user": m.group(2), "ip": m.group(3)})
    return {
        "total_lines": total_lines, "total_failed": sum(ip_counter.values()),
        "total_successful": len(successful_logins), "unique_ips": len(ip_counter),
        "unique_users": len(user_counter), "top_ips": ip_counter.most_common(15),
        "top_users": user_counter.most_common(15), "timeline": dict(sorted(timeline.items())),
        "successful_logins": successful_logins,
        "ip_users": {ip: list(u) for ip, u in ip_users.items()},
    }

def save_json(data, outpath):
    with open(outpath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    print(f"[+] JSON saved -> {outpath}")

def print_summary(data):
    sep = "=" * 60
    print(f"\n{sep}\n  SSH THREAT ANALYSIS REPORT\n{sep}")
    print(f"  Total log lines parsed : {data['total_lines']:,}")
    print(f"  Total failed attempts  : {data['total_failed']:,}")
    print(f"  Successful logins      : {data['total_successful']:,}")
    print(f"  Unique attacker IPs    : {data['unique_ips']:,}")
    print(f"  Unique usernames tried : {data['unique_users']:,}")
    print(f"\n{sep}\n  TOP 10 ATTACKER IPs\n{sep}")
    for rank, (ip, count) in enumerate(data['top_ips'][:10], 1):
        bar = "#" * min(count // max(1, data['top_ips'][0][1] // 30), 30)
        print(f"  {rank:>2}. {ip:<20} {count:>6} attempts  {bar}")
    print(f"\n{sep}\n  TOP 10 USERNAMES TRIED\n{sep}")
    for rank, (user, count) in enumerate(data['top_users'][:10], 1):
        bar = "#" * min(count // max(1, data['top_users'][0][1] // 30), 30)
        print(f"  {rank:>2}. {user:<20} {count:>6} attempts  {bar}")
    if data['successful_logins']:
        print(f"\n{sep}\n  *** SUCCESSFUL LOGINS DETECTED ({len(data['successful_logins'])}) ***\n{sep}")
        for e in data['successful_logins'][:5]:
            print(f"  [!] {e['ts']}  user={e['user']}  from={e['ip']}")
    print(f"\n{sep}\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("logfile")
    parser.add_argument("-o", "--output", default="output")
    args = parser.parse_args()
    os.makedirs(args.output, exist_ok=True)
    data = analyze_log(args.logfile)
    print_summary(data)
    save_json(data, f"{args.output}/analysis.json")

if __name__ == "__main__":
    main()