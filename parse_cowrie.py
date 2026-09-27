#!/usr/bin/env python3
"""
Cowrie Honeypot Log Parser
Parses cowrie.json telemetry to summarize SSH brute-force attempts.
"""

import json
import sys
from collections import Counter

LOG_FILE = "sample_logs/cowrie_sample.json"

def parse_logs(file_path):
    failed_logins = Counter()
    successful_logins = Counter()
    attacker_ips = Counter()

    print(f"\n[+] Processing Cowrie Telemetry: {file_path}\n")
    print(f"{'TIMESTAMP':<20} | {'ATTACKER IP':<15} | {'USERNAME':<12} | {'PASSWORD':<15} | {'STATUS'}")
    print("-" * 80)

    try:
        with open(file_path, "r") as f:
            for line in f:
                try:
                    event = json.loads(line)
                    event_id = event.get("eventid", "")

                    if event_id in ["cowrie.login.failed", "cowrie.login.success"]:
                        ts = event.get("timestamp", "")[:19].replace("T", " ")
                        ip = event.get("src_ip", "0.0.0.0")
                        user = event.get("username", "N/A")
                        pwd = event.get("password", "N/A")
                        status = "SUCCESS" if event_id == "cowrie.login.success" else "FAILED"

                        attacker_ips[ip] += 1
                        if status == "FAILED":
                            failed_logins[(user, pwd)] += 1
                        else:
                            successful_logins[(user, pwd)] += 1

                        print(f"{ts:<20} | {ip:<15} | {user:<12} | {pwd:<15} | {status}")
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        print(f"[-] Error: Could not find log file at {file_path}")
        sys.exit(1)

    print("\n" + "=" * 80)
    print("ATTACK SUMMARY METRICS")
    print("=" * 80)
    print(f"Top Attacker IPs:     {dict(attacker_ips.most_common(5))}")
    print(f"Top Attempted Creds:  {dict(failed_logins.most_common(5))}")

if __name__ == "__main__":
    target_file = sys.argv[1] if len(sys.argv) > 1 else LOG_FILE
    parse_logs(target_file)
