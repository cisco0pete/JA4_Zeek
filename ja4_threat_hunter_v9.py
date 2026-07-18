#!/usr/bin/env python3
"""
JA4 Threat Hunter v5.2 - Behavioral Threat Clustering
Groups findings by C2 Server (IP + JA4S) and summarizes client behaviors 
to handle beaconing noise without losing unique fingerprints.
"""

import json
import gzip
import sys
import os
from pathlib import Path
from collections import defaultdict
from datetime import datetime

# JA4 field mappings for each log type
PRIMARY_FIELDS = {
    'ssl.log': ['ja4', 'ja4s'],
    'http.log': ['ja4h'],
    'ssh.log': ['ja4ssh'],
    'x509.log': ['ja4x']
}

# All other logs that contain related data
RELATED_LOGS = {
    'conn.log': ['ja4t', 'ja4ts'],  # TCP fingerprints (Source/Dest)
    'ssl.log': ['ja4', 'ja4s'],      # TLS fingerprints
    'x509.log': ['ja4x']             # Certificate fingerprints
}

def load_malicious_db(db_path):
    """Load the malicious JA4 database (FoxIO format - array of objects)"""
    try:
        with open(db_path, 'r') as f:
            db_array = json.load(f)

        fingerprint_db = {
            'ja4': {}, 'ja4s': {}, 'ja4h': {}, 'ja4ssh': {}, 
            'ja4x': {}, 'ja4t': {}, 'ja4ts': {}
        }

        for entry in db_array:
            for fp_key in fingerprint_db.keys():
                field_name = f"{fp_key}_fingerprint"
                if entry.get(field_name):
                    fingerprint_db[fp_key][entry[field_name]] = entry

        return fingerprint_db

    except FileNotFoundError:
        print(f"[!] Database not found: {db_path}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"[!] Invalid JSON in database: {db_path}", file=sys.stderr)
        sys.exit(1)

def parse_zeek_log(log_path):
    """Parse a Zeek log file (handles both plain and gzipped)"""
    opener = gzip.open if str(log_path).endswith('.gz') else open
    mode = 'rt' if str(log_path).endswith('.gz') else 'r'

    try:
        with opener(log_path, mode) as f:
            headers = None
            separator = None

            for line in f:
                line = line.strip()
                if line.startswith('#'):
                    if line.startswith('#separator'):
                        separator = line.split()[-1]
                        if separator.startswith('\\x'):
                            separator = bytes.fromhex(separator[2:]).decode('ascii')
                    elif line.startswith('#fields'):
                        headers = line.split('\t')[1:]
                    continue

                if not line: continue

                if headers and separator:
                    values = line.split(separator if separator != '\\x09' else '\t')
                    if len(values) == len(headers):
                        yield dict(zip(headers, line.split('\t')))
    except Exception as e:
        print(f"[!] Error parsing {log_path}: {e}", file=sys.stderr)

def extract_ja4_fingerprints(log_entry, ja4_fields):
    """Extract JA4 fingerprints from a log entry"""
    fingerprints = {}
    for field in ja4_fields:
        if field in log_entry and log_entry[field] not in ['-', '(empty)', '']:
            fingerprints[field] = log_entry[field]
    return fingerprints

def check_against_db(fingerprints, malicious_db):
    """Check if any fingerprints match the malicious database"""
    matches = []
    for fp_type, fp_value in fingerprints.items():
        if fp_type in malicious_db and fp_value in malicious_db[fp_type]:
            entry = malicious_db[fp_type][fp_value]
            matches.append({
                'type': fp_type,
                'fingerprint': fp_value,
                'application': entry.get('application', 'Unknown'),
                'os': entry.get('os', 'Unknown'),
                'notes': entry.get('notes', ''),
                'verified': entry.get('verified', False)
            })
    return matches

def find_log_files(directory):
    """Find all Zeek log files recursively"""
    log_files = {'primary': [], 'related': []}
    all_log_types = {**PRIMARY_FIELDS, **RELATED_LOGS}

    for log_file in Path(directory).rglob("*.log*"):
        filename = log_file.name
        clean_name = filename.replace('.gz', '')
        
        for log_type in all_log_types.keys():
            if clean_name == log_type or clean_name.startswith(log_type.replace('.log', '.')):
                category = 'primary' if log_type in PRIMARY_FIELDS else 'related'
                log_files[category].append((str(log_file), log_type))
                break

    return log_files

def convert_ts_to_utc(timestamp_str):
    """Convert Zeek timestamp to UTC format"""
    try:
        ts = float(timestamp_str)
        return datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S UTC')
    except:
        return timestamp_str

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 ja4_threat_hunter_v5.py <zeek_log_directory>", file=sys.stderr)
        sys.exit(1)

    log_dir = sys.argv[1]
    db_path = "/home/thedr/db/ja4+_db.json"

    malicious_db = load_malicious_db(db_path)
    log_files = find_log_files(log_dir)

    if not log_files['primary']:
        print(f"[!] No JA4-related log files found in {log_dir}", file=sys.stderr)
        sys.exit(1)

    # Cluster storage: Groups by Source, Destination, and Malicious Server Fingerprint (JA4S)
    # Key: (src_ip, dst_ip, ja4s_val)
    threat_clusters = {}
    uid_to_cluster_key = {}
    matched_uids = set()

    # PHASE 1: Identify Clusters based on Malicious Server Handshakes
    for log_path, log_type in log_files['primary']:
        for entry in parse_zeek_log(log_path):
            fingerprints = extract_ja4_fingerprints(entry, PRIMARY_FIELDS[log_type])
            if fingerprints:
                matches = check_against_db(fingerprints, malicious_db)
                if matches:
                    uid = entry.get('uid', 'Unknown')
                    matched_uids.add(uid)
                    
                    src_ip = entry.get('id.orig_h', 'N/A')
                    dst_ip = entry.get('id.resp_h', 'N/A')
                    ja4s = entry.get('ja4s', 'N/A')
                    
                    cluster_key = (src_ip, dst_ip, ja4s)
                    uid_to_cluster_key[uid] = cluster_key

                    if cluster_key not in threat_clusters:
                        threat_clusters[cluster_key] = {
                            "summary_type": "Threat Cluster",
                            "explanation": "Summarized connections sharing the same Malicious Server Fingerprint (JA4S).",
                            "source_ip": src_ip,
                            "dest_ip": dst_ip,
                            "malicious_server_fingerprint": ja4s,
                            "threat_details": matches,
                            "total_connection_count": 0,
                            "client_behaviors": {}, # Keyed by (ja4, server_name)
                            "has_ja4x_match": False
                        }
                    
                    tc = threat_clusters[cluster_key]
                    tc["total_connection_count"] += 1
                    
                    # Track client behaviors within this cluster
                    ja4_client = entry.get('ja4', 'N/A')
                    srv_name = entry.get('server_name', entry.get('host', 'N/A'))
                    behavior_key = (ja4_client, srv_name)
                    
                    if behavior_key not in tc["client_behaviors"]:
                        tc["client_behaviors"][behavior_key] = {
                            "ja4_client": ja4_client,
                            "server_name": srv_name,
                            "first_seen": convert_ts_to_utc(entry.get('ts', '')),
                            "last_seen": convert_ts_to_utc(entry.get('ts', '')),
                            "connection_count": 0,
                            "uids_preview": []
                        }
                    
                    b = tc["client_behaviors"][behavior_key]
                    b["connection_count"] += 1
                    if len(b["uids_preview"]) < 5:
                        b["uids_preview"].append(uid)
                    
                    # Update timestamps
                    current_ts = convert_ts_to_utc(entry.get('ts', ''))
                    if current_ts > b["last_seen"]: b["last_seen"] = current_ts
                    
                    if any(m['type'] == 'ja4x' for m in matches):
                        tc["has_ja4x_match"] = True

    # PHASE 2: Correlate related logs (TCP hashes, etc)
    if matched_uids:
        for log_path, log_type in log_files['related']:
            for entry in parse_zeek_log(log_path):
                uid = entry.get('uid', '')
                if uid in matched_uids:
                    cluster_key = uid_to_cluster_key.get(uid)
                    if not cluster_key: continue
                    tc = threat_clusters[cluster_key]
                    
                    # We add TCP hashes to the general cluster details if found
                    if entry.get('ja4t'): tc["ja4t_source"] = entry['ja4t']
                    if entry.get('ja4ts'): tc["ja4ts_dest"] = entry['ja4ts']
                    if entry.get('ja4x'): tc["ja4x_cert"] = entry['ja4x']

    # Final Output Formatting
    output = []
    for cluster in threat_clusters.values():
        # Flatten client behaviors for the JSON array
        behaviors = list(cluster["client_behaviors"].values())
        cluster["client_behaviors"] = behaviors
        output.append(cluster)

    # Sort: JA4X priority, then connection count
    output.sort(key=lambda x: (not x["has_ja4x_match"], -x["total_connection_count"]))

    print(json.dumps(output, indent=4))

if __name__ == "__main__":
    main()
