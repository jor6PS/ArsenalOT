
import sqlite3
import ipaddress
import sys
from pathlib import Path

db_path = "/home/redteam/tools/Industrial/ArsenalOT/src/scans_debug.db"
target_ip = "10.239.150.129"
org = "OW"

def debug():
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        print(f"--- ANALYZING EVERY NETWORK IN DB for IP {target_ip} ---")
        networks = cursor.execute("SELECT organization_name, system_name, network_name, network_range FROM networks").fetchall()
        
        found_match = False
        ip_obj = ipaddress.ip_address(target_ip)
        
        for net in networks:
            org_db = net['organization_name']
            sys_db = net['system_name']
            name_db = net['network_name']
            range_db = net['network_range'].strip()
            
            try:
                net_obj = ipaddress.ip_network(range_db, strict=False)
                if ip_obj in net_obj:
                    print(f"✅ FOUND MATCHING NETWORK!")
                    print(f"   Name: {name_db} ({sys_db})")
                    print(f"   Range: {range_db}")
                    print(f"   Organization: {org_db}")
                    found_match = True
                else:
                    # Optional: print close matches or ranges for transparency
                    if range_db.startswith("10.239."):
                        print(f"ℹ️  Checking {range_db} ({name_db}): Out of range")
            except Exception as e:
                print(f"⚠️  Error parsing range '{range_db}': {e}")
        
        if not found_match:
            print(f"\n❌ CONCLUSION: No matching network found in the entire database for IP {target_ip}.")
            
        conn.close()
    except Exception as e:
        print(f"Fatal error: {e}")
    except Exception as e:
        print(f"Fatal error: {e}")

if __name__ == "__main__":
    debug()
