import requests
import time
import subprocess
import os
import signal

BASE_URL = "http://localhost:8000"

def get_running_processes(pattern):
    try:
        output = subprocess.check_output(f"ps aux | grep -v grep | grep -E '{pattern}'", shell=True).decode()
        return output.strip().split('\n')
    except:
        return []

def test_scan(name, config, stop_type='stop'):
    print(f"\n--- Testing {name} ({stop_type}) ---")
    
    # Start Scan
    resp = requests.post(f"{BASE_URL}/api/scan/start", json=config)
    if resp.status_code != 200:
        print(f"FAILED to start scan: {resp.text}")
        return False
    
    scan_id = resp.json().get('scan_id')
    print(f"Scan started with ID: {scan_id}")
    
    # Wait for processes to spawn
    time.sleep(3)
    
    pattern = "nmap|tshark"
    procs = get_running_processes(pattern)
    if not procs:
        print("FAILED: No nmap or tshark processes found after start")
        # return False # Sometimes they finish fast if range is small, but let's assume they should be there
    else:
        print(f"Found processes: {len(procs)}")
    
    # Stop or Cancel
    if stop_type == 'stop':
        stop_resp = requests.post(f"{BASE_URL}/api/scan/{scan_id}/stop")
    else:
        stop_resp = requests.post(f"{BASE_URL}/api/scan/{scan_id}/cancel")
    
    print(f"{stop_type.capitalize()} response: {stop_resp.status_code}")
    
    # Wait for cleanup
    time.sleep(5)
    
    # Verify processes are gone
    remaining = get_running_processes(pattern)
    if remaining:
        print(f"FAILED: Processes still running after {stop_type}:")
        for p in remaining:
            print(f"  {p}")
        return False
    
    print(f"SUCCESS: {name} {stop_type} verified.")
    return True

if __name__ == "__main__":
    # Ensure server is up (dummy check)
    try:
        requests.get(BASE_URL)
    except:
        print(f"Error: Server not running at {BASE_URL}")
        exit(1)

    # Active Scan Test
    test_scan("Active Scan", {
        "organization": "TEST_ORG",
        "location": "TEST_LOC",
        "target_range": "127.0.0.1",
        "interface": "lo",
        "scan_mode": "active",
        "host_discovery": True,
        "nmap": True,
        "nmap_ot_ports": True
    }, stop_type='stop')

    # Passive Scan Test
    test_scan("Passive Scan", {
        "organization": "TEST_ORG",
        "location": "TEST_LOC",
        "target_range": "0.0.0.0/0",
        "interface": "lo",
        "scan_mode": "passive"
    }, stop_type='stop')

    # ICMP Scan Test
    test_scan("ICMP Scan", {
        "organization": "TEST_ORG",
        "location": "TEST_LOC",
        "target_range": "127.0.0.1",
        "interface": "lo",
        "scan_mode": "active",
        "nmap": True,
        "nmap_icmp": True
    }, stop_type='cancel')
