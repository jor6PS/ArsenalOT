"""
FINS (Factory Interface Network Service) scripts for Omron PLCs via UDP.
"""

import socket
import struct
from typing import Generator

_TIMEOUT = 5
_FINS_PORT = 9600


def _fins_udp(host: str, port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(_TIMEOUT)
    return sock


def _fins_header(cmd_code: int, sub_code: int, dst_node: int = 0, src_node: int = 1) -> bytes:
    """Build FINS command header."""
    return bytes([
        0x80,           # ICF: Command, not split
        0x00,           # RSV
        0x02,           # GCT: 2 gateways
        0x00,           # DNA: destination network 0 (local)
        dst_node,       # DA1: destination node
        0x00,           # DA2: unit address 0
        0x00,           # SNA: source network 0
        src_node,       # SA1: source node
        0x00,           # SA2
        0x00,           # SID: service ID
        (cmd_code >> 8) & 0xFF, cmd_code & 0xFF,  # MRC + SRC
        (sub_code >> 8) & 0xFF, sub_code & 0xFF,
    ])


def run_read_memory_area(host: str, port: int = _FINS_PORT, area: int = 0x82, start: int = 0, count: int = 10) -> Generator[str, None, None]:
    """
    FINS Read Memory Area.
    area: 0x82=DM (Data Memory), 0x80=CIO, 0x31=Work bits
    """
    area = int(area); start = int(start); count = int(count)
    area_names = {0x82: "DM", 0x80: "CIO", 0x31: "Work", 0xB0: "Timer", 0xC0: "Counter"}
    area_name = area_names.get(area, f"0x{area:02X}")
    yield f"[*] FINS - Read {area_name} Area | {host}:{port} start={start} count={count}"
    try:
        sock = _fins_udp(host, int(port))
        header = _fins_header(0x0101, 0x0000)  # Memory Area Read
        # Read params: area code, start address (2 bytes), start bit, count
        params = bytes([area]) + struct.pack('>H', start) + bytes([0x00]) + struct.pack('>H', count)
        pkt = header + params
        sock.sendto(pkt, (host, int(port)))
        data, addr = sock.recvfrom(4096)
        yield f"[+] Response from {addr[0]} ({len(data)} bytes)"

        # Response header is 14 bytes, then 2-byte end code, then data
        if len(data) >= 16:
            end_code = struct.unpack_from('>H', data, 12)[0]
            if end_code == 0x0000:
                yield f"[+] {area_name} words {start}..{start+count-1}:"
                word_data = data[14:]
                for i in range(min(count, len(word_data) // 2)):
                    w = struct.unpack_from('>H', word_data, i * 2)[0]
                    yield f"    {area_name}{start+i:04d}: {w} (0x{w:04X}) [{w:016b}]"
            else:
                yield f"[-] FINS error code: 0x{end_code:04X}"
        else:
            yield f"[-] Short response: {data.hex()}"
        sock.close()
    except socket.timeout:
        yield f"[-] Timeout — no response from {host}:{port}"
    except Exception as e:
        yield f"[!] Exception: {e}"


def run_controller_data_read(host: str, port: int = _FINS_PORT) -> Generator[str, None, None]:
    """FINS Controller Data Read — get model, version, area sizes."""
    yield f"[*] FINS - Controller Data Read | {host}:{port}"
    try:
        sock = _fins_udp(host, int(port))
        header = _fins_header(0x0501, 0x0000)  # Controller Data Read
        sock.sendto(header, (host, int(port)))
        data, addr = sock.recvfrom(4096)
        yield f"[+] Response from {addr[0]} ({len(data)} bytes)"
        if len(data) >= 16:
            end_code = struct.unpack_from('>H', data, 12)[0]
            if end_code == 0x0000:
                payload = data[14:]
                # Model: bytes 0-19 (ASCII), version: bytes 20-31
                model = payload[:20].rstrip(b'\x00').decode('ascii', errors='replace')
                version = payload[20:32].rstrip(b'\x00').decode('ascii', errors='replace')
                yield f"[+] Model:   {model}"
                yield f"[+] Version: {version}"
                if len(payload) >= 40:
                    yield f"[+] Extra:   {payload[32:40].hex()}"
            else:
                yield f"[-] FINS error: 0x{end_code:04X}"
        else:
            yield f"[-] Short response: {data.hex()}"
        sock.close()
    except socket.timeout:
        yield f"[-] Timeout"
    except Exception as e:
        yield f"[!] Exception: {e}"


def run_write_memory_area(host: str, port: int = _FINS_PORT, area: int = 0x82, start: int = 0, value: int = 0) -> Generator[str, None, None]:
    """FINS Write Memory Area — write a single word."""
    area = int(area); start = int(start); value = int(value)
    area_names = {0x82: "DM", 0x80: "CIO", 0x31: "Work"}
    area_name = area_names.get(area, f"0x{area:02X}")
    yield f"[!] WARNING: FINS Write to {area_name}{start} = {value} (0x{value:04X}) on {host}:{port}"
    try:
        sock = _fins_udp(host, int(port))
        header = _fins_header(0x0102, 0x0000)  # Memory Area Write
        params = bytes([area]) + struct.pack('>H', start) + bytes([0x00]) + struct.pack('>H', 1)
        word = struct.pack('>H', value & 0xFFFF)
        pkt = header + params + word
        sock.sendto(pkt, (host, int(port)))
        data, addr = sock.recvfrom(256)
        if len(data) >= 14:
            end_code = struct.unpack_from('>H', data, 12)[0]
            if end_code == 0x0000:
                yield f"[+] Write successful — {area_name}{start} = {value}"
            else:
                yield f"[-] FINS error: 0x{end_code:04X}"
        sock.close()
    except socket.timeout:
        yield f"[-] Timeout"
    except Exception as e:
        yield f"[!] Exception: {e}"
