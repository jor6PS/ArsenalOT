"""
DNP3 scripts via raw TCP/UDP sockets.
"""

import socket
import struct
from typing import Generator

_TIMEOUT = 5
_DNP3_PORT = 20000


def _crc16(data: bytes) -> int:
    """DNP3 CRC-16."""
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA6BC
            else:
                crc >>= 1
    return crc ^ 0xFFFF


def _build_dnp3_read(src: int = 3, dst: int = 1) -> bytes:
    """Build DNP3 Read request for Class 0 (static) data."""
    # Application layer: Read (FC=1), Class 0 (group 60 var 1)
    app = bytes([
        0xC0,  # FIR+FIN, seq=0
        0x01,  # Function: Read
        0x3C, 0x01, 0x06,  # All points, Group 60 Var 1 (Class 0)
    ])

    # Transport layer
    transport = bytes([0xC0])  # FIR+FIN, seq=0

    payload = transport + app

    # Data link header (without CRC)
    header = struct.pack('<BBHHHB',
        0x05, 0x64,        # Start bytes
        len(payload) + 5,  # length (header excl start + CRC, + payload length)
        0x44,              # Control: PRI, unconfirmed data (DIR+PRM+FC=4)
        dst & 0xFFFF,
        src & 0xFFFF,
    )
    # Append CRC to header
    hcrc = _crc16(header)
    frame = header + struct.pack('<H', hcrc)

    # Payload in 16-byte chunks with CRC
    for i in range(0, len(payload), 16):
        chunk = payload[i:i+16]
        crc = _crc16(chunk)
        frame += chunk + struct.pack('<H', crc)

    return frame


def run_read_class0(host: str, port: int = _DNP3_PORT, src: int = 3, dst: int = 1) -> Generator[str, None, None]:
    """DNP3 Read Class 0 (all static data)."""
    yield f"[*] DNP3 - Read Class 0 (Static Data) | {host}:{port} src={src} dst={dst}"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(_TIMEOUT)
        sock.connect((host, int(port)))
        yield f"[+] TCP connected"

        frame = _build_dnp3_read(int(src), int(dst))
        sock.send(frame)
        yield f"[*] Read request sent ({len(frame)} bytes): {frame.hex()}"

        resp = sock.recv(4096)
        yield f"[+] Response ({len(resp)} bytes):"
        yield f"    Hex: {resp.hex()}"
        if len(resp) >= 10:
            ctrl = resp[3]
            dst_r = struct.unpack_from('<H', resp, 4)[0]
            src_r = struct.unpack_from('<H', resp, 6)[0]
            yield f"    DL: control=0x{ctrl:02X} dst={dst_r} src={src_r}"
        sock.close()
    except ConnectionRefusedError:
        yield f"[-] Connection refused — DNP3 TCP not available on {host}:{port}"
    except socket.timeout:
        yield f"[-] Timeout connecting to {host}:{port}"
    except Exception as e:
        yield f"[!] Exception: {e}"


def run_read_class1(host: str, port: int = _DNP3_PORT, src: int = 3, dst: int = 1) -> Generator[str, None, None]:
    """DNP3 Read Class 1 (event data)."""
    yield f"[*] DNP3 - Read Class 1 (Event Data) | {host}:{port}"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(_TIMEOUT)
        sock.connect((host, int(port)))
        yield f"[+] TCP connected"

        # App: Read Group 60 Var 2 (Class 1 events)
        app = bytes([0xC0, 0x01, 0x3C, 0x02, 0x06])
        transport = bytes([0xC0])
        payload = transport + app
        header = struct.pack('<BBHHHB',
            0x05, 0x64, len(payload) + 5, 0x44,
            int(dst) & 0xFFFF, int(src) & 0xFFFF,
        )
        hcrc = _crc16(header)
        frame = header + struct.pack('<H', hcrc)
        for i in range(0, len(payload), 16):
            chunk = payload[i:i+16]
            frame += chunk + struct.pack('<H', _crc16(chunk))

        sock.send(frame)
        resp = sock.recv(4096)
        yield f"[+] Response ({len(resp)} bytes): {resp.hex()}"
        sock.close()
    except Exception as e:
        yield f"[!] Exception: {e}"


def run_send_direct_operate(host: str, port: int = _DNP3_PORT, src: int = 3, dst: int = 1, index: int = 0, value: int = 3) -> Generator[str, None, None]:
    """
    DNP3 Direct Operate — control a binary output (CROB).
    value: 3=LATCH_ON, 4=LATCH_OFF
    """
    yield f"[!] WARNING: DNP3 Direct Operate on {host}:{port} index={index} value={value}"
    yield f"[!] This sends a control command to physical output point {index}!"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(_TIMEOUT)
        sock.connect((host, int(port)))
        yield f"[+] TCP connected"

        # CROB: Group 12 Var 1
        crob = bytes([
            int(value) & 0xFF,  # Control code (3=LATCH_ON, 4=LATCH_OFF)
            0x01,               # Count
            0x00, 0x00, 0x00, 0x00,  # On time
            0x00, 0x00, 0x00, 0x00,  # Off time
            0x00,               # Status
        ])
        # App: Direct Operate (FC=3), prefix=1 (16-bit index), Group 12 Var 1
        app = bytes([0xC0, 0x03]) + bytes([0x0C, 0x01, 0x28, 0x01, 0x00]) + struct.pack('<H', int(index)) + crob
        transport = bytes([0xC0])
        payload = transport + app
        header = struct.pack('<BBHHHB',
            0x05, 0x64, len(payload) + 5, 0x44,
            int(dst) & 0xFFFF, int(src) & 0xFFFF,
        )
        hcrc = _crc16(header)
        frame = header + struct.pack('<H', hcrc)
        for i in range(0, len(payload), 16):
            chunk = payload[i:i+16]
            frame += chunk + struct.pack('<H', _crc16(chunk))

        sock.send(frame)
        resp = sock.recv(1024)
        yield f"[+] Response ({len(resp)} bytes): {resp.hex()}"
        sock.close()
    except Exception as e:
        yield f"[!] Exception: {e}"
