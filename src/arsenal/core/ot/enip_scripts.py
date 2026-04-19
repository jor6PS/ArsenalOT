"""
EtherNet/IP (CIP) scripts via raw TCP sockets.
"""

import socket
import struct
from typing import Generator

_TIMEOUT = 5
_ENIP_PORT = 44818


def _enip_sock(host: str, port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(_TIMEOUT)
    sock.connect((host, int(port)))
    return sock


def _register_session(sock: socket.socket) -> int:
    """Send RegisterSession and return session handle."""
    req = struct.pack('<HHIIQHH',
        0x65,   # Command: RegisterSession
        4,      # Length
        0,      # Session handle (0 for register)
        0,      # Status
        0,      # Sender context
        1,      # Protocol version
        0,      # Options flags
    )
    sock.send(req)
    resp = sock.recv(1024)
    if len(resp) < 4:
        raise ConnectionError("No RegisterSession response")
    handle = struct.unpack_from('<I', resp, 4)[0]
    return handle


def run_list_identity(host: str, port: int = _ENIP_PORT) -> Generator[str, None, None]:
    """Send EtherNet/IP ListIdentity broadcast to identify device."""
    yield f"[*] EtherNet/IP - ListIdentity | {host}:{port}"
    try:
        # ListIdentity can be sent via UDP broadcast too, but TCP works on unicast
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(_TIMEOUT)
        sock.connect((host, int(port)))

        # ListIdentity request (no session needed)
        req = struct.pack('<HHIIQII',
            0x63,  # Command: ListIdentity
            0,     # Length (no data)
            0,     # Session handle
            0,     # Status
            0,     # Sender context
            0,     # Options
        )
        sock.send(req)
        resp = sock.recv(4096)

        if len(resp) < 26:
            yield f"[-] Short response: {resp.hex()}"
            sock.close()
            return

        yield f"[+] ListIdentity Response ({len(resp)} bytes):"
        cmd = struct.unpack_from('<H', resp, 0)[0]
        status = struct.unpack_from('<I', resp, 8)[0]
        yield f"    Command: 0x{cmd:04X}, Status: 0x{status:08X}"

        # Parse items list starting at offset 24
        if len(resp) > 26:
            item_count = struct.unpack_from('<H', resp, 24)[0]
            yield f"    Item count: {item_count}"
            offset = 26
            for _ in range(item_count):
                if offset + 4 > len(resp):
                    break
                item_type = struct.unpack_from('<H', resp, offset)[0]
                item_len = struct.unpack_from('<H', resp, offset + 2)[0]
                offset += 4
                if item_type == 0x000C and item_len >= 33:
                    # Identity item
                    vendor_id = struct.unpack_from('<H', resp, offset)[0]
                    device_type = struct.unpack_from('<H', resp, offset + 2)[0]
                    product_code = struct.unpack_from('<H', resp, offset + 4)[0]
                    rev_major = resp[offset + 6]
                    rev_minor = resp[offset + 7]
                    status_word = struct.unpack_from('<H', resp, offset + 8)[0]
                    serial = struct.unpack_from('<I', resp, offset + 10)[0]
                    name_len = resp[offset + 14]
                    name = resp[offset + 15:offset + 15 + name_len].decode('ascii', errors='replace')
                    yield f"    Vendor ID:    0x{vendor_id:04X}"
                    yield f"    Device Type:  0x{device_type:04X}"
                    yield f"    Product Code: 0x{product_code:04X}"
                    yield f"    Revision:     {rev_major}.{rev_minor}"
                    yield f"    Status:       0x{status_word:04X}"
                    yield f"    Serial:       0x{serial:08X}"
                    yield f"    Product Name: {name}"
                offset += item_len
        sock.close()
    except Exception as e:
        yield f"[!] Exception: {e}"


def run_get_attribute_all(host: str, port: int = _ENIP_PORT) -> Generator[str, None, None]:
    """Read Identity class attributes via CIP GetAttributeAll."""
    yield f"[*] EtherNet/IP - GetAttributeAll (Identity 0x01) | {host}:{port}"
    try:
        sock = _enip_sock(host, int(port))
        handle = _register_session(sock)
        yield f"[+] Session: 0x{handle:08X}"

        # CIP: GetAttributeAll service (0x01) on Identity Object (0x01, instance 1)
        cip = bytes([
            0x01,        # Service: GetAttributeAll
            0x02,        # Path size (words)
            0x20, 0x01,  # Class: Identity (0x01)
            0x24, 0x01,  # Instance: 1
        ])
        # Unconnected Send via SendRRData
        uccm = bytes([
            0x52,        # Service: Unconnected Send
            0x02,
            0x20, 0x06,  # Class: CM
            0x24, 0x01,  # Instance: 1
            0x0a,        # Priority/tick = 0x0a
            0x05,        # Timeout ticks
        ]) + struct.pack('<H', len(cip)) + cip + b'\x00' * (len(cip) % 2)

        data = struct.pack('<HH', 0x00B2, len(uccm)) + uccm
        interface_handle = struct.pack('<IHH', 0, 5, 0)
        req = struct.pack('<HHII8sI',
            0x65,  # SendRRData
            len(interface_handle) + len(data),
            handle,
            0, b'\x00' * 8, 0,
        ) + interface_handle + data

        sock.send(req)
        resp = sock.recv(4096)
        if len(resp) > 44:
            payload = resp[44:]
            yield f"[+] CIP Response ({len(payload)} bytes):"
            printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in payload)
            yield f"    Data: {printable[:80]}"
            yield f"    Hex:  {payload[:32].hex()}"
        else:
            yield f"[-] Response too short: {resp.hex()}"
        sock.close()
    except Exception as e:
        yield f"[!] Exception: {e}"


def run_read_tag(host: str, port: int = _ENIP_PORT, tag: str = "Program:MainProgram.Tag1") -> Generator[str, None, None]:
    """Read a named tag via CIP symbolic path (Allen Bradley / Logix)."""
    yield f"[*] EtherNet/IP - Read Tag '{tag}' | {host}:{port}"
    try:
        sock = _enip_sock(host, int(port))
        handle = _register_session(sock)
        yield f"[+] Session: 0x{handle:08X}"

        tag_bytes = tag.encode('ascii')
        # Symbolic path: 0x91 = ANSI extended symbol
        path = bytes([0x91, len(tag_bytes)]) + tag_bytes
        if len(path) % 2:
            path += b'\x00'

        cip = bytes([0x4C, len(path) // 2]) + path + struct.pack('<H', 1)  # service=Read, count=1

        data = struct.pack('<HH', 0x00B2, len(cip)) + cip
        interface_handle = struct.pack('<IHH', 0, 5, 0)
        req = struct.pack('<HHII8sI',
            0x65, len(interface_handle) + len(data),
            handle, 0, b'\x00' * 8, 0,
        ) + interface_handle + data

        sock.send(req)
        resp = sock.recv(4096)
        if len(resp) > 46:
            service_resp = resp[44]
            status = resp[46] if len(resp) > 46 else 0xFF
            if service_resp == 0xCC:  # Read Tag Response
                data_type = struct.unpack_from('<H', resp, 48)[0]
                value = resp[50:]
                yield f"[+] Tag read OK — Type: 0x{data_type:04X}"
                yield f"    Value bytes: {value[:8].hex()}"
            else:
                yield f"[-] CIP error — service=0x{service_resp:02X} status=0x{status:02X}"
        else:
            yield f"[-] Short response"
        sock.close()
    except Exception as e:
        yield f"[!] Exception: {e}"
