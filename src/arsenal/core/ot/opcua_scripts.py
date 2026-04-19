"""
OPC-UA scripts — uses opcua-asyncio (sync wrapper) or falls back to raw Hello/GetEndpoints.
"""

import socket
import struct
from typing import Generator

_TIMEOUT = 5
_OPCUA_PORT = 4840


def _send_hello(sock: socket.socket, endpoint_url: str) -> None:
    """Send OPC-UA HEL message."""
    url_bytes = endpoint_url.encode('utf-8')
    # HEL body
    body = struct.pack('<IIIII', 0, 65536, 65536, 4096, len(url_bytes)) + url_bytes
    # Message header: type=HEL, chunk=F, size
    header = b'HEL' + b'F' + struct.pack('<I', 8 + len(body))
    sock.send(header + body)


def _recv_message(sock: socket.socket) -> bytes:
    """Receive a complete OPC-UA binary message."""
    header = sock.recv(8)
    if len(header) < 8:
        return b''
    msg_size = struct.unpack_from('<I', header, 4)[0]
    body = b''
    remaining = msg_size - 8
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            break
        body += chunk
        remaining -= len(chunk)
    return header + body


def run_get_endpoints(host: str, port: int = _OPCUA_PORT) -> Generator[str, None, None]:
    """OPC-UA GetEndpoints request to enumerate server endpoints."""
    endpoint_url = f"opc.tcp://{host}:{port}"
    yield f"[*] OPC-UA - GetEndpoints | {endpoint_url}"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(_TIMEOUT)
        sock.connect((host, int(port)))

        _send_hello(sock, endpoint_url)
        ack = _recv_message(sock)
        if not ack or ack[:3] != b'ACK':
            yield f"[-] No ACK received: {ack[:8].hex() if ack else 'empty'}"
            sock.close()
            return
        yield f"[+] ACK received — OPC-UA server is responding"

        # GetEndpoints request (minimal Open SecureChannel not needed for this)
        # We send it as a raw Hello/GetEndpoints over null security
        # Node ID for GetEndpoints = 0x01AD (429)
        req_node = struct.pack('<BBH', 0x01, 0x00, 429)  # Numeric NodeId
        req_header = struct.pack('<IHI',
            0xFFFFFFFF,  # AuthToken: null
            1,           # RequestHandle
            0,           # ReturnDiagnostics
        ) + b'\x00' * 8  # Timestamp + RequestHandle padding

        # Build GetEndpoints parameters
        url_b = endpoint_url.encode()
        params = struct.pack('<I', len(url_b)) + url_b
        params += struct.pack('<I', 0xFFFFFFFF)  # LocaleIds: null array
        params += struct.pack('<I', 0xFFFFFFFF)  # ProfileUris: null array

        # OpenSecureChannel + SecurityMode=None
        # Simplified: try to use asyncua if available
        try:
            from asyncua.sync import Client
            client = Client(url=endpoint_url, timeout=_TIMEOUT)
            endpoints = client.connect_and_get_server_endpoints()
            yield f"[+] Endpoints ({len(endpoints)}):"
            for ep in endpoints:
                yield f"    URL: {ep.EndpointUrl}"
                yield f"    Security: {ep.SecurityMode} / {ep.SecurityPolicyUri.split('#')[-1]}"
                yield f"    Transport: {ep.TransportProfileUri.split('/')[-1]}"
            return
        except ImportError:
            yield f"[*] asyncua not installed — using raw socket probe"

        # Raw: just report what we got
        resp = _recv_message(sock)
        yield f"[+] Server response ({len(resp)} bytes)"
        if len(resp) > 8:
            yield f"    Type: {resp[:3].decode('ascii', errors='?')}"
            yield f"    Data: {resp[8:40].hex()}"
        sock.close()
    except Exception as e:
        yield f"[!] Exception: {e}"


def run_browse_nodes(host: str, port: int = _OPCUA_PORT) -> Generator[str, None, None]:
    """Browse OPC-UA address space root nodes."""
    endpoint_url = f"opc.tcp://{host}:{port}"
    yield f"[*] OPC-UA - Browse Root Nodes | {endpoint_url}"
    try:
        from asyncua.sync import Client
        client = Client(url=endpoint_url, timeout=_TIMEOUT)
        with client:
            yield f"[+] Connected"
            root = client.get_root_node()
            yield f"[+] Root node: {root}"
            children = root.get_children()
            yield f"[+] Root children ({len(children)}):"
            for child in children[:20]:
                try:
                    name = child.read_browse_name()
                    yield f"    {child.nodeid} — {name}"
                    grandchildren = child.get_children()
                    for gc in grandchildren[:5]:
                        try:
                            gcname = gc.read_browse_name()
                            yield f"        {gc.nodeid} — {gcname}"
                        except Exception:
                            pass
                except Exception as e:
                    yield f"    {child}: {e}"
    except ImportError:
        yield f"[-] asyncua library not installed. Install with: pip install asyncua"
        yield f"[*] Falling back to raw TCP probe..."
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(_TIMEOUT)
            sock.connect((host, int(port)))
            _send_hello(sock, endpoint_url)
            ack = _recv_message(sock)
            if ack and ack[:3] == b'ACK':
                yield f"[+] OPC-UA server confirmed at {endpoint_url} (install asyncua for full browsing)"
            sock.close()
        except Exception as e:
            yield f"[!] Exception: {e}"
    except Exception as e:
        yield f"[!] Exception: {e}"
