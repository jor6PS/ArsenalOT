"""
BACnet/IP scripts via raw UDP sockets.
"""

import socket
import struct
from typing import Generator

_TIMEOUT = 5
_BACNET_PORT = 47808  # 0xBAC0


def _udp_sock() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(_TIMEOUT)
    return sock


def run_who_is(host: str, port: int = _BACNET_PORT) -> Generator[str, None, None]:
    """Send BACnet WhoIs and parse IAm responses."""
    yield f"[*] BACnet - WhoIs | {host}:{port}"
    try:
        sock = _udp_sock()

        # BVLC (BACnet Virtual Link Control) + NPDU + APDU WhoIs
        bvlc = bytes([
            0x81,        # BACnet/IP
            0x0a,        # Original-Unicast-NPDU
            0x00, 0x0c,  # Length = 12
        ])
        npdu = bytes([0x01, 0x20, 0xff, 0xff, 0x00, 0xff])  # unicast, no hop count limit
        apdu = bytes([0x10, 0x08])  # WhoIs (unconfirmed, service=8)
        pkt = bvlc + npdu + apdu

        sock.sendto(pkt, (host, int(port)))
        yield f"[+] WhoIs sent, waiting for IAm..."

        try:
            while True:
                data, addr = sock.recvfrom(1024)
                if len(data) >= 6 and data[0] == 0x81 and data[4] == 0x10 and data[5] == 0x00:
                    # IAm (service=0)
                    yield f"[+] IAm from {addr[0]}:{addr[1]}"
                    # Parse object-identifier (tag 0)
                    offset = 6
                    if len(data) > offset + 4:
                        obj_id_raw = struct.unpack_from('>I', data, offset + 1)[0]
                        obj_type = (obj_id_raw >> 22) & 0x3FF
                        instance = obj_id_raw & 0x3FFFFF
                        yield f"    Object Identifier: type={obj_type}, instance={instance}"
                    if len(data) > offset + 7:
                        max_apdu = struct.unpack_from('>H', data, offset + 6)[0]
                        yield f"    Max APDU: {max_apdu}"
        except socket.timeout:
            yield f"[*] WhoIs scan complete"
        sock.close()
    except Exception as e:
        yield f"[!] Exception: {e}"


def run_read_property(host: str, port: int = _BACNET_PORT, obj_type: int = 8, obj_instance: int = 1, prop_id: int = 85) -> Generator[str, None, None]:
    """
    BACnet ReadProperty request.
    Default: Analog Input 1, Present Value (prop 85).
    """
    obj_type = int(obj_type); obj_instance = int(obj_instance); prop_id = int(prop_id)
    yield f"[*] BACnet - ReadProperty | {host}:{port}"
    yield f"    Object: type={obj_type} instance={obj_instance}, Property: {prop_id}"
    try:
        sock = _udp_sock()

        # Build ReadProperty APDU
        obj_id = (obj_type << 22) | (obj_instance & 0x3FFFFF)
        apdu = bytes([
            0x00,       # Confirmed request, no seg, no more
            0x05,       # Max segments / max resp = 5
            0x00,       # Invoke ID
            0x0c,       # Service: ReadProperty
        ])
        # Object Identifier: context tag 0, length 4
        apdu += bytes([0x0c]) + struct.pack('>I', obj_id)
        # Property Identifier: context tag 1
        apdu += bytes([0x19, prop_id & 0xff])

        bvlc = bytes([0x81, 0x0a]) + struct.pack('>H', 4 + 6 + len(apdu))
        npdu = bytes([0x01, 0x04])  # expecting reply
        pkt = bvlc + npdu + apdu

        sock.sendto(pkt, (host, int(port)))
        data, addr = sock.recvfrom(4096)
        yield f"[+] Response from {addr[0]} ({len(data)} bytes)"
        if len(data) > 10:
            payload = data[10:]
            yield f"    Hex: {payload.hex()}"
            printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in payload)
            yield f"    Text: {printable}"
        sock.close()
    except socket.timeout:
        yield f"[-] No response (timeout)"
    except Exception as e:
        yield f"[!] Exception: {e}"


def run_read_device_info(host: str, port: int = _BACNET_PORT, device_instance: int = 1) -> Generator[str, None, None]:
    """Read BACnet Device object properties (name, description, model)."""
    device_instance = int(device_instance)
    yield f"[*] BACnet - Read Device Info | {host}:{port} device={device_instance}"
    props = {
        77: "Object Name",
        28: "Description",
        70: "Model Name",
        12: "Application Software Version",
        96: "System Status",
    }
    try:
        sock = _udp_sock()
        for prop_id, label in props.items():
            obj_id = (8 << 22) | (device_instance & 0x3FFFFF)  # object type 8 = Device
            apdu = bytes([0x00, 0x05, 0x00, 0x0c])
            apdu += bytes([0x0c]) + struct.pack('>I', obj_id)
            apdu += bytes([0x19, prop_id & 0xff])
            bvlc = bytes([0x81, 0x0a]) + struct.pack('>H', 4 + 6 + len(apdu))
            npdu = bytes([0x01, 0x04])
            pkt = bvlc + npdu + apdu
            sock.sendto(pkt, (host, int(port)))
            try:
                data, _ = sock.recvfrom(4096)
                if len(data) > 12:
                    val_bytes = data[12:]
                    printable = ''.join(chr(b) if 32 <= b < 127 else '' for b in val_bytes).strip()
                    yield f"[+] {label}: {printable or val_bytes.hex()}"
                else:
                    yield f"[-] {label}: empty response"
            except socket.timeout:
                yield f"[-] {label}: timeout"
        sock.close()
    except Exception as e:
        yield f"[!] Exception: {e}"


def run_write_property(host: str, port: int = _BACNET_PORT, obj_type: int = 1, obj_instance: int = 1, prop_id: int = 85, value: float = 0.0) -> Generator[str, None, None]:
    """BACnet WriteProperty — write a REAL value to an object property."""
    yield f"[!] WARNING: BACnet WriteProperty — writes to device at {host}"
    yield f"    Object type={obj_type} instance={obj_instance} property={prop_id} value={value}"
    try:
        sock = _udp_sock()
        obj_id = (int(obj_type) << 22) | (int(obj_instance) & 0x3FFFFF)
        fval = struct.pack('>f', float(value))
        apdu = bytes([0x00, 0x05, 0x00, 0x0f])  # WriteProperty
        apdu += bytes([0x0c]) + struct.pack('>I', obj_id)
        apdu += bytes([0x19, int(prop_id) & 0xff])
        # Property Value: opening tag 3, REAL (app tag 4)
        apdu += bytes([0x3e, 0x44]) + fval + bytes([0x3f])
        bvlc = bytes([0x81, 0x0a]) + struct.pack('>H', 4 + 6 + len(apdu))
        npdu = bytes([0x01, 0x04])
        pkt = bvlc + npdu + apdu
        sock.sendto(pkt, (host, int(port)))
        try:
            data, addr = sock.recvfrom(1024)
            if data[9] == 0x0f:  # SimpleACK
                yield f"[+] WriteProperty ACK — value {value} written successfully"
            else:
                yield f"[-] Unexpected response: {data.hex()}"
        except socket.timeout:
            yield f"[-] No ACK received (timeout)"
        sock.close()
    except Exception as e:
        yield f"[!] Exception: {e}"
