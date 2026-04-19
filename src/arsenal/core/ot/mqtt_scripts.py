"""
MQTT scripts via raw TCP sockets (no external library needed).
Implements minimal MQTT 3.1.1 framing.
"""

import socket
import struct
from typing import Generator

_TIMEOUT = 8
_MQTT_PORT = 1883


def _encode_remaining(n: int) -> bytes:
    """Encode MQTT remaining length (variable byte integer)."""
    out = []
    while True:
        byte = n % 128
        n //= 128
        if n > 0:
            byte |= 0x80
        out.append(byte)
        if n == 0:
            break
    return bytes(out)


def _mqtt_connect(host: str, port: int, client_id: str = "arsenal-ot", username: str = "", password: str = "") -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(_TIMEOUT)
    sock.connect((host, int(port)))

    # Build CONNECT packet
    protocol_name = b'\x00\x04MQTT'
    protocol_level = b'\x04'  # MQTT 3.1.1
    connect_flags = 0x02  # Clean session
    if username:
        connect_flags |= 0x80
    if password:
        connect_flags |= 0x40
    keep_alive = struct.pack('>H', 60)

    cid_bytes = client_id.encode()
    payload = struct.pack('>H', len(cid_bytes)) + cid_bytes
    if username:
        u = username.encode()
        payload += struct.pack('>H', len(u)) + u
    if password:
        p = password.encode()
        payload += struct.pack('>H', len(p)) + p

    var_header = protocol_name + protocol_level + bytes([connect_flags]) + keep_alive
    body = var_header + payload
    packet = bytes([0x10]) + _encode_remaining(len(body)) + body
    sock.send(packet)

    resp = sock.recv(4)
    if len(resp) < 4 or resp[0] != 0x20:
        raise ConnectionError(f"CONNACK not received: {resp.hex()}")
    rc = resp[3]
    if rc != 0:
        codes = {1: "Unacceptable protocol", 2: "ID rejected", 3: "Server unavailable", 4: "Bad credentials", 5: "Unauthorized"}
        raise PermissionError(f"CONNACK rc={rc}: {codes.get(rc, 'Unknown')}")
    return sock


def run_connect_info(host: str, port: int = _MQTT_PORT, client_id: str = "arsenal-ot") -> Generator[str, None, None]:
    """Attempt MQTT CONNECT and report broker info."""
    yield f"[*] MQTT - Connect & Probe | {host}:{port}"
    try:
        sock = _mqtt_connect(host, int(port), client_id)
        yield f"[+] CONNACK received — broker accepts anonymous connections"
        yield f"[+] Broker at {host}:{port} is accessible without authentication"

        # Send PINGREQ to check responsiveness
        sock.send(bytes([0xC0, 0x00]))
        try:
            resp = sock.recv(2)
            if resp == bytes([0xD0, 0x00]):
                yield f"[+] PINGRESP received — broker is healthy"
        except socket.timeout:
            yield f"[-] No PINGRESP"

        # Disconnect cleanly
        sock.send(bytes([0xE0, 0x00]))
        sock.close()
    except PermissionError as e:
        yield f"[-] Broker requires authentication: {e}"
    except Exception as e:
        yield f"[!] Exception: {e}"


def run_subscribe_topic(host: str, port: int = _MQTT_PORT, topic: str = "#", timeout: int = 5) -> Generator[str, None, None]:
    """Subscribe to an MQTT topic and collect messages."""
    yield f"[*] MQTT - Subscribe '{topic}' | {host}:{port} (timeout={timeout}s)"
    try:
        sock = _mqtt_connect(host, int(port))
        yield f"[+] Connected"

        # SUBSCRIBE
        packet_id = 1
        topic_bytes = topic.encode()
        var_header = struct.pack('>H', packet_id)
        payload = struct.pack('>H', len(topic_bytes)) + topic_bytes + bytes([0x00])  # QoS 0
        body = var_header + payload
        pkt = bytes([0x82]) + _encode_remaining(len(body)) + body
        sock.send(pkt)

        # Wait for SUBACK
        resp = sock.recv(5)
        if resp[0] == 0x90:
            yield f"[+] SUBACK received — subscription active"
        else:
            yield f"[-] Unexpected response: {resp.hex()}"
            sock.close()
            return

        # Collect messages
        sock.settimeout(float(timeout))
        msg_count = 0
        yield f"[*] Collecting messages for {timeout}s..."
        try:
            while msg_count < 20:
                data = sock.recv(4096)
                if not data:
                    break
                if data[0] & 0xF0 == 0x30:  # PUBLISH
                    # Parse topic length
                    pos = 1
                    # Remaining length
                    rem = 0; mult = 1
                    while True:
                        b = data[pos]; pos += 1
                        rem += (b & 127) * mult
                        mult *= 128
                        if not (b & 128):
                            break
                    t_len = struct.unpack_from('>H', data, pos)[0]
                    pos += 2
                    t_name = data[pos:pos+t_len].decode('utf-8', errors='replace')
                    pos += t_len
                    msg_payload = data[pos:pos+rem]
                    printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in msg_payload)
                    yield f"[+] Topic: {t_name}"
                    yield f"    Payload: {printable[:120]}"
                    msg_count += 1
        except socket.timeout:
            yield f"[*] Timeout — received {msg_count} messages"

        sock.send(bytes([0xE0, 0x00]))
        sock.close()
    except Exception as e:
        yield f"[!] Exception: {e}"


def run_publish_message(host: str, port: int = _MQTT_PORT, topic: str = "test/arsenal", message: str = "hello") -> Generator[str, None, None]:
    """Publish a message to an MQTT topic."""
    yield f"[!] WARNING: Publishing to MQTT broker at {host}:{port}"
    yield f"    Topic: {topic}"
    yield f"    Message: {message}"
    try:
        sock = _mqtt_connect(host, int(port))
        yield f"[+] Connected"

        topic_bytes = topic.encode()
        msg_bytes = message.encode()
        var_header = struct.pack('>H', len(topic_bytes)) + topic_bytes
        body = var_header + msg_bytes
        pkt = bytes([0x30]) + _encode_remaining(len(body)) + body
        sock.send(pkt)
        yield f"[+] PUBLISH sent ({len(pkt)} bytes)"

        sock.send(bytes([0xE0, 0x00]))
        sock.close()
    except Exception as e:
        yield f"[!] Exception: {e}"
