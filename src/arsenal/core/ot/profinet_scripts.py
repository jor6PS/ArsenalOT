"""
PROFINET DCP scripts via raw Ethernet (requires root + scapy) or probe via TCP 102.
"""

import socket
import struct
from typing import Generator

_TIMEOUT = 5


def run_dcp_identify(host: str, port: int = 0, iface: str = "eth0") -> Generator[str, None, None]:
    """
    PROFINET DCP Identify-All multicast probe.
    Requires scapy and root privileges. Falls back to ARP+TCP probe.
    """
    yield f"[*] PROFINET - DCP Identify-All | target={host} iface={iface}"
    try:
        from scapy.all import Ether, sendp, sniff, conf
        conf.iface = iface

        # PROFINET DCP Identify All frame
        # Dst: PROFINET multicast 01:0e:cf:00:00:00
        # EtherType: 0x8892 (PROFINET)
        # FrameID: 0xFEFE (DCP Identify)
        PROFINET_MULTICAST = "01:0e:cf:00:00:00"
        payload = bytes([
            0xFE, 0xFE,  # FrameID: DCP-Identify-All
            0xFE,        # ServiceID: Identify
            0x00,        # ServiceType: Request
            0x00, 0x00, 0x00, 0x01,  # XID
            0x00, 0x00,  # ResponseDelay = 0
            0x00, 0x04,  # DCPDataLength = 4
            0xFF, 0xFF,  # Option/Suboption: AllSelector
            0x00, 0x00,  # Length = 0
        ])
        frame = Ether(dst=PROFINET_MULTICAST, type=0x8892) / payload
        sendp(frame, iface=iface, verbose=False)
        yield f"[+] DCP Identify-All multicast sent on {iface}"
        yield f"[*] Sniffing for responses (3 seconds)..."

        responses = []
        def capture(pkt):
            if pkt.haslayer('Ether') and pkt['Ether'].type == 0x8892:
                src = pkt['Ether'].src
                raw = bytes(pkt['Ether'].payload)
                if len(raw) > 4 and raw[0] == 0xFE and raw[1] == 0xFF:
                    responses.append((src, raw))

        sniff(iface=iface, timeout=3, prn=capture, store=False)

        if responses:
            yield f"[+] {len(responses)} PROFINET device(s) found:"
            for src_mac, raw in responses:
                yield f"    MAC: {src_mac}"
                # Try to extract station name from DCP
                offset = 10
                while offset + 4 <= len(raw):
                    opt = raw[offset]; sub = raw[offset+1]
                    dlen = struct.unpack_from('>H', raw, offset+2)[0]
                    val = raw[offset+4:offset+4+dlen]
                    if opt == 2 and sub == 2:  # NameOfStation
                        yield f"    Name-of-Station: {val.decode('ascii', errors='replace')}"
                    elif opt == 1 and sub == 2:  # IP Address
                        if len(val) >= 4:
                            ip = '.'.join(str(b) for b in val[:4])
                            yield f"    IP: {ip}"
                    offset += 4 + dlen + (dlen % 2)
        else:
            yield f"[-] No PROFINET devices responded"
    except ImportError:
        yield f"[-] scapy not installed — raw Ethernet not available"
        yield f"[*] Probing {host} via TCP port 102 (S7/PN overlap)..."
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(_TIMEOUT)
            result = sock.connect_ex((host, 102))
            if result == 0:
                yield f"[+] TCP/102 open on {host} — likely Siemens PROFINET/S7 device"
            else:
                yield f"[-] TCP/102 closed on {host}"
            sock.close()
        except Exception as e:
            yield f"[!] Exception: {e}"
    except Exception as e:
        yield f"[!] Exception: {e}"
