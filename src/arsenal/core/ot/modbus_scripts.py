"""
Modbus TCP scripts using pymodbus 3.x async-free sync client.
"""

from typing import Generator


def _get_client(host: str, port: int = 502):
    from pymodbus.client import ModbusTcpClient
    client = ModbusTcpClient(host=host, port=port)
    return client


def run_read_coils(host: str, port: int = 502, address: int = 0, count: int = 16, unit: int = 1) -> Generator[str, None, None]:
    yield f"[*] Modbus TCP - Read Coils | {host}:{port} | address={address} count={count} unit={unit}"
    try:
        client = _get_client(host, int(port))
        if not client.connect():
            yield f"[-] Could not connect to {host}:{port}"
            return
        rr = client.read_coils(int(address), int(count), slave=int(unit))
        if rr.isError():
            yield f"[-] Error reading coils: {rr}"
        else:
            bits = rr.bits[:int(count)]
            yield f"[+] Coils [{address}..{int(address)+int(count)-1}]:"
            for i, b in enumerate(bits):
                yield f"    Coil {int(address)+i}: {'ON' if b else 'OFF'}"
        client.close()
    except Exception as e:
        yield f"[!] Exception: {e}"


def run_read_discrete_inputs(host: str, port: int = 502, address: int = 0, count: int = 16, unit: int = 1) -> Generator[str, None, None]:
    yield f"[*] Modbus TCP - Read Discrete Inputs | {host}:{port} | address={address} count={count}"
    try:
        client = _get_client(host, int(port))
        if not client.connect():
            yield f"[-] Could not connect to {host}:{port}"
            return
        rr = client.read_discrete_inputs(int(address), int(count), slave=int(unit))
        if rr.isError():
            yield f"[-] Error: {rr}"
        else:
            bits = rr.bits[:int(count)]
            yield f"[+] Discrete Inputs [{address}..{int(address)+int(count)-1}]:"
            for i, b in enumerate(bits):
                yield f"    DI {int(address)+i}: {'ON' if b else 'OFF'}"
        client.close()
    except Exception as e:
        yield f"[!] Exception: {e}"


def run_read_holding_registers(host: str, port: int = 502, address: int = 0, count: int = 10, unit: int = 1) -> Generator[str, None, None]:
    yield f"[*] Modbus TCP - Read Holding Registers | {host}:{port} | address={address} count={count}"
    try:
        client = _get_client(host, int(port))
        if not client.connect():
            yield f"[-] Could not connect to {host}:{port}"
            return
        rr = client.read_holding_registers(int(address), int(count), slave=int(unit))
        if rr.isError():
            yield f"[-] Error: {rr}"
        else:
            yield f"[+] Holding Registers [{address}..{int(address)+int(count)-1}]:"
            for i, v in enumerate(rr.registers):
                yield f"    HR {int(address)+i}: {v} (0x{v:04X})"
        client.close()
    except Exception as e:
        yield f"[!] Exception: {e}"


def run_read_input_registers(host: str, port: int = 502, address: int = 0, count: int = 10, unit: int = 1) -> Generator[str, None, None]:
    yield f"[*] Modbus TCP - Read Input Registers | {host}:{port} | address={address} count={count}"
    try:
        client = _get_client(host, int(port))
        if not client.connect():
            yield f"[-] Could not connect to {host}:{port}"
            return
        rr = client.read_input_registers(int(address), int(count), slave=int(unit))
        if rr.isError():
            yield f"[-] Error: {rr}"
        else:
            yield f"[+] Input Registers [{address}..{int(address)+int(count)-1}]:"
            for i, v in enumerate(rr.registers):
                yield f"    IR {int(address)+i}: {v} (0x{v:04X})"
        client.close()
    except Exception as e:
        yield f"[!] Exception: {e}"


def run_write_coil(host: str, port: int = 502, address: int = 0, value: int = 1, unit: int = 1) -> Generator[str, None, None]:
    val_bool = bool(int(value))
    yield f"[*] Modbus TCP - Write Single Coil | {host}:{port} | address={address} value={val_bool}"
    yield f"[!] WARNING: This is a write operation — it modifies device state."
    try:
        client = _get_client(host, int(port))
        if not client.connect():
            yield f"[-] Could not connect to {host}:{port}"
            return
        rr = client.write_coil(int(address), val_bool, slave=int(unit))
        if rr.isError():
            yield f"[-] Write failed: {rr}"
        else:
            yield f"[+] Coil {address} set to {'ON' if val_bool else 'OFF'} successfully"
        client.close()
    except Exception as e:
        yield f"[!] Exception: {e}"


def run_write_register(host: str, port: int = 502, address: int = 0, value: int = 0, unit: int = 1) -> Generator[str, None, None]:
    yield f"[*] Modbus TCP - Write Single Register | {host}:{port} | address={address} value={value}"
    yield f"[!] WARNING: This is a write operation — it modifies device state."
    try:
        client = _get_client(host, int(port))
        if not client.connect():
            yield f"[-] Could not connect to {host}:{port}"
            return
        rr = client.write_register(int(address), int(value), slave=int(unit))
        if rr.isError():
            yield f"[-] Write failed: {rr}"
        else:
            yield f"[+] Register {address} set to {value} (0x{int(value):04X}) successfully"
        client.close()
    except Exception as e:
        yield f"[!] Exception: {e}"


def run_device_info(host: str, port: int = 502, unit: int = 1) -> Generator[str, None, None]:
    yield f"[*] Modbus TCP - Read Device Identification | {host}:{port}"
    try:
        from pymodbus.constants import DeviceInformation
        client = _get_client(host, int(port))
        if not client.connect():
            yield f"[-] Could not connect to {host}:{port}"
            return
        rr = client.read_device_information(read_code=DeviceInformation.Basic, slave=int(unit))
        if rr.isError():
            yield f"[-] Device info not available: {rr}"
        else:
            yield f"[+] Device Identification:"
            for k, v in rr.information.items():
                label = {0x00: "VendorName", 0x01: "ProductCode", 0x02: "MajorMinorRevision",
                         0x03: "VendorURL", 0x04: "ProductName", 0x05: "ModelName"}.get(k, f"0x{k:02X}")
                val = v.decode() if isinstance(v, bytes) else str(v)
                yield f"    {label}: {val}"
        client.close()
    except Exception as e:
        yield f"[!] Exception: {e}"
