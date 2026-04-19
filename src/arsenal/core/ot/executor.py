"""
Dispatcher for OT protocol script execution.
Receives protocol + script_id + params and routes to the appropriate implementation.
Returns a streaming-compatible generator of output lines.
"""

import importlib
from typing import Generator


# Map protocol_id -> module name
_PROTOCOL_MODULES = {
    "modbus": "arsenal.core.ot.modbus_scripts",
    "s7comm": "arsenal.core.ot.s7_scripts",
    "enip": "arsenal.core.ot.enip_scripts",
    "bacnet": "arsenal.core.ot.bacnet_scripts",
    "dnp3": "arsenal.core.ot.dnp3_scripts",
    "mqtt": "arsenal.core.ot.mqtt_scripts",
    "opcua": "arsenal.core.ot.opcua_scripts",
    "profinet": "arsenal.core.ot.profinet_scripts",
    "fins": "arsenal.core.ot.fins_scripts",
}


def execute_script(
    protocol_id: str,
    script_id: str,
    target_ip: str,
    params: dict,
) -> Generator[str, None, None]:
    """
    Execute an OT script and yield output lines.
    Each yielded line is a string (may include ANSI-like prefixes: [+], [-], [!], [*]).
    """
    if protocol_id not in _PROTOCOL_MODULES:
        yield f"[!] Unknown protocol: {protocol_id}"
        return

    module_name = _PROTOCOL_MODULES[protocol_id]
    try:
        mod = importlib.import_module(module_name)
    except ImportError as e:
        yield f"[!] Failed to load module {module_name}: {e}"
        return

    func_name = f"run_{script_id}"
    func = getattr(mod, func_name, None)
    if func is None:
        yield f"[!] Script '{script_id}' not found in {module_name}"
        return

    try:
        yield from func(target_ip, **params)
    except Exception as e:
        yield f"[!] Execution error: {e}"
