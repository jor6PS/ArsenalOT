import binascii
import socket
import logging

logger = logging.getLogger(__name__)

port = 502
bufsize = 2048
timeout = 5
unit_id = "\x00"
payload = (
    "\x44\x62"  # Transaction Identifier
    "\x00\x00"  # Protocol Identifier
    "\x00\x05"  # Length
    "{}"        # Unit Identifier
    "\x2b"      # .010 1011 = Function Code: Encapsulated Interface Transport (43)
    "\x0e"      # MEI type: Read Device Identification (14)
    "\x03"      # Read Device ID: Extended Device Identification (3)
    "\x00"      # Object ID: VendorName (0)
).format(unit_id)

object_name = { 
    0: "VendorName",
    1: "ProductCode",
    2: "MajorMinorRevision",
    3: "VendorUrl",
    4: "ProductName",
    5: "ModelName",
    6: "UserApplicationName",
    7: "Reserved",
    8: "Reserved",
    9: "Reserved",
    10: "Reserved",
    128: "PrivateObjects",
    255: "PrivateObjects"
}

# Modbus/TCP Response Bytes
mbtcp = {
    "trans_id":         { "start":  0, "bytes": 2, "length": 4, "end":  4 },
    "prot_id":          { "start":  4, "bytes": 2, "length": 4, "end":  8 },
    "len":              { "start":  8, "bytes": 2, "length": 4, "end": 12 },
    "unit_id":          { "start": 12, "bytes": 1, "length": 2, "end": 14 },
    "func_code":        { "start": 14, "bytes": 1, "length": 2, "end": 16 },
    "mei":              { "start": 16, "bytes": 1, "length": 2, "end": 18 },
    "read_device_id":   { "start": 18, "bytes": 1, "length": 2, "end": 20 },
    "conformity_level": { "start": 20, "bytes": 1, "length": 2, "end": 22 },
    "more_follows":     { "start": 22, "bytes": 1, "length": 2, "end": 24 },
    "next_object_id":   { "start": 24, "bytes": 1, "length": 2, "end": 26 },
    "num_objects":      { "start": 26, "bytes": 1, "length": 2, "end": 28 },
    "object_id":        { "start": 28, "bytes": 1, "length": 2, "end": 30 },
    "objects_len":      { "start": 30, "bytes": 1, "length": 2, "end": 32 },
    "object_str_value": { "start": 32, "bytes": None, "length": None, "end": None }
}

def dec(hex):
    return int(hex, 16)

# Main Modbus exception codes
def handle_exception_codes(code):
    if code == b'ab01':
        return "[!] Illegal Function: Function code received in the query is not recognized or allowed by slave."
    elif code == b'ab02':
        return "[!] Illegal Data Address: Data address of some or all the required entities are not allowed or do not exist in slave."
    elif code == b'ab03':
        return "[!] Illegal Data Value: Value is not accepted by slave."
    elif code == b'ab04':
        return "[!] Slave Device Failure: Unrecoverable error occurred while slave was attempting to perform requested action."
    elif code == b'ab05':
        return "[!] Acknowledge: Slave has accepted request and is processing it, but a long duration of time is required."
    elif code == b'ab06':
        return "[!] Slave Device Busy: Slave is engaged in processing a long-duration command."
    elif code == b'ab07':
        return "[!] Negative Acknowledge: Slave cannot perform the programming functions."
    elif code == b'ab08':
        return "[!] Memory Parity Error: Slave detected a parity error in memory."
    elif code == b'ab0a':
        return "[!] Gateway Path Unavailable: Specialized for Modbus gateways. Indicates a misconfigured gateway."
    elif code == b'ab0b':
        return "[!] Gateway Target Device Failed to Respond: Specialized for Modbus gateways."
    else:
        return "[!] MODBUS - received incorrect data {}".format(code)

def parse_response(data, host):
    """Parsea la respuesta Modbus y devuelve información formateada."""
    if not data or len(data) < 8:
        logger.warning(f"Respuesta Modbus demasiado corta de {host}")
        return f"[!] MODBUS - Respuesta inválida de {host}\n"
    
    try:
        data = binascii.hexlify(data)
        unit_id_hex = data[mbtcp["unit_id"]["start"]:mbtcp["unit_id"]["end"]]
        
        result = ""
        result += "[+] Host:\t\t" + host + "\n"
        result += "[+] Port:\t\t" + str(port) + "\n"
        result += "[+] Unit Identifier:\t" + unit_id_hex.decode("utf-8") + "\n"

        if len(data) < mbtcp["mei"]["end"]:
            logger.warning(f"Respuesta Modbus incompleta de {host}")
            return result + "[!] MODBUS - Respuesta incompleta\n"

        func_code_mei = data[mbtcp["func_code"]["start"]:mbtcp["mei"]["end"]]
        if func_code_mei == b'2b0e':
            if len(data) < mbtcp["num_objects"]["end"]:
                logger.warning(f"Respuesta Modbus sin objetos de {host}")
                return result + "[!] MODBUS - Respuesta sin objetos\n"
            
            num_objects = data[mbtcp["num_objects"]["start"]:mbtcp["num_objects"]["end"]]
            num_objects_int = dec(num_objects)
            result += "[+] Number of Objects: " + str(num_objects_int) + "\n"
            result += "\n"
            
            object_start = mbtcp["object_id"]["start"]
            for i in range(num_objects_int):
                if object_start >= len(data):
                    logger.warning(f"Índice de objeto fuera de rango en {host}")
                    break
                
                object = {}
                end_id = object_start + mbtcp["object_id"]["length"]
                if end_id > len(data):
                    break
                object["id"] = data[object_start:end_id]
                
                end_len = end_id + mbtcp["objects_len"]["length"]
                if end_len > len(data):
                    break
                object["len"] = data[end_id:end_len]  # len in bytes
                
                obj_len_bytes = dec(object["len"])
                end_str_value = end_len + (obj_len_bytes * 2)
                if end_str_value > len(data):
                    logger.warning(f"Longitud de objeto excede datos disponibles en {host}")
                    break
                
                object["str_value"] = data[end_len:end_str_value]
                try:
                    object["name"] = object_name[dec(object["id"])]
                except KeyError:
                    object["name"] = f"Unknown Object {dec(object['id'])}"

                try:
                    decoded_value = binascii.unhexlify(object["str_value"]).decode("utf-8", errors='replace')
                    result += "[*] {}: {}\n".format(
                        object["name"].ljust(20),
                        decoded_value
                    )
                except Exception as e:
                    logger.warning(f"Error decodificando objeto de {host}: {e}")
                    result += "[*] {}: [Error decodificando]\n".format(object["name"].ljust(20))

                object_start = end_str_value
            result += "\n"
        else:
            result += "\n"
            result += handle_exception_codes(func_code_mei)
            result += "\n"
        
        return result
    except Exception as e:
        logger.error(f"Error parseando respuesta Modbus de {host}: {e}")
        return f"[!] MODBUS - Error parseando respuesta: {e}\n"

def modbus_banner(host):
    """Obtiene el banner Modbus de un dispositivo."""
    client = None
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(timeout)
        client.connect((host, port))
        client.send(payload.encode('latin-1'))
        data = client.recv(bufsize)
        if not data:
            logger.warning(f"No se recibieron datos de {host}:{port}")
            return None
        return parse_response(data, host)
    except socket.timeout:
        logger.warning(f"Timeout al conectar a Modbus {host}:{port}")
        return None
    except socket.error as e:
        logger.warning(f"Error de socket al conectar a Modbus {host}:{port}: {e}")
        return None
    except Exception as e:
        logger.error(f"Error inesperado al obtener banner Modbus de {host}:{port}: {e}")
        return None
    finally:
        if client:
            try:
                client.close()
            except Exception:
                pass
