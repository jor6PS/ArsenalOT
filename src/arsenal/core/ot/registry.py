"""
Registro de protocolos OT y sus scripts disponibles.
Inspirado en ISF (Industrial Security Framework) - github.com/dark-lbp/isf
"""

PROTOCOLS = {
    "modbus": {
        "name": "Modbus TCP",
        "icon": "⚙️",
        "port": 502,
        "transport": "tcp",
        "description": "Protocolo maestro/esclavo para PLCs y RTUs. Ampliamente usado en industria.",
        "service_names": ["modbus", "modbustcp", "modbus-tcp"],
        "risk": "high",
        "scripts": {
            "scan_unit_ids": {
                "name": "Escanear Unit IDs",
                "description": "Enumera los Slave/Unit IDs activos (FC3 probe 1–247)",
                "category": "recon",
                "dangerous": False,
                "params": [
                    {"id": "start_uid", "label": "UID inicio", "type": "number", "default": 1},
                    {"id": "end_uid",   "label": "UID fin",    "type": "number", "default": 10},
                ],
            },
            "device_identification": {
                "name": "Identificación del Dispositivo (FC43)",
                "description": "Lee fabricante, modelo y firmware vía MEI Type 14",
                "category": "recon",
                "dangerous": False,
                "params": [
                    {"id": "unit_id", "label": "Unit ID", "type": "number", "default": 1},
                ],
            },
            "read_holding_registers": {
                "name": "Leer Holding Registers (FC3)",
                "description": "Lee registros de retención (temperatura, presión, setpoints…)",
                "category": "read",
                "dangerous": False,
                "params": [
                    {"id": "unit_id", "label": "Unit ID",    "type": "number", "default": 1},
                    {"id": "address", "label": "Dirección",  "type": "number", "default": 0},
                    {"id": "count",   "label": "Cantidad",   "type": "number", "default": 16},
                ],
            },
            "read_coils": {
                "name": "Leer Coils (FC1)",
                "description": "Lee bits de salida digital (estados de actuadores/relés)",
                "category": "read",
                "dangerous": False,
                "params": [
                    {"id": "unit_id", "label": "Unit ID",   "type": "number", "default": 1},
                    {"id": "address", "label": "Dirección", "type": "number", "default": 0},
                    {"id": "count",   "label": "Cantidad",  "type": "number", "default": 16},
                ],
            },
            "read_input_registers": {
                "name": "Leer Input Registers (FC4)",
                "description": "Lee registros de entrada de solo lectura (sensores analógicos)",
                "category": "read",
                "dangerous": False,
                "params": [
                    {"id": "unit_id", "label": "Unit ID",   "type": "number", "default": 1},
                    {"id": "address", "label": "Dirección", "type": "number", "default": 0},
                    {"id": "count",   "label": "Cantidad",  "type": "number", "default": 16},
                ],
            },
            "write_single_register": {
                "name": "⚠️ Escribir Registro (FC6)",
                "description": "Escribe un valor en un Holding Register. PELIGROSO en entornos productivos.",
                "category": "write",
                "dangerous": True,
                "params": [
                    {"id": "unit_id", "label": "Unit ID",         "type": "number", "default": 1},
                    {"id": "address", "label": "Dirección",       "type": "number", "default": 0},
                    {"id": "value",   "label": "Valor (0–65535)", "type": "number", "default": 0},
                ],
            },
            "write_single_coil": {
                "name": "⚠️ Escribir Coil (FC5)",
                "description": "Activa/desactiva una salida digital. Puede activar actuadores físicos.",
                "category": "write",
                "dangerous": True,
                "params": [
                    {"id": "unit_id", "label": "Unit ID",           "type": "number", "default": 1},
                    {"id": "address", "label": "Dirección",         "type": "number", "default": 0},
                    {"id": "value",   "label": "Valor (1=ON 0=OFF)","type": "number", "default": 0},
                ],
            },
        },
    },
    "s7comm": {
        "name": "Siemens S7",
        "icon": "🏭",
        "port": 102,
        "transport": "tcp",
        "description": "Protocolo propietario Siemens para PLCs SIMATIC S7. Usado en infraestructuras críticas.",
        "service_names": ["s7comm", "s7", "iso-tsap", "s7-1200", "s7-1500", "s7-300", "s7-400"],
        "risk": "critical",
        "scripts": {
            "get_plc_info": {
                "name": "Información del PLC",
                "description": "Lee hardware, firmware, número de serie y nombre del módulo vía SZL",
                "category": "recon",
                "dangerous": False,
                "params": [
                    {"id": "rack", "label": "Rack", "type": "number", "default": 0},
                    {"id": "slot", "label": "Slot", "type": "number", "default": 1},
                ],
            },
            "get_cpu_state": {
                "name": "Estado de la CPU",
                "description": "Lee el estado actual del PLC (RUN / STOP / STARTUP)",
                "category": "read",
                "dangerous": False,
                "params": [
                    {"id": "rack", "label": "Rack", "type": "number", "default": 0},
                    {"id": "slot", "label": "Slot", "type": "number", "default": 1},
                ],
            },
            "read_db": {
                "name": "Leer Data Block (DB)",
                "description": "Lee bytes de un bloque de datos del PLC (DB1, DB2…)",
                "category": "read",
                "dangerous": False,
                "params": [
                    {"id": "rack",      "label": "Rack",         "type": "number", "default": 0},
                    {"id": "slot",      "label": "Slot",         "type": "number", "default": 1},
                    {"id": "db_number", "label": "Nº DB",        "type": "number", "default": 1},
                    {"id": "start",     "label": "Byte inicio",  "type": "number", "default": 0},
                    {"id": "size",      "label": "Bytes a leer", "type": "number", "default": 32},
                ],
            },
            "stop_cpu": {
                "name": "🔴 STOP CPU",
                "description": "Envía comando STOP al PLC. EXTREMADAMENTE PELIGROSO — detiene el proceso industrial.",
                "category": "exploit",
                "dangerous": True,
                "params": [
                    {"id": "rack", "label": "Rack", "type": "number", "default": 0},
                    {"id": "slot", "label": "Slot", "type": "number", "default": 1},
                ],
            },
            "start_cpu": {
                "name": "⚠️ START CPU",
                "description": "Envía comando START al PLC. Puede reactivar un proceso detenido.",
                "category": "exploit",
                "dangerous": True,
                "params": [
                    {"id": "rack", "label": "Rack", "type": "number", "default": 0},
                    {"id": "slot", "label": "Slot", "type": "number", "default": 1},
                ],
            },
        },
    },
    "enip": {
        "name": "EtherNet/IP (CIP)",
        "icon": "🔌",
        "port": 44818,
        "transport": "tcp",
        "description": "Common Industrial Protocol sobre Ethernet. Allen-Bradley/Rockwell y muchos fabricantes.",
        "service_names": ["enip", "ethernet-ip", "ethernetip", "cip", "ab-eth", "alien-link"],
        "risk": "high",
        "scripts": {
            "list_identity": {
                "name": "List Identity",
                "description": "Descubre la identidad del dispositivo: fabricante, tipo de producto, revisión, número de serie",
                "category": "recon",
                "dangerous": False,
                "params": [],
            },
            "list_services": {
                "name": "List Services",
                "description": "Lista los servicios de comunicación CIP disponibles",
                "category": "recon",
                "dangerous": False,
                "params": [],
            },
            "get_attribute_all": {
                "name": "Get Attribute All (Identity Object)",
                "description": "Lee todos los atributos del Identity Object (clase 0x01)",
                "category": "read",
                "dangerous": False,
                "params": [],
            },
        },
    },
    "bacnet": {
        "name": "BACnet",
        "icon": "🏢",
        "port": 47808,
        "transport": "udp",
        "description": "Building Automation and Control Network. HVAC, sistemas de edificios.",
        "service_names": ["bacnet", "bacnet-ip", "bvlc"],
        "risk": "medium",
        "scripts": {
            "who_is": {
                "name": "WhoIs Discovery",
                "description": "WhoIs broadcast para descubrir todos los dispositivos BACnet en la red",
                "category": "recon",
                "dangerous": False,
                "params": [],
            },
            "read_device_info": {
                "name": "Información del Dispositivo",
                "description": "Lee vendor, modelo, descripción y localización del dispositivo",
                "category": "recon",
                "dangerous": False,
                "params": [],
            },
            "read_property": {
                "name": "Read Property",
                "description": "Lee una propiedad de un objeto BACnet (ej: Present Value de un sensor)",
                "category": "read",
                "dangerous": False,
                "params": [
                    {"id": "obj_type",     "label": "Tipo Objeto (8=Device,2=Analog)",   "type": "number", "default": 8},
                    {"id": "obj_instance", "label": "Instancia",                          "type": "number", "default": 1},
                    {"id": "property_id",  "label": "Property ID (85=PresentValue,77=Object-Name)", "type": "number", "default": 77},
                ],
            },
            "write_property": {
                "name": "⚠️ Write Property",
                "description": "Escribe un valor en un objeto BACnet. Puede modificar setpoints de HVAC.",
                "category": "write",
                "dangerous": True,
                "params": [
                    {"id": "obj_type",     "label": "Tipo Objeto",    "type": "number", "default": 2},
                    {"id": "obj_instance", "label": "Instancia",      "type": "number", "default": 1},
                    {"id": "property_id",  "label": "Property ID",    "type": "number", "default": 85},
                    {"id": "value",        "label": "Valor",          "type": "number", "default": 0},
                    {"id": "priority",     "label": "Prioridad (1–16)","type": "number", "default": 8},
                ],
            },
        },
    },
    "dnp3": {
        "name": "DNP3",
        "icon": "⚡",
        "port": 20000,
        "transport": "tcp",
        "description": "Distributed Network Protocol v3. Usado en utilities (agua, electricidad, gas).",
        "service_names": ["dnp3", "dnp", "dnp-sec"],
        "risk": "high",
        "scripts": {
            "read_class_0": {
                "name": "Leer Clase 0 (Static Data)",
                "description": "Lee todos los datos estáticos del dispositivo (valores actuales de proceso)",
                "category": "read",
                "dangerous": False,
                "params": [
                    {"id": "master_addr", "label": "Dirección Master",     "type": "number", "default": 3},
                    {"id": "slave_addr",  "label": "Dirección Outstation", "type": "number", "default": 1},
                ],
            },
            "integrity_poll": {
                "name": "Integrity Poll (Clases 0,1,2,3)",
                "description": "Solicita todos los datos estáticos y eventos pendientes del dispositivo",
                "category": "read",
                "dangerous": False,
                "params": [
                    {"id": "master_addr", "label": "Dirección Master",     "type": "number", "default": 3},
                    {"id": "slave_addr",  "label": "Dirección Outstation", "type": "number", "default": 1},
                ],
            },
            "direct_operate": {
                "name": "⚠️ Direct Operate (CROB)",
                "description": "Envía un Control Relay Output Block. Puede activar/desactivar relés físicos.",
                "category": "exploit",
                "dangerous": True,
                "params": [
                    {"id": "master_addr",   "label": "Dirección Master",            "type": "number", "default": 3},
                    {"id": "slave_addr",    "label": "Dirección Outstation",        "type": "number", "default": 1},
                    {"id": "index",         "label": "Índice del punto",            "type": "number", "default": 0},
                    {"id": "control_code",  "label": "Código (3=LATCH_ON,4=LATCH_OFF)","type": "number","default": 3},
                ],
            },
        },
    },
    "mqtt": {
        "name": "MQTT",
        "icon": "📡",
        "port": 1883,
        "transport": "tcp",
        "description": "Message Queuing Telemetry Transport. IoT industrial, SCADA modernos.",
        "service_names": ["mqtt", "mosquitto"],
        "risk": "high",
        "scripts": {
            "connect_test": {
                "name": "Test Conexión Anónima",
                "description": "Comprueba si el broker MQTT acepta conexiones sin autenticación",
                "category": "recon",
                "dangerous": False,
                "params": [
                    {"id": "client_id", "label": "Client ID", "type": "text", "default": "arsenal_probe"},
                ],
            },
            "subscribe_all": {
                "name": "Suscribirse a todos los topics (#)",
                "description": "Captura todos los mensajes publicados en el broker durante un tiempo",
                "category": "read",
                "dangerous": False,
                "params": [
                    {"id": "topic",   "label": "Topic (# = todos)",   "type": "text",   "default": "#"},
                    {"id": "timeout", "label": "Tiempo escucha (seg)","type": "number", "default": 10},
                ],
            },
            "publish": {
                "name": "⚠️ Publicar Mensaje",
                "description": "Publica un mensaje en un topic. Puede enviar comandos a dispositivos IoT.",
                "category": "write",
                "dangerous": True,
                "params": [
                    {"id": "topic",   "label": "Topic",          "type": "text",   "default": "test/arsenal"},
                    {"id": "message", "label": "Mensaje",        "type": "text",   "default": "test"},
                    {"id": "qos",     "label": "QoS (0/1/2)",   "type": "number", "default": 0},
                ],
            },
        },
    },
    "opcua": {
        "name": "OPC-UA",
        "icon": "🔧",
        "port": 4840,
        "transport": "tcp",
        "description": "OPC Unified Architecture. Estándar moderno para interoperabilidad OT/IT.",
        "service_names": ["opcua", "opc-ua", "opc", "opc-tcp"],
        "risk": "medium",
        "scripts": {
            "get_endpoints": {
                "name": "GetEndpoints",
                "description": "Descubre los endpoints disponibles sin autenticación",
                "category": "recon",
                "dangerous": False,
                "params": [],
            },
            "browse_nodes": {
                "name": "Browse Nodes",
                "description": "Navega el árbol de nodos del servidor OPC-UA (requiere acceso anónimo)",
                "category": "read",
                "dangerous": False,
                "params": [
                    {"id": "max_nodes", "label": "Máx. nodos a mostrar", "type": "number", "default": 30},
                ],
            },
        },
    },
    "profinet": {
        "name": "PROFINET",
        "icon": "🔩",
        "port": 34964,
        "transport": "udp",
        "description": "Process Field Net de Siemens. Automatización industrial de alta velocidad.",
        "service_names": ["profinet", "pnio", "pn-io"],
        "risk": "high",
        "scripts": {
            "dcp_identify": {
                "name": "DCP Identify All",
                "description": "Broadcast DCP para descubrir todos los dispositivos PROFINET en el segmento L2",
                "category": "recon",
                "dangerous": False,
                "params": [
                    {"id": "interface", "label": "Interfaz de red (ej: eth0)", "type": "text", "default": "eth0"},
                ],
            },
        },
    },
    "fins": {
        "name": "FINS (Omron)",
        "icon": "🏗️",
        "port": 9600,
        "transport": "udp",
        "description": "Factory Interface Network Service de Omron. PLCs CJ/CS/CP.",
        "service_names": ["fins", "omron-fins", "omron"],
        "risk": "high",
        "scripts": {
            "controller_info": {
                "name": "Controller Data Read",
                "description": "Lee modelo, versión del OS y estado del controlador Omron",
                "category": "recon",
                "dangerous": False,
                "params": [],
            },
            "memory_read": {
                "name": "Leer Área de Memoria",
                "description": "Lee datos de las áreas de memoria del PLC (DM, CIO, HR…)",
                "category": "read",
                "dangerous": False,
                "params": [
                    {"id": "memory_area", "label": "Área (0x82=DM, 0xB0=CIO)", "type": "number", "default": 0x82},
                    {"id": "address",     "label": "Dirección",                "type": "number", "default": 0},
                    {"id": "count",       "label": "Palabras",                 "type": "number", "default": 16},
                ],
            },
            "memory_write": {
                "name": "⚠️ Escribir Área de Memoria",
                "description": "Escribe en la memoria del PLC Omron. PELIGROSO en entornos productivos.",
                "category": "write",
                "dangerous": True,
                "params": [
                    {"id": "memory_area", "label": "Área (0x82=DM)",           "type": "number", "default": 0x82},
                    {"id": "address",     "label": "Dirección",                "type": "number", "default": 0},
                    {"id": "data_hex",    "label": "Datos hex (ej: 0001 00FF)","type": "text",   "default": "0000"},
                ],
            },
        },
    },
}


def get_protocol_info(protocol_id: str) -> dict:
    return PROTOCOLS.get(protocol_id, {})


def get_script_info(protocol_id: str, script_id: str) -> dict:
    proto = PROTOCOLS.get(protocol_id, {})
    return proto.get("scripts", {}).get(script_id, {})
