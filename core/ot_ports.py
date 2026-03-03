"""
Puertos y protocolos industriales comunes para escaneos OT
Basado en estándares IEC 61850, Modbus, DNP3, y otros protocolos industriales
"""

# Puertos TCP comunes en entornos OT
OT_TCP_PORTS = {
    # Protocolos de control industrial
    'modbus_tcp': [502],
    'modbus_rtu_over_tcp': [502],
    's7comm': [102],
    'fins': [9600],
    'dnp3': [20000],
    'iec104': [2404],
    'ethernet_ip': [44818],
    'bacnet': [47808],
    'opc_ua': [4840, 4843],
    'opc_classic': [135, 4911],
    
    # SCADA y HMI
    'wonderware': [4000],
    'intellution': [789],
    'ge_fanuc': [18245, 18246],
    'rockwell': [2222, 44818],
    'siemens': [102, 161, 162],
    
    # Protocolos de red industrial
    'profinet': [34962, 34963, 34964, 34980],
    'ethernet_powerlink': [0x88AB],  # 34987
    'cc_link': [61440, 61441],
    'moxa_nport': [4800],
    
    # Servicios web industriales
    'http': [80, 8080, 8443],
    'https': [443],
    'vnc': [5900, 5901],
    'rdp': [3389],
    'telnet': [23],
    'ssh': [22],
    'ftp': [21],
    
    # Bases de datos industriales
    'sql_server': [1433],
    'oracle': [1521],
    'mysql': [3306],
    'postgresql': [5432],
    
    # Otros servicios OT
    'snmp': [161, 162],
    'ldap': [389, 636],
    'kerberos': [88],
    'dns': [53],
    'ntp': [123],
    'smtp': [25, 587],
    'pop3': [110, 995],
    'imap': [143, 993],
    
    # Protocolos específicos de fabricantes
    'schneider': [502, 789, 4000],
    'abb': [102, 502],
    'honeywell': [502, 789],
    'yokogawa': [502, 102],
    'emerson': [502, 102],
    'mitsubishi': [5006, 5007],
    'omron': [9600, 502],
    
    # Protocolos de seguridad OT
    'tls_ot': [443, 4843, 8443],
    'ipsec': [500, 4500],
}

# Puertos UDP comunes en entornos OT
OT_UDP_PORTS = {
    'modbus_udp': [502],
    'dnp3_udp': [20000],
    'bacnet_udp': [47808],
    'snmp': [161, 162],
    'ntp': [123],
    'dns': [53],
    'dhcp': [67, 68],
    'tftp': [69],
    'syslog': [514],
    'profinet': [34962, 34963, 34964],
}

# Lista consolidada de puertos OT más comunes (prioridad alta)
OT_PRIORITY_PORTS_TCP = sorted(set([
    # Control industrial crítico
    502,    # Modbus TCP
    102,    # S7comm (Siemens)
    9600,   # FINS (Omron)
    20000,  # DNP3
    2404,   # IEC 104
    44818,  # Ethernet/IP
    47808,  # BACnet
    4840,   # OPC UA Discovery
    4843,   # OPC UA Secure
    
    # SCADA/HMI
    789,    # Intelliution
    4000,   # Wonderware
    2222,   # Rockwell
    
    # Redes industriales
    34962, 34963, 34964, 34980,  # PROFINET
    
    # Servicios comunes
    21, 22, 23, 80, 443, 445, 3389, 5900, 5901,
    
    # Otros OT
    1911, 1962, 4000, 4911, 8000, 8080, 9600,
    19999, 20547, 46823, 46824, 55000, 55001, 55002, 55003
]))

OT_PRIORITY_PORTS_UDP = sorted(set([
    502, 20000, 47808, 161, 162, 123, 53, 34962, 34963, 34964
]))

# Perfiles de escaneo OT predefinidos
OT_SCAN_PROFILES = {
    'ot_comprehensive': {
        'name': 'OT Completo',
        'description': 'Escaneo exhaustivo de todos los puertos OT conocidos',
        'tcp_ports': OT_PRIORITY_PORTS_TCP,
        'udp_ports': OT_PRIORITY_PORTS_UDP,
        'timing': '-T2',
        'scan_delay': '1s',
        'max_parallelism': 1,
        'estimated_time_per_host': 300  # segundos
    },
    'ot_plc_focused': {
        'name': 'Enfocado en PLCs',
        'description': 'Puertos específicos para PLCs (Modbus, S7comm, etc.)',
        'tcp_ports': [502, 102, 9600, 20000, 2404, 44818, 47808, 4840, 4843],
        'udp_ports': [502, 20000, 47808],
        'timing': '-T2',
        'scan_delay': '2s',
        'max_parallelism': 1,
        'estimated_time_per_host': 120
    },
    'ot_scada_hmi': {
        'name': 'SCADA/HMI',
        'description': 'Puertos comunes en sistemas SCADA y HMI',
        'tcp_ports': [80, 443, 502, 789, 4000, 2222, 3389, 5900, 5901, 8080],
        'udp_ports': [],
        'timing': '-T3',
        'scan_delay': '500ms',
        'max_parallelism': 2,
        'estimated_time_per_host': 60
    },
    'ot_network_devices': {
        'name': 'Dispositivos de Red Industrial',
        'description': 'Switches, routers y dispositivos de red industrial',
        'tcp_ports': [22, 23, 80, 443, 161, 162, 3389],
        'udp_ports': [161, 162],
        'timing': '-T3',
        'scan_delay': '500ms',
        'max_parallelism': 3,
        'estimated_time_per_host': 45
    },
    'ot_quick_discovery': {
        'name': 'Descubrimiento Rápido OT',
        'description': 'Escaneo rápido de los puertos OT más críticos',
        'tcp_ports': [502, 102, 47808, 44818, 20000, 2404],
        'udp_ports': [47808, 20000],
        'timing': '-T4',
        'scan_delay': '100ms',
        'max_parallelism': 5,
        'estimated_time_per_host': 15
    },
    'ot_safe_stealth': {
        'name': 'Stealth Seguro OT',
        'description': 'Escaneo muy lento y sigiloso para entornos críticos',
        'tcp_ports': OT_PRIORITY_PORTS_TCP,
        'udp_ports': OT_PRIORITY_PORTS_UDP,
        'timing': '-T1',
        'scan_delay': '5s',
        'max_parallelism': 1,
        'estimated_time_per_host': 600
    }
}

def get_profile_ports(profile_name: str, include_udp: bool = False) -> list:
    """Obtener lista de puertos de un perfil"""
    if profile_name not in OT_SCAN_PROFILES:
        return []
    
    profile = OT_SCAN_PROFILES[profile_name]
    ports = profile['tcp_ports'].copy()
    if include_udp:
        ports.extend(profile['udp_ports'])
    return sorted(set(ports))

def format_ports_list(ports: list) -> str:
    """Formatear lista de puertos para Nmap"""
    if not ports:
        return ''
    
    # Agrupar puertos consecutivos cuando sea posible
    ports = sorted(set(ports))
    ranges = []
    start = ports[0]
    end = ports[0]
    
    for port in ports[1:]:
        if port == end + 1:
            end = port
        else:
            if start == end:
                ranges.append(str(start))
            else:
                ranges.append(f"{start}-{end}")
            start = end = port
    
    if start == end:
        ranges.append(str(start))
    else:
        ranges.append(f"{start}-{end}")
    
    return ','.join(ranges)

def estimate_scan_time(profile_name: str, num_hosts: int) -> int:
    """Estimar tiempo de escaneo en segundos"""
    if profile_name not in OT_SCAN_PROFILES:
        return 0
    
    profile = OT_SCAN_PROFILES[profile_name]
    time_per_host = profile.get('estimated_time_per_host', 60)
    return time_per_host * num_hosts

