"""
Parser para procesar archivos XML de Nmap y construir estructuras de datos
"""

import xml.etree.ElementTree as ET
import ipaddress
from typing import Dict, List, Optional
from datetime import datetime


class NmapXMLParser:
    """Parser para archivos XML de Nmap."""
    
    def __init__(self, xml_path: str):
        """Inicializa el parser con la ruta al archivo XML."""
        self.xml_path = xml_path
        self.tree = ET.parse(xml_path)
        self.root = self.tree.getroot()
    
    def parse(self) -> Dict:
        """Parsea el XML y retorna un diccionario estructurado."""
        results = {}
        
        # Obtener información del escaneo
        scan_info = self._get_scan_info()
        
        # Procesar cada host
        for host in self.root.findall('host'):
            host_data = self._parse_host(host)
            if host_data:
                ip = host_data['ip']
                results[ip] = host_data
        
        # Si no hay hosts pero el runstats dice que hay hosts up,
        # intentar extraer información del target_range o runstats
        if not results:
            runstats = self.root.find('runstats')
            if runstats is not None:
                hosts_elem = runstats.find('hosts')
                if hosts_elem is not None:
                    hosts_up = int(hosts_elem.get('up', 0))
                    if hosts_up > 0:
                        # Intentar extraer IPs del comando o del target
                        # Esto es un fallback cuando --open no muestra hosts sin puertos abiertos
                        import re
                        args = scan_info.get('args', '')
                        # Buscar IPs en los argumentos del comando
                        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                        potential_ips = re.findall(ip_pattern, args)
                        for ip in potential_ips:
                            if ip not in results:
                                # Crear entrada básica para host sin puertos abiertos
                                results[ip] = {
                                    'ip': ip,
                                    'hostnames': [],
                                    'hostname': None,
                                    'mac_address': None,
                                    'vendor': None,
                                    'status': 'up',
                                    'reason': 'no-response',
                                    'os': {},
                                    'host_scripts': {},
                                    'ports': {}  # Sin puertos abiertos
                                }
        
        return {
            'scan_info': scan_info,
            'hosts': results
        }
    
    def _get_scan_info(self) -> Dict:
        """Extrae información general del escaneo."""
        scan_info = {
            'scanner': self.root.get('scanner', ''),
            'args': self.root.get('args', ''),
            'start': self.root.get('start', ''),
            'startstr': self.root.get('startstr', ''),
            'version': self.root.get('version', ''),
            'xmloutputversion': self.root.get('xmloutputversion', '')
        }
        
        # Información de tiempo
        runstats = self.root.find('runstats')
        if runstats is not None:
            finished = runstats.find('finished')
            if finished is not None:
                scan_info['finished'] = finished.get('time', '')
                scan_info['finishedstr'] = finished.get('timestr', '')
                scan_info['elapsed'] = finished.get('elapsed', '')
        
        return scan_info
    
    def _parse_host(self, host_elem) -> Optional[Dict]:
        """Parsea un elemento host del XML."""
        # Estado del host
        status_elem = host_elem.find('status')
        if status_elem is None or status_elem.get('state') != 'up':
            return None
        
        # Dirección IP
        address_elem = host_elem.find("address[@addrtype='ipv4']")
        if address_elem is None:
            address_elem = host_elem.find("address[@addrtype='ipv6']")
        
        if address_elem is None:
            return None
        
        ip = address_elem.get('addr')
        if not ip:
            return None
        
        # Hostnames (puede haber múltiples)
        hostnames = []
        hostnames_elem = host_elem.find('hostnames')
        if hostnames_elem is not None:
            for hostname_elem in hostnames_elem.findall('hostname'):
                hostnames.append({
                    'name': hostname_elem.get('name', ''),
                    'type': hostname_elem.get('type', '')
                })
        
        # MAC address (si existe)
        mac_address = None
        mac_elem = host_elem.find("address[@addrtype='mac']")
        if mac_elem is not None:
            mac_address = mac_elem.get('addr')
        
        # Vendor (si existe)
        vendor = None
        if mac_elem is not None:
            vendor = mac_elem.get('vendor')
        
        # OS Detection
        os_info = {}
        os_elem = host_elem.find('os')
        if os_elem is not None:
            os_matches = []
            for osmatch in os_elem.findall('osmatch'):
                os_matches.append({
                    'name': osmatch.get('name', ''),
                    'accuracy': osmatch.get('accuracy', ''),
                    'line': osmatch.get('line', '')
                })
            if os_matches:
                os_info['matches'] = os_matches
            
            # OS Classes
            os_classes = []
            for osclass in os_elem.findall('osclass'):
                os_classes.append({
                    'type': osclass.get('type', ''),
                    'vendor': osclass.get('vendor', ''),
                    'osfamily': osclass.get('osfamily', ''),
                    'osgen': osclass.get('osgen', ''),
                    'accuracy': osclass.get('accuracy', '')
                })
            if os_classes:
                os_info['classes'] = os_classes
        
        # Scripts a nivel de host
        host_scripts = {}
        hostscript_elem = host_elem.find('hostscript')
        if hostscript_elem is not None:
            for script_elem in hostscript_elem.findall('script'):
                script_id = script_elem.get('id', '')
                script_output = script_elem.get('output', '')
                host_scripts[script_id] = script_output
        
        # Puertos
        ports = {}
        ports_elem = host_elem.find('ports')
        if ports_elem is not None:
            for port_elem in ports_elem.findall('port'):
                port_data = self._parse_port(port_elem)
                if port_data:
                    port_key = f"{port_data['port']}/{port_data['protocol']}"
                    ports[port_key] = port_data
        
        return {
            'ip': ip,
            'hostnames': hostnames,
            'hostname': hostnames[0]['name'] if hostnames else None,  # Compatibilidad
            'mac_address': mac_address,
            'vendor': vendor,
            'status': status_elem.get('state'),
            'reason': status_elem.get('reason', ''),
            'os': os_info,
            'host_scripts': host_scripts,
            'ports': ports
        }
    
    def _parse_port(self, port_elem) -> Optional[Dict]:
        """Parsea un elemento port del XML."""
        port_id = port_elem.get('portid')
        protocol = port_elem.get('protocol')
        
        if not port_id or not protocol:
            return None
        
        port_num = int(port_id)
        
        # Estado del puerto
        state_elem = port_elem.find('state')
        if state_elem is None:
            return None
        
        state = state_elem.get('state')
        if state != 'open':  # Solo procesar puertos abiertos
            return None
        
        # Información del servicio
        service_elem = port_elem.find('service')
        service_data = {}
        if service_elem is not None:
            service_data = {
                'name': service_elem.get('name', ''),
                'product': service_elem.get('product', ''),
                'version': service_elem.get('version', ''),
                'extrainfo': service_elem.get('extrainfo', ''),
                'method': service_elem.get('method', ''),
                'conf': int(service_elem.get('conf', 0)) if service_elem.get('conf') else 0
            }
            
            # CPEs
            cpes = []
            for cpe_elem in service_elem.findall('cpe'):
                cpes.append(cpe_elem.text)
            service_data['cpe'] = ', '.join(cpes) if cpes else ''
        
        # Scripts (NSE) - más detallado
        scripts = {}
        for script_elem in port_elem.findall('script'):
            script_id = script_elem.get('id', '')
            script_output = script_elem.get('output', '')
            
            # Extraer elementos dentro del script si existen
            script_data = {
                'output': script_output,
                'elements': {}
            }
            
            # Algunos scripts tienen elementos estructurados
            for elem in script_elem.findall('elem'):
                key = elem.get('key', '')
                value = elem.text or ''
                script_data['elements'][key] = value
            
            # Algunos scripts tienen tablas
            tables = []
            for table in script_elem.findall('table'):
                table_data = {}
                for elem in table.findall('elem'):
                    key = elem.get('key', '')
                    value = elem.text or ''
                    table_data[key] = value
                if table_data:
                    tables.append(table_data)
            if tables:
                script_data['tables'] = tables
            
            scripts[script_id] = script_data if script_data['elements'] or tables else script_output
        
        return {
            'port': port_num,
            'protocol': protocol,
            'state': state,
            'reason': state_elem.get('reason', ''),
            'reason_ttl': state_elem.get('reason_ttl', ''),
            **service_data,
            'scripts': scripts
        }
    
    def get_all_hosts(self) -> List[str]:
        """Retorna lista de todas las IPs de hosts activos."""
        hosts = []
        for host in self.root.findall('host'):
            status_elem = host.find('status')
            if status_elem is not None and status_elem.get('state') == 'up':
                address_elem = host.find("address[@addrtype='ipv4']")
                if address_elem is None:
                    address_elem = host.find("address[@addrtype='ipv6']")
                if address_elem is not None:
                    ip = address_elem.get('addr')
                    if ip:
                        hosts.append(ip)
        return hosts
    
    def get_open_ports(self, host_ip: str) -> List[Dict]:
        """Retorna lista de puertos abiertos para un host específico."""
        for host in self.root.findall('host'):
            address_elem = host.find("address[@addrtype='ipv4']")
            if address_elem is None:
                address_elem = host.find("address[@addrtype='ipv6']")
            
            if address_elem is None or address_elem.get('addr') != host_ip:
                continue
            
            ports = []
            ports_elem = host.find('ports')
            if ports_elem is not None:
                for port_elem in ports_elem.findall('port'):
                    port_data = self._parse_port(port_elem)
                    if port_data:
                        ports.append(port_data)
            return ports
        
        return []

