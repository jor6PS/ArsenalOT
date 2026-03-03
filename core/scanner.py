"""
Network Scanner Module - Adaptado para uso en aplicación web
"""
import os
import json
import datetime
import ipaddress
import nmap
import logging
import subprocess
from typing import Dict, Optional, Callable

from protocols.web import take_screenshot, get_source
from protocols.modbus_banner import modbus_banner
from protocols.bacnet_banner import bacnet_banner
import hostdiscovery as hostdiscovery_module
from core.ot_ports import (
    OT_SCAN_PROFILES, OT_PRIORITY_PORTS_TCP, OT_PRIORITY_PORTS_UDP,
    get_profile_ports, format_ports_list, estimate_scan_time
)

logger = logging.getLogger(__name__)

class NetworkScanner:
    """Clase para realizar escaneos de red optimizados para OT"""
    
    def __init__(self):
        self.date_today = datetime.datetime.today().strftime('%Y-%m-%d')
        self.private_subnets = [
            ipaddress.ip_network(subnet) for subnet in [
                '10.0.0.0/8', '172.16.0.0/12', 
                '192.168.0.0/16', '169.254.0.0/16'
            ]
        ]
        
        # Construir opciones de escaneo mejoradas
        ot_tcp_ports_str = format_ports_list(OT_PRIORITY_PORTS_TCP)
        ot_udp_ports_str = format_ports_list(OT_PRIORITY_PORTS_UDP)
        
        self.scan_options = {
            # Escaneos generales
            'rapido': '-T4 -Pn --open -sV --version-intensity 2',
            'normal': '-T3 -Pn --open -sV --version-intensity 3',
            'lento': '-T2 -Pn --open --min-rate 100 -sV --version-intensity 4',
            
            # Escaneos OT mejorados
            'industrial': f'--open -Pn --scan-delay 1s --max-parallelism 1 -sV --version-intensity 3 -p {ot_tcp_ports_str}',
            'industrial_rapido': f'--open -Pn -T3 -sV --version-intensity 2 -p {ot_tcp_ports_str}',
            'industrial_udp': f'--open -Pn -sU -sV --version-intensity 2 -p {ot_udp_ports_str}',
            'industrial_completo': f'--open -Pn --scan-delay 1s --max-parallelism 1 -sV --version-intensity 4 -p T:{ot_tcp_ports_str},U:{ot_udp_ports_str}',
            
            # Nuevos perfiles OT
            'ot_plc_focused': self._build_profile_scan('ot_plc_focused'),
            'ot_scada_hmi': self._build_profile_scan('ot_scada_hmi'),
            'ot_network_devices': self._build_profile_scan('ot_network_devices'),
            'ot_quick_discovery': self._build_profile_scan('ot_quick_discovery'),
            'ot_safe_stealth': self._build_profile_scan('ot_safe_stealth'),
        }
    
    def _build_profile_scan(self, profile_name: str) -> str:
        """Construir string de escaneo desde un perfil OT"""
        if profile_name not in OT_SCAN_PROFILES:
            return ''
        
        profile = OT_SCAN_PROFILES[profile_name]
        tcp_ports = format_ports_list(profile['tcp_ports'])
        udp_ports = format_ports_list(profile['udp_ports'])
        
        args = [
            '--open',
            '-Pn',
            profile['timing'],
            f"--scan-delay {profile['scan_delay']}",
            f"--max-parallelism {profile['max_parallelism']}",
            '-sV',
            '--version-intensity 3'
        ]
        
        if tcp_ports and udp_ports:
            args.append(f"-p T:{tcp_ports},U:{udp_ports}")
        elif tcp_ports:
            args.append(f"-p {tcp_ports}")
        elif udp_ports:
            args.append(f"-sU -p {udp_ports}")
        
        return ' '.join(args)
    
    def validate_ip_range(self, ip_range: str) -> bool:
        """Valida que el rango de IP sea válido"""
        try:
            ipaddress.ip_network(ip_range, strict=False)
            return True
        except ValueError:
            try:
                ipaddress.ip_address(ip_range)
                return True
            except ValueError:
                return False
    
    def estimate_scan_duration(self, rango: str, scan_type: str, hostdiscovery: bool = False,
                               enable_ot: bool = False, enable_versions: bool = True,
                               enable_screenshots: bool = False, enable_source: bool = False,
                               enable_vulns: bool = False) -> Dict:
        """Estimar duración del escaneo considerando opciones seleccionadas"""
        try:
            network = ipaddress.ip_network(rango, strict=False)
            num_hosts = network.num_addresses - 2  # Excluir network y broadcast
            
            # Si es descubrimiento de hosts, reducir número estimado
            if hostdiscovery:
                num_hosts = min(num_hosts, 254)  # Asumir máximo /24 activo
            
            # Obtener tiempo estimado por host según perfil base
            if scan_type in OT_SCAN_PROFILES:
                time_per_host = OT_SCAN_PROFILES[scan_type].get('estimated_time_per_host', 60)
            elif 'industrial' in scan_type or 'ot_' in scan_type:
                time_per_host = 120  # Escaneos OT más lentos
            elif scan_type == 'rapido':
                time_per_host = 10
            elif scan_type == 'normal':
                time_per_host = 30
            elif scan_type == 'lento':
                time_per_host = 60
            else:
                time_per_host = 45
            
            # Ajustar tiempo según opciones seleccionadas
            if enable_ot and scan_type not in ['industrial', 'industrial_rapido', 'industrial_udp', 
                                               'industrial_completo', 'ot_plc_focused', 'ot_scada_hmi',
                                               'ot_network_devices', 'ot_quick_discovery', 'ot_safe_stealth']:
                time_per_host += 30  # Escanear puertos OT adicionales
            
            if enable_versions:
                time_per_host += 15  # Detección de versiones añade tiempo
            
            if enable_vulns:
                time_per_host += 45  # Scripts de vulnerabilidades son lentos
            
            # Screenshots y source code se procesan después del escaneo principal
            # pero añaden tiempo adicional por servicio web encontrado
            # Estimamos 2-3 servicios web por host en promedio
            if enable_screenshots or enable_source:
                time_per_host += 20  # Tiempo adicional para procesar servicios web
            
            total_seconds = time_per_host * num_hosts
            minutes = total_seconds // 60
            seconds = total_seconds % 60
            
            return {
                'estimated_hosts': num_hosts,
                'estimated_seconds': total_seconds,
                'estimated_minutes': minutes,
                'estimated_seconds_remainder': seconds,
                'estimated_formatted': f"{minutes}m {seconds}s" if minutes > 0 else f"{seconds}s"
            }
        except:
            return {
                'estimated_hosts': 0,
                'estimated_seconds': 0,
                'estimated_minutes': 0,
                'estimated_seconds_remainder': 0,
                'estimated_formatted': 'N/A'
            }
    
    def scan(self, rango: str, org: str, desde: str, scan_type: str,
             hostdiscovery: bool = False, interfaz: str = 'eth0',
             custom_args: str = '', progress_callback: Optional[Callable] = None,
             neo4j_updater: Optional[object] = None,
             enable_ot: bool = False, enable_versions: bool = True,
             enable_screenshots: bool = False, enable_source: bool = False,
             enable_vulns: bool = False) -> Dict:
        """
        Realiza un escaneo de red
        
        Args:
            rango: Rango de IPs a escanear
            org: Organización
            desde: Ubicación del escaneo
            scan_type: Tipo de escaneo base (rapido, normal, lento)
            hostdiscovery: Si realizar descubrimiento de hosts
            interfaz: Interfaz de red
            custom_args: Argumentos personalizados para Nmap
            progress_callback: Función callback para actualizar progreso
            neo4j_updater: Instancia de Neo4jRealtimeUpdater para actualizaciones en tiempo real
            enable_ot: Si debe enfocarse en puertos OT
            enable_versions: Si debe detectar versiones de servicios (-sV)
            enable_screenshots: Si debe tomar capturas de pantalla de servicios web
            enable_source: Si debe obtener código fuente HTML
            enable_vulns: Si debe ejecutar scripts de vulnerabilidades de Nmap
        
        Returns:
            Dict con resultado del escaneo
        """
        try:
            # Validar rango
            if not self.validate_ip_range(rango):
                return {'success': False, 'error': f'Rango de IP inválido: {rango}'}
            
            # Usar estructura organizada
            from core.structure import OrganizationStructure
            structure = OrganizationStructure.ensure_location_structure(org, desde)
            folder_path = structure['scan_path']
            evidence_path = structure['evidence_path']
            
            # Crear subdirectorios adicionales si son necesarios
            for subfolder in ["img", "source", "vuln"]:
                os.makedirs(os.path.join(folder_path, subfolder), exist_ok=True)
            
            if progress_callback:
                progress_callback(20, "Descubriendo hosts...")
            
            # Descubrimiento de hosts
            discovered_ips = set()
            if hostdiscovery:
                try:
                    arp_output = hostdiscovery_module.escanear_arp_scan(interfaz, rango)
                    discovered_ips.update(hostdiscovery_module.extraer_ips(arp_output))
                    ping_ips = hostdiscovery_module.escanear_ping_concurrente(rango)
                    discovered_ips.update(ping_ips)
                    local_ip = hostdiscovery_module.obtener_ip_local()
                    discovered_ips.discard(local_ip)
                except Exception as e:
                    logger.warning(f"Error en descubrimiento de hosts: {e}")
            
            rango_ips = ' '.join(discovered_ips) if discovered_ips else rango
            
            if progress_callback:
                progress_callback(30, f"Escaneando {len(discovered_ips) if discovered_ips else 'rango'} hosts...")
            
            # Determinar argumentos de escaneo base
            if custom_args:
                base_args = custom_args
            elif scan_type in ['rapido', 'normal', 'lento']:
                # Tipos base: construir argumentos según velocidad
                if scan_type == 'rapido':
                    base_args = '-T4 -Pn --open'
                elif scan_type == 'normal':
                    base_args = '-T3 -Pn --open'
                elif scan_type == 'lento':
                    base_args = '-T2 -Pn --open --min-rate 100'
                else:
                    base_args = '-T3 -Pn --open'
            elif scan_type in self.scan_options:
                # Perfiles predefinidos (OT, etc.)
                base_args = self.scan_options[scan_type]
            else:
                return {'success': False, 'error': f'Tipo de escaneo inválido: {scan_type}'}
            
            # Construir argumentos finales según opciones seleccionadas
            scan_args_list = base_args.split()
            
            # Añadir puertos OT si está habilitado y no es un perfil OT predefinido
            if enable_ot and scan_type not in ['industrial', 'industrial_rapido', 'industrial_udp', 
                                                 'industrial_completo', 'ot_plc_focused', 'ot_scada_hmi',
                                                 'ot_network_devices', 'ot_quick_discovery', 'ot_safe_stealth']:
                ot_tcp_ports_str = format_ports_list(OT_PRIORITY_PORTS_TCP)
                # Si no hay -p en los argumentos, añadir puertos OT
                if not any(arg.startswith('-p') for arg in scan_args_list):
                    scan_args_list.append(f'-p {ot_tcp_ports_str}')
                else:
                    # Si ya hay -p, añadir puertos OT a la lista existente
                    for i, arg in enumerate(scan_args_list):
                        if arg.startswith('-p'):
                            if i + 1 < len(scan_args_list) and not scan_args_list[i + 1].startswith('-'):
                                # Ya tiene puertos especificados, añadir OT
                                existing_ports = scan_args_list[i + 1]
                                scan_args_list[i + 1] = f"{existing_ports},{ot_tcp_ports_str}"
                            else:
                                scan_args_list.insert(i + 1, ot_tcp_ports_str)
                            break
            
            # Añadir detección de versiones si está habilitado
            if enable_versions and '-sV' not in scan_args_list:
                scan_args_list.append('-sV')
                scan_args_list.append('--version-intensity 3')
            
            # Añadir scripts de vulnerabilidades si está habilitado
            if enable_vulns:
                if '--script' not in scan_args_list:
                    # Scripts básicos de vulnerabilidades
                    scan_args_list.append('--script')
                    scan_args_list.append('vuln,default,auth')
                elif 'vuln' not in ' '.join(scan_args_list):
                    # Si ya hay --script pero no vuln, añadirlo
                    for i, arg in enumerate(scan_args_list):
                        if arg == '--script':
                            if i + 1 < len(scan_args_list):
                                existing_scripts = scan_args_list[i + 1]
                                scan_args_list[i + 1] = f"{existing_scripts},vuln"
                            else:
                                scan_args_list.append('vuln,default,auth')
                            break
            
            # Construir string final de argumentos
            scan_arg = ' '.join(scan_args_list)
            
            # Ejecutar escaneo Nmap
            try:
                scanner = nmap.PortScanner()
            except nmap.PortScannerError as e:
                if "not found" in str(e).lower() or "path" in str(e).lower():
                    return {
                        'success': False, 
                        'error': 'Nmap no está instalado o no está en el PATH. Por favor, instala Nmap desde https://nmap.org/download.html y asegúrate de agregarlo al PATH del sistema.'
                    }
                raise
            
            # Generar nombre de archivo XML con timestamp
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            xml_filename = f"nmap_scan_{timestamp}.xml"
            xml_path = os.path.join(evidence_path, xml_filename)
            
            try:
                scanner = nmap.PortScanner()
            except nmap.PortScannerError as e:
                if "not found" in str(e).lower() or "path" in str(e).lower():
                    return {
                        'success': False, 
                        'error': 'Nmap no está instalado o no está en el PATH. Por favor, instala Nmap desde https://nmap.org/download.html y asegúrate de agregarlo al PATH del sistema.'
                    }
                raise
            
            try:
                # Ejecutar escaneo normal para procesamiento
                scanner.scan(hosts=rango_ips, arguments=scan_arg)
                
                # Guardar XML ejecutando nmap directamente con -oX
                try:
                    # Construir comando nmap con salida XML
                    nmap_cmd = ['nmap']
                    # Añadir argumentos del escaneo (sin -oX si ya está)
                    scan_args_list = scan_arg.split()
                    if '-oX' not in scan_args_list:
                        nmap_cmd.extend(scan_args_list)
                        nmap_cmd.extend(['-oX', xml_path])
                    else:
                        # Si ya tiene -oX, reemplazar la ruta
                        for i, arg in enumerate(scan_args_list):
                            if arg == '-oX' and i + 1 < len(scan_args_list):
                                scan_args_list[i + 1] = xml_path
                        nmap_cmd.extend(scan_args_list)
                    nmap_cmd.append(rango_ips)
                    
                    # Ejecutar nmap para generar XML
                    result = subprocess.run(nmap_cmd, capture_output=True, text=True, timeout=3600)
                    if result.returncode == 0 and os.path.exists(xml_path):
                        logger.info(f"Evidencia XML guardada en: {xml_path}")
                    else:
                        logger.warning(f"No se pudo generar XML: {result.stderr}")
                except subprocess.TimeoutExpired:
                    logger.warning("Timeout al ejecutar nmap para XML, continuando con resultados...")
                except FileNotFoundError:
                    logger.warning("Nmap no encontrado en PATH para generar XML")
                except Exception as e:
                    logger.warning(f"Error guardando XML: {e}")
                        
            except nmap.PortScannerError as e:
                if "not found" in str(e).lower() or "path" in str(e).lower():
                    return {
                        'success': False, 
                        'error': 'Nmap no está instalado o no está en el PATH. Por favor, instala Nmap desde https://nmap.org/download.html y asegúrate de agregarlo al PATH del sistema.'
                    }
                raise
            
            if progress_callback:
                progress_callback(50, "Procesando resultados...")
            
            # Cargar resultados existentes
            json_path = structure['result_file']
            try:
                with open(json_path, 'r', encoding='utf-8') as f:
                    scan_results = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                scan_results = {}
            
            scan_results.setdefault(org, {}).setdefault(desde, {})
            
            # Procesar resultados
            hosts_found = 0
            ports_found = 0
            
            for host in scanner.all_hosts():
                try:
                    ip = ipaddress.ip_address(host)
                    subnet = next(
                        (str(sub) for sub in self.private_subnets if ip in sub),
                        "Public IP"
                    )
                    host_data = scan_results[org][desde].setdefault(subnet, {}).setdefault(host, {})
                    
                    # Obtener hostname
                    hostname = scanner[host].hostname()
                    
                    # Actualizar host en Neo4j en tiempo real (antes de procesar puertos)
                    if neo4j_updater and neo4j_updater.is_connected():
                        try:
                            neo4j_updater.update_host(
                                org, desde, subnet, host, hostname
                            )
                        except Exception as e:
                            logger.warning(f"Error actualizando host en Neo4j: {e}")
                    
                    for proto in scanner[host].all_protocols():
                        for port, port_data in scanner[host][proto].items():
                            if port_data['state'] == 'open':
                                ports_found += 1
                                key = f"{port}/{proto}"
                                existing_data = host_data.setdefault(key, {})
                                
                                def update_if_empty(field, value):
                                    if existing_data.get(field) in [None, "", "null"]:
                                        existing_data[field] = value
                                
                                update_if_empty('Hostname', hostname)
                                update_if_empty('State', port_data['state'])
                                update_if_empty('Reason', port_data.get('reason', ''))
                                update_if_empty('Name', port_data.get('name', ''))
                                update_if_empty('Product', port_data.get('product', ''))
                                
                                # Solo añadir información de versiones si está habilitado
                                if enable_versions:
                                    update_if_empty('Version', port_data.get('version', ''))
                                    update_if_empty('Extrainfo', port_data.get('extrainfo', ''))
                                    update_if_empty('Conf', port_data.get('conf', ''))
                                    update_if_empty('Cpe', port_data.get('cpe', ''))
                                
                                update_if_empty('Date', self.date_today)
                                
                                # Extraer información adicional - Detección mejorada de protocolos OT
                                service_name = port_data.get('name', '').lower()
                                product_name = port_data.get('product', '').lower()
                                
                                # Detección de servicios web - solo si están habilitadas las opciones
                                if port in {80, 8080, 443, 8000, 8443} or 'http' in service_name:
                                    if enable_screenshots or enable_source:
                                        if progress_callback:
                                            progress_callback(60 + (ports_found % 10), f"Analizando servicio web {host}:{port}...")
                                    
                                    if enable_screenshots:
                                        img_path = os.path.join(folder_path, "img")
                                        update_if_empty('Screenshot', take_screenshot(host, port, img_path))
                                    
                                    if enable_source:
                                        src_path = os.path.join(folder_path, "source")
                                        update_if_empty('Websource', get_source(host, port, src_path))
                                
                                # Detección de protocolos industriales
                                elif port == 502 or 'modbus' in service_name or 'modbus' in product_name:
                                    if progress_callback:
                                        progress_callback(60 + (ports_found % 10), f"Analizando Modbus TCP {host}:{port}...")
                                    update_if_empty('modbus_banner', modbus_banner(host))
                                    update_if_empty('Protocol', 'Modbus TCP')
                                    update_if_empty('OT_Protocol', True)
                                
                                elif port == 47808 or 'bacnet' in service_name or 'bacnet' in product_name:
                                    if progress_callback:
                                        progress_callback(60 + (ports_found % 10), f"Analizando BACnet {host}:{port}...")
                                    update_if_empty('bacnet_banner', bacnet_banner(host))
                                    update_if_empty('Protocol', 'BACnet')
                                    update_if_empty('OT_Protocol', True)
                                
                                elif port == 102 or 's7' in service_name or 'siemens' in product_name:
                                    update_if_empty('Protocol', 'S7comm (Siemens)')
                                    update_if_empty('OT_Protocol', True)
                                    update_if_empty('Manufacturer', 'Siemens')
                                
                                elif port == 20000 or 'dnp3' in service_name:
                                    update_if_empty('Protocol', 'DNP3')
                                    update_if_empty('OT_Protocol', True)
                                
                                elif port == 2404 or 'iec104' in service_name or 'iec-104' in service_name:
                                    update_if_empty('Protocol', 'IEC 60870-5-104')
                                    update_if_empty('OT_Protocol', True)
                                
                                elif port == 44818 or 'ethernet/ip' in service_name or 'ethernetip' in service_name:
                                    update_if_empty('Protocol', 'Ethernet/IP')
                                    update_if_empty('OT_Protocol', True)
                                
                                elif port in [4840, 4843] or 'opc' in service_name:
                                    update_if_empty('Protocol', 'OPC UA' if port == 4840 or port == 4843 else 'OPC Classic')
                                    update_if_empty('OT_Protocol', True)
                                
                                elif port == 9600 or 'fins' in service_name or 'omron' in product_name:
                                    update_if_empty('Protocol', 'FINS (Omron)')
                                    update_if_empty('OT_Protocol', True)
                                    update_if_empty('Manufacturer', 'Omron')
                                
                                elif port in [34962, 34963, 34964, 34980] or 'profinet' in service_name:
                                    update_if_empty('Protocol', 'PROFINET')
                                    update_if_empty('OT_Protocol', True)
                                
                                # Detección de SCADA/HMI
                                elif port in [789, 4000, 2222] or any(x in service_name for x in ['wonderware', 'intellution', 'scada', 'hmi']):
                                    update_if_empty('OT_Protocol', True)
                                    if port == 789:
                                        update_if_empty('Protocol', 'Intelliution')
                                    elif port == 4000:
                                        update_if_empty('Protocol', 'Wonderware')
                                    elif port == 2222:
                                        update_if_empty('Protocol', 'Rockwell/Allen-Bradley')
                                
                                # Detección de servicios remotos comunes en OT
                                elif port == 3389:
                                    update_if_empty('Protocol', 'RDP (Remote Desktop)')
                                    update_if_empty('OT_Service', 'Remote Access')
                                
                                elif port in [5900, 5901]:
                                    update_if_empty('Protocol', 'VNC (Remote Desktop)')
                                    update_if_empty('OT_Service', 'Remote Access')
                                
                                elif port == 22:
                                    update_if_empty('Protocol', 'SSH')
                                    update_if_empty('OT_Service', 'Remote Access')
                                
                                elif port == 161 or port == 162:
                                    update_if_empty('Protocol', 'SNMP')
                                    update_if_empty('OT_Service', 'Network Management')
                                
                                # Marcar como dispositivo OT si tiene protocolos OT
                                if existing_data.get('OT_Protocol'):
                                    host_data['_is_ot_device'] = True
                                    host_data['_ot_protocols'] = host_data.get('_ot_protocols', [])
                                    protocol = existing_data.get('Protocol', '')
                                    if protocol and protocol not in host_data['_ot_protocols']:
                                        host_data['_ot_protocols'].append(protocol)
                                
                                # Actualizar puerto en Neo4j en tiempo real
                                # Pasar TODAS las propiedades del puerto para seguir la estructura exacta del JSON
                                if neo4j_updater and neo4j_updater.is_connected():
                                    try:
                                        # Copiar TODAS las propiedades de existing_data (que contiene toda la info del JSON)
                                        port_update_data = dict(existing_data)
                                        
                                        # Asegurar que las propiedades básicas estén presentes
                                        if 'State' not in port_update_data:
                                            port_update_data['State'] = port_data.get('state', '')
                                        if 'Name' not in port_update_data:
                                            port_update_data['Name'] = port_data.get('name', '')
                                        if 'Product' not in port_update_data:
                                            port_update_data['Product'] = port_data.get('product', '')
                                        
                                        neo4j_updater.update_port(
                                            org, desde, subnet, host, key, port_update_data
                                        )
                                    except Exception as e:
                                        logger.warning(f"Error actualizando puerto en Neo4j: {e}")
                    
                    hosts_found += 1
                except Exception as e:
                    logger.warning(f"Error procesando host {host}: {e}")
            
            if progress_callback:
                progress_callback(90, "Guardando resultados...")
            
            # Guardar resultados
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(scan_results, f, indent=4, ensure_ascii=False)
            
            # Guardar información completa de la evidencia
            scan_datetime = datetime.datetime.now()
            evidence_info = {
                'xml_file': xml_filename,
                'xml_path': xml_path,
                'scan_date': timestamp,
                'scan_datetime': scan_datetime.isoformat(),
                'rango': rango_ips,
                'scan_type': scan_type,
                'scan_args': scan_arg,
                'hosts_found': hosts_found,
                'ports_found': ports_found,
                'organization': org.upper(),
                'location': desde.upper(),
                'hostdiscovery': hostdiscovery,
                'interfaz': interfaz,
                'custom_args': custom_args
            }
            
            # Calcular hash del archivo XML si existe
            if os.path.exists(xml_path):
                try:
                    import hashlib
                    sha256_hash = hashlib.sha256()
                    with open(xml_path, "rb") as f:
                        for byte_block in iter(lambda: f.read(4096), b""):
                            sha256_hash.update(byte_block)
                    evidence_info['xml_sha256'] = sha256_hash.hexdigest()
                    evidence_info['xml_size'] = os.path.getsize(xml_path)
                except Exception as e:
                    logger.warning(f"Error calculando hash del XML: {e}")
            
            # Guardar metadatos de evidencia mejorados
            evidence_metadata_path = os.path.join(evidence_path, "evidence_metadata.json")
            evidence_metadata = {
                'version': '2.0',
                'last_updated': scan_datetime.isoformat(),
                'scans': {}
            }
            
            if os.path.exists(evidence_metadata_path):
                try:
                    with open(evidence_metadata_path, 'r', encoding='utf-8') as f:
                        existing_metadata = json.load(f)
                        # Mantener compatibilidad con versiones anteriores
                        if isinstance(existing_metadata, dict):
                            if 'scans' in existing_metadata:
                                evidence_metadata['scans'] = existing_metadata['scans']
                            else:
                                # Convertir formato antiguo
                                evidence_metadata['scans'] = existing_metadata
                except Exception as e:
                    logger.warning(f"Error leyendo metadata existente: {e}")
            
            evidence_metadata['scans'][timestamp] = evidence_info
            evidence_metadata['last_updated'] = scan_datetime.isoformat()
            
            with open(evidence_metadata_path, 'w', encoding='utf-8') as f:
                json.dump(evidence_metadata, f, indent=4, ensure_ascii=False)
            
            if progress_callback:
                progress_callback(100, "Escaneo completado")
            
            return {
                'success': True,
                'hosts_found': hosts_found,
                'ports_found': ports_found,
                'file_path': json_path
            }
            
        except Exception as e:
            logger.error(f"Error en escaneo: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_results(self, org: str, location: str) -> Dict:
        """Obtener resultados de una organización y ubicación específica"""
        try:
            json_path = os.path.join("results", org, location, "scan_result.json")
            if not os.path.exists(json_path):
                return {}
            
            with open(json_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error obteniendo resultados: {e}")
            return {}
    
    def get_all_results(self, org: Optional[str] = None, location: Optional[str] = None) -> Dict:
        """Obtener todos los resultados o filtrar por org/location"""
        results = {}
        results_dir = "results"
        
        if not os.path.exists(results_dir):
            return results
        
        for org_name in os.listdir(results_dir):
            if org and org_name != org:
                continue
            
            org_path = os.path.join(results_dir, org_name)
            if not os.path.isdir(org_path):
                continue
            
            # Buscar en estructura nueva (scans/) y antigua
            scans_path = os.path.join(org_path, "scans")
            if os.path.exists(scans_path):
                search_path = scans_path
            else:
                search_path = org_path
            
            for loc_name in os.listdir(search_path):
                if location and loc_name.upper() != location.upper():
                    continue
                
                loc_path = os.path.join(search_path, loc_name)
                if not os.path.isdir(loc_path):
                    continue
                
                # Buscar en estructura nueva
                json_path = os.path.join(loc_path, "scan_result.json")
                if not os.path.exists(json_path):
                    # Fallback a estructura antigua
                    json_path = os.path.join(org_path, loc_name, "scan_result.json")
                
                if os.path.exists(json_path):
                    try:
                        with open(json_path, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                            if org_name not in results:
                                results[org_name] = {}
                            results[org_name][loc_name] = data.get(org_name, {}).get(loc_name, {})
                    except Exception as e:
                        logger.warning(f"Error leyendo {json_path}: {e}")
        
        return results
    
    def get_statistics(self) -> Dict:
        """Obtener estadísticas generales"""
        stats = {
            'total_orgs': 0,
            'total_locations': 0,
            'total_hosts': 0,
            'total_ports': 0,
            'organizations': []
        }
        
        results = self.get_all_results()
        
        for org_name, org_data in results.items():
            org_stats = {
                'name': org_name,
                'locations': 0,
                'hosts': 0,
                'ports': 0
            }
            
            for loc_name, loc_data in org_data.items():
                org_stats['locations'] += 1
                stats['total_locations'] += 1
                
                for subnet, subnet_data in loc_data.items():
                    for host, host_data in subnet_data.items():
                        org_stats['hosts'] += 1
                        stats['total_hosts'] += 1
                        
                        for port, port_data in host_data.items():
                            org_stats['ports'] += 1
                            stats['total_ports'] += 1
            
            stats['organizations'].append(org_stats)
            stats['total_orgs'] += 1
        
        return stats
    
    def merge_results(self, import_data: Dict) -> Dict:
        """
        Fusionar resultados importados con los existentes.
        Enriquece los datos sin sobrescribir información existente.
        """
        merge_stats = {
            'orgs_added': 0,
            'locations_added': 0,
            'hosts_added': 0,
            'hosts_updated': 0,
            'ports_added': 0,
            'ports_updated': 0
        }
        
        try:
            for org_name, org_data in import_data.items():
                if not isinstance(org_data, dict):
                    continue
                
                org_path = os.path.join("results", org_name)
                os.makedirs(org_path, exist_ok=True)
                
                # Cargar resultados existentes de esta org
                existing_org_data = {}
                for loc_name in os.listdir(org_path):
                    if os.path.isdir(os.path.join(org_path, loc_name)):
                        json_path = os.path.join(org_path, loc_name, "scan_result.json")
                        if os.path.exists(json_path):
                            try:
                                with open(json_path, 'r', encoding='utf-8') as f:
                                    existing_data = json.load(f)
                                    if org_name in existing_data and loc_name in existing_data[org_name]:
                                        if org_name not in existing_org_data:
                                            existing_org_data[org_name] = {}
                                        existing_org_data[org_name][loc_name] = existing_data[org_name][loc_name]
                            except Exception as e:
                                logger.warning(f"Error leyendo {json_path}: {e}")
                
                # Si es nueva organización, añadir contador
                if org_name not in existing_org_data:
                    merge_stats['orgs_added'] += 1
                
                for loc_name, loc_data in org_data.items():
                    if not isinstance(loc_data, dict):
                        continue
                    
                    loc_path = os.path.join(org_path, loc_name)
                    os.makedirs(loc_path, exist_ok=True)
                    json_path = os.path.join(loc_path, "scan_result.json")
                    
                    # Cargar datos existentes
                    existing_data = {}
                    if os.path.exists(json_path):
                        try:
                            with open(json_path, 'r', encoding='utf-8') as f:
                                existing_data = json.load(f)
                        except Exception as e:
                            logger.warning(f"Error leyendo {json_path}: {e}")
                    
                    # Inicializar estructura si no existe
                    if org_name not in existing_data:
                        existing_data[org_name] = {}
                    if loc_name not in existing_data[org_name]:
                        existing_data[org_name][loc_name] = {}
                        merge_stats['locations_added'] += 1
                    
                    # Fusionar datos por subnet, host y puerto
                    for subnet, subnet_data in loc_data.items():
                        if not isinstance(subnet_data, dict):
                            continue
                        
                        if subnet not in existing_data[org_name][loc_name]:
                            existing_data[org_name][loc_name][subnet] = {}
                        
                        for host, host_data in subnet_data.items():
                            if not isinstance(host_data, dict):
                                continue
                            
                            if host not in existing_data[org_name][loc_name][subnet]:
                                existing_data[org_name][loc_name][subnet][host] = {}
                                merge_stats['hosts_added'] += 1
                            else:
                                merge_stats['hosts_updated'] += 1
                            
                            # Fusionar puertos y datos
                            for port_key, port_data in host_data.items():
                                if port_key not in existing_data[org_name][loc_name][subnet][host]:
                                    existing_data[org_name][loc_name][subnet][host][port_key] = port_data
                                    merge_stats['ports_added'] += 1
                                else:
                                    # Enriquecer datos existentes sin sobrescribir
                                    existing_port = existing_data[org_name][loc_name][subnet][host][port_key]
                                    for key, value in port_data.items():
                                        # Solo actualizar si el campo está vacío o no existe
                                        if key not in existing_port or existing_port[key] in [None, "", "null"]:
                                            if value not in [None, "", "null"]:
                                                existing_port[key] = value
                                    merge_stats['ports_updated'] += 1
                    
                    # Guardar resultados fusionados
                    with open(json_path, 'w', encoding='utf-8') as f:
                        json.dump(existing_data, f, indent=4, ensure_ascii=False)
                    
                    logger.info(f"Resultados fusionados para {org_name}/{loc_name}")
            
            return merge_stats
        except Exception as e:
            logger.error(f"Error fusionando resultados: {e}")
            raise

