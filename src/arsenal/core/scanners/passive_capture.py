"""
Módulo mejorado de captura pasiva de tráfico de red.

Incluye:
- Captura de tráfico con tshark/wireshark
- Análisis en tiempo real de protocolos
- Extracción de IPs, puertos y servicios
- Detección de protocolos específicos (HTTP, HTTPS, Modbus, etc.)
- Integración con base de datos
"""

import subprocess
import ipaddress
from typing import Set, Dict, Tuple, Optional
from pathlib import Path
from datetime import datetime


class PassiveCapture:
    """Clase para captura pasiva de tráfico de red."""
    
    def __init__(self, interface: str = 'eth0'):
        """
        Inicializa el capturador pasivo.
        
        Args:
            interface: Interfaz de red a usar para captura
        """
        self.interface = interface
    
    def start_capture(self, output_file: str, filter: Optional[str] = None, 
                     duration: Optional[int] = None) -> subprocess.Popen:
        """
        Inicia una captura de tráfico de red.
        
        Args:
            output_file: Archivo pcap de salida
            filter: Filtro BPF (ej: "tcp port 80")
            duration: Duración máxima en segundos (None = sin límite)
            
        Returns:
            Proceso de tshark
        """
        cmd = ['tshark', '-i', self.interface, '-w', output_file, '-q']
        
        if filter:
            cmd.extend(['-f', filter])
        
        if duration:
            cmd.extend(['-a', f'duration:{duration}'])
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return process
        except FileNotFoundError:
            raise FileNotFoundError("tshark no está instalado. Instala Wireshark para captura pasiva.")
    
    def extract_connections(self, pcap_file: str) -> list[Dict]:
        """
        Extrae conexiones detalladas (IP, puerto, protocolo, MAC) de un archivo pcap.
        
        Args:
            pcap_file: Ruta al archivo pcap
            
        Returns:
            Lista de diccionarios con la información de la conversación
        """
        conversations = []
        
        # Usar tshark para extraer conexiones con MACs
        cmd = [
            'tshark', '-r', pcap_file,
            '-T', 'fields',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'tcp.srcport',
            '-e', 'tcp.dstport',
            '-e', 'udp.srcport',
            '-e', 'udp.dstport',
            '-e', 'eth.src',
            '-e', 'eth.dst',
            '-e', 'frame.time_epoch',
            '-E', 'header=n',
            '-E', 'separator=|'
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode != 0:
                return conversations
            
            seen_convs = set()
            
            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                
                parts = line.split('|')
                if len(parts) < 9:
                    continue
                
                src_ip, dst_ip, tcp_sport, tcp_dport, udp_sport, udp_dport, src_mac, dst_mac, epoch = parts[:9]
                
                if not src_ip or not dst_ip:
                    continue

                # Timestamp real del paquete
                timestamp = None
                if epoch and epoch.strip():
                    try:
                        timestamp = datetime.fromtimestamp(float(epoch.strip()))
                    except (ValueError, TypeError):
                        timestamp = datetime.now()
                else:
                    timestamp = datetime.now()

                protocol = None
                src_port = None
                dst_port = None

                # Procesar TCP
                if tcp_sport and tcp_sport.strip() and tcp_dport and tcp_dport.strip():
                    try:
                        src_port = int(tcp_sport.strip())
                        dst_port = int(tcp_dport.strip())
                        protocol = 'tcp'
                    except (ValueError, AttributeError):
                        pass
                
                # Procesar UDP (si no es TCP)
                if not protocol and udp_sport and udp_sport.strip() and udp_dport and udp_dport.strip():
                    try:
                        src_port = int(udp_sport.strip())
                        dst_port = int(udp_dport.strip())
                        protocol = 'udp'
                    except (ValueError, AttributeError):
                        pass
                
                # Crear clave única para evitar duplicados masivos en el mismo pcap
                conv_key = (src_ip, dst_ip, src_port, dst_port, protocol)
                if conv_key not in seen_convs:
                    conversations.append({
                        'src_ip': src_ip.strip(),
                        'dst_ip': dst_ip.strip(),
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'protocol': protocol,
                        'src_mac': src_mac.strip() if src_mac else None,
                        'dst_mac': dst_mac.strip() if dst_mac else None,
                        'timestamp': timestamp
                    })
                    seen_convs.add(conv_key)
            
        except Exception as e:
            print(f"⚠️  Error extrayendo conexiones: {e}")
        
        return conversations
    
    def extract_protocols(self, pcap_file: str) -> Dict[str, Set[str]]:
        """
        Extrae información de protocolos detectados en el tráfico.
        
        Args:
            pcap_file: Ruta al archivo pcap
            
        Returns:
            Diccionario {protocolo: set de IPs que lo usan}
        """
        protocols = {}
        
        # Protocolos comunes a detectar
        protocol_fields = {
            'http': 'http.host',
            'https': 'tls.handshake.extensions_server_name',
            'modbus': 'modbus.func_code',
            'ftp': 'ftp.request.command',
            'ssh': 'ssh.version'
        }
        
        for protocol, field in protocol_fields.items():
            cmd = [
                'tshark', '-r', pcap_file,
                '-T', 'fields',
                '-e', 'ip.src',
                '-e', field,
                '-Y', f'{field}'
            ]
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                if result.returncode == 0:
                    ips = set()
                    for line in result.stdout.strip().split('\n'):
                        if line.strip():
                            ip = line.split()[0].strip() if line.split() else None
                            if ip and self._is_valid_ip(ip):
                                ips.add(ip)
                    if ips:
                        protocols[protocol] = ips
            except Exception:
                pass
        
        return protocols
    
    def _is_valid_ip(self, ip_str: str) -> bool:
        """Valida si una cadena es una IP válida."""
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False

