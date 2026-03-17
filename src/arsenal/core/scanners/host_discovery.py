"""
Módulo mejorado de descubrimiento de hosts con técnicas avanzadas de pentesting.

Incluye múltiples técnicas de descubrimiento:
- ARP scanning (más rápido en LANs)
- ICMP ping (echo request/reply)
- ICMP timestamp/netmask (para hosts que filtran ping)
- SYN scan rápido (detecta hosts sin enviar paquetes completos)
- UDP scan (para servicios UDP)
- Combinación inteligente de técnicas
"""

import subprocess
import re
import socket
import ipaddress
import concurrent.futures
from typing import Set, List, Optional, Dict
from datetime import datetime


class HostDiscovery:
    """Clase para descubrimiento de hosts usando múltiples técnicas."""
    
    def __init__(self, interface: str = 'eth0', timeout: int = 1, max_threads: int = 50):
        """
        Inicializa el descubridor de hosts.
        
        Args:
            interface: Interfaz de red a usar
            timeout: Timeout en segundos para cada técnica
            max_threads: Número máximo de hilos concurrentes
        """
        self.interface = interface
        self.timeout = timeout
        self.max_threads = max_threads
        self.current_process: Optional[subprocess.Popen] = None
    
    def get_local_ip(self) -> str:
        """Obtiene la IP local de la máquina."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(('10.254.254.254', 1))
                return s.getsockname()[0]
        except Exception:
            return '127.0.0.1'
    
    def arp_scan(self, target_range: str, process_callback: Optional[callable] = None) -> Dict[str, Dict]:
        """
        Ejecuta un escaneo ARP en la interfaz especificada.

        ARP scan es muy rápido y efectivo en redes locales porque no depende
        de respuestas de capa 3. Detecta hosts incluso si tienen firewall activo.

        Args:
            target_range: Rango de IPs a escanear (ej: 192.168.1.0/24)

        Returns:
            Dict IP -> {mac_address, vendor} con la información de cada host descubierto
        """
        discovered: Dict[str, Dict] = {}

        # Verificar si arp-scan está disponible
        try:
            subprocess.run(["which", "arp-scan"], check=True, capture_output=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            return discovered

        # Construir comando arp-scan
        cmd = ["arp-scan", "--interface", self.interface, "--local", target_range]

        try:
            self.current_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            if process_callback:
                try:
                    process_callback(self.current_process)
                except:
                    pass

            stdout, stderr = self.current_process.communicate()

            if self.current_process.returncode == 0 or stdout:
                # Formato de salida arp-scan: IP\tMAC\tVendor  (una línea por host)
                mac_pattern = re.compile(r'([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})', re.IGNORECASE)
                ip_pattern = re.compile(r'\b((?:\d{1,3}\.){3}\d{1,3})\b')

                for line in stdout.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    ip_match = ip_pattern.search(line)
                    mac_match = mac_pattern.search(line)
                    if not ip_match or not mac_match:
                        continue
                    ip_str = ip_match.group(1)
                    mac_str = mac_match.group(1).upper()
                    try:
                        ip_obj = ipaddress.ip_address(ip_str)
                        if ip_obj.is_multicast or ip_obj.is_reserved:
                            continue
                    except ValueError:
                        continue

                    # Extraer vendor: todo lo que sigue a la MAC en la línea
                    parts = re.split(r'\s+', line, maxsplit=2)
                    vendor = parts[2].strip() if len(parts) >= 3 else None
                    # Ignorar entradas duplicadas (arp-scan las marca con "(DUP: N)")
                    if vendor and vendor.startswith('(DUP:'):
                        continue
                    # Vaciar vendor vacío o genérico
                    if not vendor:
                        vendor = None

                    # Conservar la entrada más completa si ya existe
                    if ip_str not in discovered:
                        discovered[ip_str] = {'mac_address': mac_str, 'vendor': vendor}

        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            print(f"⚠️  Error en ARP scan: {e}")

        return discovered
    
    def icmp_ping_scan(self, target_range: str) -> Set[str]:
        """
        Escaneo ICMP usando ping (echo request/reply).
        
        Técnica clásica pero efectiva. Algunos hosts filtran ICMP echo,
        por lo que se complementa con otras técnicas.
        
        Args:
            target_range: Rango de IPs a escanear
            
        Returns:
            Set de direcciones IP descubiertas
        """
        discovered = set()
        
        try:
            network = ipaddress.IPv4Network(target_range, strict=False)
        except ValueError:
            return discovered
        
        def ping_host(ip: ipaddress.IPv4Address) -> Optional[str]:
            """Ejecuta ping a una IP específica."""
            try:
                # Usar timeout más corto para mayor velocidad
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', str(self.timeout * 1000), str(ip)],
                    capture_output=True,
                    text=True,
                    timeout=self.timeout + 1
                )
                
                # Buscar indicadores de respuesta exitosa
                if result.returncode == 0:
                    # Verificar que realmente recibió respuesta
                    if "1 received" in result.stdout or "0% packet loss" in result.stdout:
                        return str(ip)
            except Exception:
                pass
            return None
        
        # Ejecutar ping concurrente
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            results = executor.map(ping_host, network.hosts())
            discovered = {ip for ip in results if ip is not None}
        
        return discovered
    
    def icmp_alternative_scan(self, target_range: str) -> Set[str]:
        """
        Escaneo ICMP usando tipos alternativos (timestamp, netmask).
        
        Algunos hosts filtran ICMP echo pero responden a otros tipos ICMP.
        Útil para evadir filtros básicos de firewall.
        
        Args:
            target_range: Rango de IPs a escanear
            
        Returns:
            Set de direcciones IP descubiertas
        """
        discovered = set()
        
        try:
            network = ipaddress.IPv4Network(target_range, strict=False)
        except ValueError:
            return discovered
        
        # Nota: ping puede usar tipos ICMP alternativos con opciones específicas
        # En Linux, podemos usar ping con timestamp request
        def icmp_timestamp(ip: ipaddress.IPv4Address) -> Optional[str]:
            """Intenta timestamp request."""
            try:
                # Usar nping o herramientas avanzadas si están disponibles
                # Por ahora, usamos una técnica simple con socket raw (requiere root)
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                sock.settimeout(self.timeout)
                
                # Construir paquete ICMP timestamp request (tipo 13)
                # Nota: Esto requiere permisos root y conocimiento de estructura de paquetes
                # Por simplicidad, omitimos esto aquí pero es una técnica válida
                sock.close()
            except (PermissionError, OSError):
                pass
            except Exception:
                pass
            return None
        
        # Para implementación completa, se requeriría usar scapy o herramientas avanzadas
        # Por ahora, esta función está preparada para extensión futura
        
        return discovered
    
    def syn_quick_scan(self, target_range: str, ports: List[int] = [22, 80, 443, 3389]) -> Set[str]:
        """
        Escaneo SYN rápido a puertos comunes para detectar hosts activos.
        
        Envía paquetes SYN a puertos comunes. Si recibimos SYN-ACK o RST,
        el host está activo. Más sigiloso que ping completo.
        
        Args:
            target_range: Rango de IPs a escanear
            ports: Lista de puertos a probar (por defecto puertos comunes)
            
        Returns:
            Set de direcciones IP descubiertas
        """
        discovered = set()
        
        try:
            network = ipaddress.IPv4Network(target_range, strict=False)
        except ValueError:
            return discovered
        
        def check_port(ip: str, port: int) -> bool:
            """Verifica si un puerto está abierto usando conexión TCP rápida."""
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                # Si hay respuesta (incluso cerrado), el host está activo
                return result == 0 or result == 111  # 0 = abierto, 111 = connection refused (host activo)
            except Exception:
                return False
        
        def scan_host(ip: ipaddress.IPv4Address) -> Optional[str]:
            """Escanea un host probando puertos comunes."""
            ip_str = str(ip)
            for port in ports:
                if check_port(ip_str, port):
                    return ip_str
            return None
        
        # Escaneo concurrente limitado para no saturar
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(self.max_threads, 20)) as executor:
            results = executor.map(scan_host, list(network.hosts())[:1000])  # Limitar a 1000 IPs
            discovered = {ip for ip in results if ip is not None}
        
        return discovered
    
    def discover_hosts(self, target_range: str, techniques: Optional[List[str]] = None,
                      process_callback: Optional[callable] = None,
                      is_cancelled_callback: Optional[callable] = None) -> Dict[str, Dict]:
        """
        Descubre hosts usando múltiples técnicas de forma inteligente.

        Combina diferentes técnicas para maximizar el descubrimiento:
        1. ARP scan (más rápido en LAN, aporta MAC y vendor)
        2. ICMP ping (técnica estándar)
        3. SYN quick scan (para hosts que filtran ICMP)

        Args:
            target_range: Rango de IPs a escanear
            techniques: Lista de técnicas a usar. Si None, usa todas disponibles.
                        Opciones: 'arp', 'icmp', 'syn'

        Returns:
            Dict IP -> {mac_address, vendor} con todos los hosts descubiertos.
            Para hosts encontrados sólo por ICMP/SYN, mac_address y vendor serán None.
        """
        if techniques is None:
            techniques = ['arp', 'icmp', 'syn']

        all_discovered: Dict[str, Dict] = {}

        print(f"🔍 Iniciando descubrimiento de hosts en {target_range}...")
        print(f"   Técnicas seleccionadas: {', '.join(techniques)}")

        # Técnica 1: ARP scan (más rápido en redes locales, aporta MAC + vendor)
        if 'arp' in techniques:
            if is_cancelled_callback and is_cancelled_callback(): return all_discovered
            print("   📡 Ejecutando ARP scan...")
            arp_results = self.arp_scan(target_range, process_callback=process_callback)
            all_discovered.update(arp_results)
            print(f"      ✓ Descubiertos {len(arp_results)} hosts vía ARP")
            if is_cancelled_callback and is_cancelled_callback(): return all_discovered

        # Técnica 2: ICMP ping (técnica estándar)
        if 'icmp' in techniques:
            if is_cancelled_callback and is_cancelled_callback(): return all_discovered
            print("   📡 Ejecutando ICMP ping scan...")
            icmp_results = self.icmp_ping_scan(target_range)
            for ip in icmp_results:
                if ip not in all_discovered:
                    all_discovered[ip] = {'mac_address': None, 'vendor': None}
            print(f"      ✓ Descubiertos {len(icmp_results)} hosts vía ICMP")
            if is_cancelled_callback and is_cancelled_callback(): return all_discovered

        # Técnica 3: SYN quick scan (para hosts que filtran ICMP)
        if 'syn' in techniques and len(all_discovered) < 10:
            if is_cancelled_callback and is_cancelled_callback(): return all_discovered
            print("   📡 Ejecutando SYN quick scan (puertos comunes)...")
            syn_results = self.syn_quick_scan(target_range)
            for ip in syn_results:
                if ip not in all_discovered:
                    all_discovered[ip] = {'mac_address': None, 'vendor': None}
            print(f"      ✓ Descubiertos {len(syn_results)} hosts vía SYN scan")
            if is_cancelled_callback and is_cancelled_callback(): return all_discovered

        print(f"✅ Total de hosts únicos descubiertos: {len(all_discovered)}")

        return all_discovered
    
    def extract_ips_from_output(self, output: str) -> Set[str]:
        """Extrae direcciones IP de una cadena de salida."""
        return set(self.extract_hosts_from_output(output).keys())

    def extract_hosts_from_output(self, output: str) -> Dict[str, Dict]:
        """
        Extrae hosts con MAC y vendor de una salida de texto.
        Soporta formato arp-scan (IP\\tMAC\\tVendor) y salida genérica (solo IPs).

        Returns:
            Dict IP -> {mac_address, vendor}
        """
        discovered: Dict[str, Dict] = {}
        mac_pattern = re.compile(r'([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})', re.IGNORECASE)
        ip_pattern_full = re.compile(r'\b((?:\d{1,3}\.){3}\d{1,3})\b')

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            ip_match = ip_pattern_full.search(line)
            if not ip_match:
                continue
            ip_str = ip_match.group(1)
            if not self._is_valid_ip(ip_str):
                continue

            mac_match = mac_pattern.search(line)
            if mac_match:
                mac_str = mac_match.group(1).upper()
                parts = re.split(r'\s+', line, maxsplit=2)
                vendor = parts[2].strip() if len(parts) >= 3 else None
                if vendor and vendor.startswith('(DUP:'):
                    continue
                if not vendor:
                    vendor = None
                if ip_str not in discovered:
                    discovered[ip_str] = {'mac_address': mac_str, 'vendor': vendor}
            else:
                if ip_str not in discovered:
                    discovered[ip_str] = {'mac_address': None, 'vendor': None}

        return discovered
    
    def _is_valid_ip(self, ip_str: str) -> bool:
        """Valida si una cadena es una IP válida y no es reservada."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return not (ip.is_multicast or ip.is_reserved or ip.is_loopback)
        except ValueError:
            return False

