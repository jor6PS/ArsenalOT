"""
Módulo de detección mejorada de servicios y banners.

Integra detección de servicios específicos:
- Servicios web (HTTP/HTTPS)
- Protocolos OT (Modbus, BACnet)
- Banners de servicios comunes
- Detección de versiones
"""

from typing import Dict, Optional
import socket
import sys
from pathlib import Path

# Importar módulos de protocolos si están disponibles
try:
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from protocols.modbus_banner import modbus_banner
    MODBUS_AVAILABLE = True
except ImportError:
    MODBUS_AVAILABLE = False
    modbus_banner = None

try:
    from protocols.bacnet_banner import bacnet_banner
    BACNET_AVAILABLE = True
except ImportError:
    BACNET_AVAILABLE = False
    bacnet_banner = None


class ServiceDetection:
    """Clase para detección mejorada de servicios y banners."""
    
    def __init__(self, timeout: int = 3):
        """
        Inicializa el detector de servicios.
        
        Args:
            timeout: Timeout en segundos para conexiones
        """
        self.timeout = timeout
    
    def get_banner(self, host: str, port: int, protocol: str = 'tcp') -> Optional[str]:
        """
        Obtiene el banner de un servicio.
        
        Args:
            host: IP o hostname
            port: Puerto
            protocol: Protocolo ('tcp' o 'udp')
            
        Returns:
            Banner del servicio o None
        """
        if protocol != 'tcp':
            return None
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # Intentar recibir banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner if banner else None
        except Exception:
            return None
    
    def detect_modbus(self, host: str, port: int = 502) -> Optional[Dict]:
        """
        Detecta información Modbus en un dispositivo.
        
        Args:
            host: IP del dispositivo
            port: Puerto Modbus (por defecto 502)
            
        Returns:
            Diccionario con información Modbus o None
        """
        if not MODBUS_AVAILABLE or not modbus_banner:
            return None
        
        try:
            return modbus_banner(host)
        except Exception:
            return None
    
    def detect_bacnet(self, host: str, port: int = 47808) -> Optional[Dict]:
        """
        Detecta información BACnet en un dispositivo.
        
        Args:
            host: IP del dispositivo
            port: Puerto BACnet (por defecto 47808)
            
        Returns:
            Diccionario con información BACnet o None
        """
        if not BACNET_AVAILABLE or not bacnet_banner:
            return None
        
        try:
            return bacnet_banner(host)
        except Exception:
            return None
    
    def detect_service_type(self, host: str, port: int) -> Optional[str]:
        """
        Detecta el tipo de servicio en un puerto.
        
        Args:
            host: IP del dispositivo
            port: Puerto a verificar
            
        Returns:
            Tipo de servicio detectado o None
        """
        # Intentar obtener banner
        banner = self.get_banner(host, port)
        
        if not banner:
            return None
        
        banner_lower = banner.lower()
        
        # Detección básica de servicios comunes
        if 'ssh' in banner_lower:
            return 'ssh'
        elif 'http' in banner_lower or 'apache' in banner_lower or 'nginx' in banner_lower:
            return 'http'
        elif 'ftp' in banner_lower:
            return 'ftp'
        elif 'smtp' in banner_lower:
            return 'smtp'
        elif 'pop' in banner_lower:
            return 'pop'
        elif 'imap' in banner_lower:
            return 'imap'
        elif 'telnet' in banner_lower:
            return 'telnet'
        
        return 'unknown'

