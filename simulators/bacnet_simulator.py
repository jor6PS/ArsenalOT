"""
Simulador BACnet
"""
import socket
import threading
import struct
import logging
from typing import Dict
from simulators.base import ProtocolSimulator

logger = logging.getLogger(__name__)

class BacnetSimulator(ProtocolSimulator):
    """Simulador de servidor BACnet"""
    
    def __init__(self, port: int = 47808):
        super().__init__("BACnet Simulator", port, "BACnet")
        self.server_socket = None
        self.clients = []
        self.objects = {}
        
    def start(self, config: Dict) -> bool:
        """Iniciar servidor BACnet"""
        try:
            self.config = config
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.settimeout(1.0)
            
            def run_server():
                self.log('info', f'Servidor BACnet iniciado en puerto {self.port}')
                while self.is_running:
                    try:
                        data, addr = self.server_socket.recvfrom(2048)
                        self.handle_bacnet_request(data, addr)
                    except socket.timeout:
                        continue
                    except Exception as e:
                        if self.is_running:
                            self.log('error', f'Error procesando BACnet: {e}')
            
            self.thread = threading.Thread(target=run_server, daemon=True)
            self.thread.start()
            self.is_running = True
            return True
            
        except Exception as e:
            self.log('error', f'Error iniciando simulador BACnet: {e}')
            return False
    
    def handle_bacnet_request(self, data: bytes, addr: tuple):
        """Procesar petición BACnet"""
        try:
            if len(data) < 2:
                return
            
            # BACnet/IP Header
            # Type: Original-Unicast-NPDU (0x0A)
            # Function: Who-Is, I-Am, etc.
            
            self.log('info', f'Petición BACnet recibida de {addr[0]}:{addr[1]}', {
                'data_length': len(data),
                'data_hex': data[:20].hex()
            })
            
            # Respuesta básica BACnet
            response = self.build_bacnet_response(data)
            if response:
                self.server_socket.sendto(response, addr)
                self.log('info', f'Respuesta BACnet enviada a {addr[0]}:{addr[1]}')
                
        except Exception as e:
            self.log('error', f'Error procesando petición BACnet: {e}')
    
    def build_bacnet_response(self, request: bytes) -> bytes:
        """Construir respuesta BACnet"""
        try:
            if len(request) < 2:
                return None
            
            # BACnet/IP Header básico
            # Type: Original-Unicast-NPDU
            response = struct.pack('BB', 0x81, 0x0A)
            # Length
            response += struct.pack('>H', 0x0004)
            # NPDU
            response += struct.pack('BB', 0x01, 0x20)  # Version, NPDU type
            
            return response
            
        except Exception as e:
            self.log('error', f'Error construyendo respuesta BACnet: {e}')
        return None
    
    def stop(self):
        """Detener servidor BACnet"""
        try:
            self.is_running = False
            if self.server_socket:
                self.server_socket.close()
            self.log('info', 'Servidor BACnet detenido')
        except Exception as e:
            self.log('error', f'Error deteniendo simulador BACnet: {e}')
    
    def get_status(self) -> Dict:
        """Obtener estado"""
        return {
            **self.get_info(),
            'connections': len(self.clients),
            'objects': len(self.objects)
        }
    
    def update_config(self, config: Dict):
        """Actualizar configuración"""
        self.config.update(config)
        self.log('info', 'Configuración actualizada')

