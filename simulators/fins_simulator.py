"""
Simulador FINS (Omron)
"""
import socket
import threading
import struct
import logging
from typing import Dict
from simulators.base import ProtocolSimulator

logger = logging.getLogger(__name__)

class FinsSimulator(ProtocolSimulator):
    """Simulador de servidor FINS (Factory Interface Network Service) de Omron"""
    
    def __init__(self, port: int = 9600):
        super().__init__("FINS Simulator", port, "FINS")
        self.server_socket = None
        self.clients = []
        self.memory = {}
        
    def start(self, config: Dict) -> bool:
        """Iniciar servidor FINS"""
        try:
            self.config = config
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.settimeout(1.0)
            
            def run_server():
                self.log('info', f'Servidor FINS iniciado en puerto {self.port}')
                while self.is_running:
                    try:
                        data, addr = self.server_socket.recvfrom(2048)
                        self.handle_fins_request(data, addr)
                    except socket.timeout:
                        continue
                    except Exception as e:
                        if self.is_running:
                            self.log('error', f'Error procesando FINS: {e}')
            
            self.thread = threading.Thread(target=run_server, daemon=True)
            self.thread.start()
            self.is_running = True
            return True
            
        except Exception as e:
            self.log('error', f'Error iniciando simulador FINS: {e}')
            return False
    
    def handle_fins_request(self, data: bytes, addr: tuple):
        """Procesar petición FINS"""
        try:
            if len(data) < 10:
                return
            
            # Parsear header FINS
            fins_header = struct.unpack('>BBBBBBBB', data[:8])
            command = data[8:10]
            
            self.log('info', f'Petición FINS recibida de {addr[0]}:{addr[1]}', {
                'command': command.hex(),
                'data_length': len(data)
            })
            
            # Respuesta básica FINS
            response = self.build_fins_response(data)
            if response:
                self.server_socket.sendto(response, addr)
                self.log('info', f'Respuesta FINS enviada a {addr[0]}:{addr[1]}')
                
        except Exception as e:
            self.log('error', f'Error procesando petición FINS: {e}')
    
    def build_fins_response(self, request: bytes) -> bytes:
        """Construir respuesta FINS"""
        try:
            # Respuesta básica de confirmación
            if len(request) >= 10:
                # Header FINS
                response = bytearray(request[:8])
                # Command response
                response.extend(b'\x00\x00')  # Comando de respuesta
                response.extend(b'\x00\x00')  # End code (normal)
                return bytes(response)
        except Exception as e:
            self.log('error', f'Error construyendo respuesta FINS: {e}')
        return None
    
    def stop(self):
        """Detener servidor FINS"""
        try:
            self.is_running = False
            if self.server_socket:
                self.server_socket.close()
            self.log('info', 'Servidor FINS detenido')
        except Exception as e:
            self.log('error', f'Error deteniendo simulador FINS: {e}')
    
    def get_status(self) -> Dict:
        """Obtener estado"""
        return {
            **self.get_info(),
            'connections': len(self.clients),
            'memory_registers': len(self.memory)
        }
    
    def update_config(self, config: Dict):
        """Actualizar configuración"""
        self.config.update(config)
        self.log('info', 'Configuración actualizada')

