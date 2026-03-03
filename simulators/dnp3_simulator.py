"""
Simulador DNP3
"""
import socket
import threading
import struct
import logging
from typing import Dict
from simulators.base import ProtocolSimulator

logger = logging.getLogger(__name__)

class Dnp3Simulator(ProtocolSimulator):
    """Simulador de servidor DNP3 (Distributed Network Protocol)"""
    
    def __init__(self, port: int = 20000):
        super().__init__("DNP3 Simulator", port, "DNP3")
        self.server_socket = None
        self.clients = []
        self.points = {}
        
    def start(self, config: Dict) -> bool:
        """Iniciar servidor DNP3"""
        try:
            self.config = config
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(5)
            
            def run_server():
                self.log('info', f'Servidor DNP3 iniciado en puerto {self.port}')
                while self.is_running:
                    try:
                        client_socket, addr = self.server_socket.accept()
                        self.clients.append((client_socket, addr))
                        client_thread = threading.Thread(
                            target=self.handle_client,
                            args=(client_socket, addr),
                            daemon=True
                        )
                        client_thread.start()
                    except Exception as e:
                        if self.is_running:
                            self.log('error', f'Error aceptando conexión DNP3: {e}')
            
            self.thread = threading.Thread(target=run_server, daemon=True)
            self.thread.start()
            self.is_running = True
            return True
            
        except Exception as e:
            self.log('error', f'Error iniciando simulador DNP3: {e}')
            return False
    
    def handle_client(self, client_socket: socket.socket, addr: tuple):
        """Manejar cliente DNP3"""
        try:
            self.log('info', f'Cliente DNP3 conectado desde {addr[0]}:{addr[1]}')
            
            while self.is_running:
                data = client_socket.recv(4096)
                if not data:
                    break
                
                self.log('info', f'Petición DNP3 recibida de {addr[0]}:{addr[1]}', {
                    'data_length': len(data),
                    'data_hex': data[:20].hex()
                })
                
                # Respuesta básica DNP3
                response = self.build_dnp3_response(data)
                if response:
                    client_socket.send(response)
                    self.log('info', f'Respuesta DNP3 enviada a {addr[0]}:{addr[1]}')
                    
        except Exception as e:
            self.log('error', f'Error manejando cliente DNP3: {e}')
        finally:
            client_socket.close()
            if (client_socket, addr) in self.clients:
                self.clients.remove((client_socket, addr))
            self.log('info', f'Cliente DNP3 desconectado: {addr[0]}:{addr[1]}')
    
    def build_dnp3_response(self, request: bytes) -> bytes:
        """Construir respuesta DNP3"""
        try:
            if len(request) < 10:
                return None
            
            # DNP3 Header básico
            # Start bytes
            response = b'\x05\x64'
            # Length
            response += struct.pack('>H', 0x0008)
            # Control
            response += b'\x44'  # Response, no error
            # Destination
            response += b'\x00\x00'
            # Source
            response += b'\x00\x00'
            
            return response
            
        except Exception as e:
            self.log('error', f'Error construyendo respuesta DNP3: {e}')
        return None
    
    def stop(self):
        """Detener servidor DNP3"""
        try:
            self.is_running = False
            for client_socket, _ in self.clients:
                try:
                    client_socket.close()
                except:
                    pass
            self.clients.clear()
            if self.server_socket:
                self.server_socket.close()
            self.log('info', 'Servidor DNP3 detenido')
        except Exception as e:
            self.log('error', f'Error deteniendo simulador DNP3: {e}')
    
    def get_status(self) -> Dict:
        """Obtener estado"""
        return {
            **self.get_info(),
            'connections': len(self.clients),
            'points': len(self.points)
        }
    
    def update_config(self, config: Dict):
        """Actualizar configuración"""
        self.config.update(config)
        self.log('info', 'Configuración actualizada')

