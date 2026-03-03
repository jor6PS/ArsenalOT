"""
Simulador Ethernet/IP
"""
import socket
import threading
import struct
import logging
from typing import Dict
from simulators.base import ProtocolSimulator

logger = logging.getLogger(__name__)

class EthernetIPSimulator(ProtocolSimulator):
    """Simulador de servidor Ethernet/IP"""
    
    def __init__(self, port: int = 44818):
        super().__init__("Ethernet/IP Simulator", port, "Ethernet/IP")
        self.server_socket = None
        self.clients = []
        self.tags = {}
        
    def start(self, config: Dict) -> bool:
        """Iniciar servidor Ethernet/IP"""
        try:
            self.config = config
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(5)
            
            def run_server():
                self.log('info', f'Servidor Ethernet/IP iniciado en puerto {self.port}')
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
                            self.log('error', f'Error aceptando conexión Ethernet/IP: {e}')
            
            self.thread = threading.Thread(target=run_server, daemon=True)
            self.thread.start()
            self.is_running = True
            return True
            
        except Exception as e:
            self.log('error', f'Error iniciando simulador Ethernet/IP: {e}')
            return False
    
    def handle_client(self, client_socket: socket.socket, addr: tuple):
        """Manejar cliente Ethernet/IP"""
        try:
            self.log('info', f'Cliente Ethernet/IP conectado desde {addr[0]}:{addr[1]}')
            
            while self.is_running:
                data = client_socket.recv(4096)
                if not data:
                    break
                
                self.log('info', f'Petición Ethernet/IP recibida de {addr[0]}:{addr[1]}', {
                    'data_length': len(data),
                    'data_hex': data[:20].hex()
                })
                
                # Respuesta básica Ethernet/IP
                response = self.build_ethernetip_response(data)
                if response:
                    client_socket.send(response)
                    self.log('info', f'Respuesta Ethernet/IP enviada a {addr[0]}:{addr[1]}')
                    
        except Exception as e:
            self.log('error', f'Error manejando cliente Ethernet/IP: {e}')
        finally:
            client_socket.close()
            if (client_socket, addr) in self.clients:
                self.clients.remove((client_socket, addr))
            self.log('info', f'Cliente Ethernet/IP desconectado: {addr[0]}:{addr[1]}')
    
    def build_ethernetip_response(self, request: bytes) -> bytes:
        """Construir respuesta Ethernet/IP"""
        try:
            if len(request) < 24:
                return None
            
            # Ethernet/IP Header
            # Command: Register Session (0x0065) response
            response = struct.pack('>HHHH', 0x0065, 0x0000, 0x0004, 0x0000)
            # Session handle
            response += struct.pack('>I', 0x00000001)
            # Status: Success
            response += struct.pack('>I', 0x00000000)
            
            return response
            
        except Exception as e:
            self.log('error', f'Error construyendo respuesta Ethernet/IP: {e}')
        return None
    
    def stop(self):
        """Detener servidor Ethernet/IP"""
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
            self.log('info', 'Servidor Ethernet/IP detenido')
        except Exception as e:
            self.log('error', f'Error deteniendo simulador Ethernet/IP: {e}')
    
    def get_status(self) -> Dict:
        """Obtener estado"""
        return {
            **self.get_info(),
            'connections': len(self.clients),
            'tags': len(self.tags)
        }
    
    def update_config(self, config: Dict):
        """Actualizar configuración"""
        self.config.update(config)
        self.log('info', 'Configuración actualizada')

