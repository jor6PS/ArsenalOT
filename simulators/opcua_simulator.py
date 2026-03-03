"""
Simulador OPC UA
"""
import socket
import threading
import struct
import logging
from typing import Dict
from simulators.base import ProtocolSimulator

logger = logging.getLogger(__name__)

class OpcuaSimulator(ProtocolSimulator):
    """Simulador de servidor OPC UA"""
    
    def __init__(self, port: int = 4840):
        super().__init__("OPC UA Simulator", port, "OPC UA")
        self.server_socket = None
        self.clients = []
        self.nodes = {}
        
    def start(self, config: Dict) -> bool:
        """Iniciar servidor OPC UA"""
        try:
            self.config = config
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(5)
            
            def run_server():
                self.log('info', f'Servidor OPC UA iniciado en puerto {self.port}')
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
                            self.log('error', f'Error aceptando conexión OPC UA: {e}')
            
            self.thread = threading.Thread(target=run_server, daemon=True)
            self.thread.start()
            self.is_running = True
            return True
            
        except Exception as e:
            self.log('error', f'Error iniciando simulador OPC UA: {e}')
            return False
    
    def handle_client(self, client_socket: socket.socket, addr: tuple):
        """Manejar cliente OPC UA"""
        try:
            self.log('info', f'Cliente OPC UA conectado desde {addr[0]}:{addr[1]}')
            
            while self.is_running:
                data = client_socket.recv(4096)
                if not data:
                    break
                
                self.log('info', f'Petición OPC UA recibida de {addr[0]}:{addr[1]}', {
                    'data_length': len(data),
                    'data_hex': data[:20].hex()
                })
                
                # Respuesta básica OPC UA
                response = self.build_opcua_response(data)
                if response:
                    client_socket.send(response)
                    self.log('info', f'Respuesta OPC UA enviada a {addr[0]}:{addr[1]}')
                    
        except Exception as e:
            self.log('error', f'Error manejando cliente OPC UA: {e}')
        finally:
            client_socket.close()
            if (client_socket, addr) in self.clients:
                self.clients.remove((client_socket, addr))
            self.log('info', f'Cliente OPC UA desconectado: {addr[0]}:{addr[1]}')
    
    def build_opcua_response(self, request: bytes) -> bytes:
        """Construir respuesta OPC UA"""
        try:
            # OPC UA utiliza un protocolo binario complejo
            # Respuesta básica de Hello/Acknowledge
            if len(request) >= 8:
                # Message Type: Acknowledge (ACK)
                response = b'ACK'
                # Chunk Type
                response += b'F'
                # Message Size
                response += struct.pack('>I', 28)
                # Protocol Version
                response += struct.pack('>I', 0)
                # Receive Buffer Size
                response += struct.pack('>I', 65535)
                # Send Buffer Size
                response += struct.pack('>I', 65535)
                # Max Message Size
                response += struct.pack('>I', 0)
                # Max Chunk Count
                response += struct.pack('>I', 0)
                
                return response
                
        except Exception as e:
            self.log('error', f'Error construyendo respuesta OPC UA: {e}')
        return None
    
    def stop(self):
        """Detener servidor OPC UA"""
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
            self.log('info', 'Servidor OPC UA detenido')
        except Exception as e:
            self.log('error', f'Error deteniendo simulador OPC UA: {e}')
    
    def get_status(self) -> Dict:
        """Obtener estado"""
        return {
            **self.get_info(),
            'connections': len(self.clients),
            'nodes': len(self.nodes)
        }
    
    def update_config(self, config: Dict):
        """Actualizar configuración"""
        self.config.update(config)
        self.log('info', 'Configuración actualizada')

