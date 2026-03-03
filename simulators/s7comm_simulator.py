"""
Simulador S7comm (Siemens)
"""
import socket
import threading
import struct
import logging
from typing import Dict
from simulators.base import ProtocolSimulator

logger = logging.getLogger(__name__)

class S7commSimulator(ProtocolSimulator):
    """Simulador de servidor S7comm (Siemens S7)"""
    
    def __init__(self, port: int = 102):
        super().__init__("S7comm Simulator", port, "S7comm")
        self.server_socket = None
        self.clients = []
        self.memory = {}
        
    def start(self, config: Dict) -> bool:
        """Iniciar servidor S7comm"""
        try:
            self.config = config
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(5)
            
            def run_server():
                self.log('info', f'Servidor S7comm iniciado en puerto {self.port}')
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
                            self.log('error', f'Error aceptando conexión S7comm: {e}')
            
            self.thread = threading.Thread(target=run_server, daemon=True)
            self.thread.start()
            self.is_running = True
            return True
            
        except Exception as e:
            self.log('error', f'Error iniciando simulador S7comm: {e}')
            return False
    
    def handle_client(self, client_socket: socket.socket, addr: tuple):
        """Manejar cliente S7comm"""
        try:
            self.log('info', f'Cliente S7comm conectado desde {addr[0]}:{addr[1]}')
            
            while self.is_running:
                data = client_socket.recv(4096)
                if not data:
                    break
                
                self.log('info', f'Petición S7comm recibida de {addr[0]}:{addr[1]}', {
                    'data_length': len(data),
                    'data_hex': data[:20].hex()  # Primeros 20 bytes
                })
                
                # Respuesta básica S7comm
                response = self.build_s7comm_response(data)
                if response:
                    client_socket.send(response)
                    self.log('info', f'Respuesta S7comm enviada a {addr[0]}:{addr[1]}')
                    
        except Exception as e:
            self.log('error', f'Error manejando cliente S7comm: {e}')
        finally:
            client_socket.close()
            if (client_socket, addr) in self.clients:
                self.clients.remove((client_socket, addr))
            self.log('info', f'Cliente S7comm desconectado: {addr[0]}:{addr[1]}')
    
    def build_s7comm_response(self, request: bytes) -> bytes:
        """Construir respuesta S7comm"""
        try:
            if len(request) < 4:
                return None
            
            # Header S7comm básico
            # TPKT Header
            tpkt_length = len(request) + 4
            response = struct.pack('>BBH', 0x03, 0x00, tpkt_length)
            
            # COTP Header
            response += struct.pack('BB', 0x02, 0xf0)  # Data TPDU
            
            # S7 Header básico
            response += struct.pack('>BBHHH', 0x32, 0x01, 0x0000, 0x0001, 0x0000)
            
            # Respuesta de confirmación
            response += b'\x00'  # Error code (no error)
            
            return response
            
        except Exception as e:
            self.log('error', f'Error construyendo respuesta S7comm: {e}')
        return None
    
    def stop(self):
        """Detener servidor S7comm"""
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
            self.log('info', 'Servidor S7comm detenido')
        except Exception as e:
            self.log('error', f'Error deteniendo simulador S7comm: {e}')
    
    def get_status(self) -> Dict:
        """Obtener estado"""
        return {
            **self.get_info(),
            'connections': len(self.clients),
            'memory_blocks': len(self.memory)
        }
    
    def update_config(self, config: Dict):
        """Actualizar configuración"""
        self.config.update(config)
        self.log('info', 'Configuración actualizada')

