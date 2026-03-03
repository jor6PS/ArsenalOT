"""
Simulador IEC 60870-5-104
"""
import socket
import threading
import struct
import logging
from typing import Dict
from simulators.base import ProtocolSimulator

logger = logging.getLogger(__name__)

class Iec104Simulator(ProtocolSimulator):
    """Simulador de servidor IEC 60870-5-104"""
    
    def __init__(self, port: int = 2404):
        super().__init__("IEC104 Simulator", port, "IEC104")
        self.server_socket = None
        self.clients = []
        self.ioa = {}  # Information Object Addresses
        
    def start(self, config: Dict) -> bool:
        """Iniciar servidor IEC104"""
        try:
            self.config = config
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(5)
            
            def run_server():
                self.log('info', f'Servidor IEC104 iniciado en puerto {self.port}')
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
                            self.log('error', f'Error aceptando conexión IEC104: {e}')
            
            self.thread = threading.Thread(target=run_server, daemon=True)
            self.thread.start()
            self.is_running = True
            return True
            
        except Exception as e:
            self.log('error', f'Error iniciando simulador IEC104: {e}')
            return False
    
    def handle_client(self, client_socket: socket.socket, addr: tuple):
        """Manejar cliente IEC104"""
        try:
            self.log('info', f'Cliente IEC104 conectado desde {addr[0]}:{addr[1]}')
            
            # Enviar STARTDT act (Start Data Transfer)
            startdt_act = self.build_startdt_act()
            client_socket.send(startdt_act)
            
            while self.is_running:
                data = client_socket.recv(4096)
                if not data:
                    break
                
                self.log('info', f'Petición IEC104 recibida de {addr[0]}:{addr[1]}', {
                    'data_length': len(data),
                    'data_hex': data[:20].hex()
                })
                
                # Procesar y responder
                response = self.build_iec104_response(data)
                if response:
                    client_socket.send(response)
                    self.log('info', f'Respuesta IEC104 enviada a {addr[0]}:{addr[1]}')
                    
        except Exception as e:
            self.log('error', f'Error manejando cliente IEC104: {e}')
        finally:
            client_socket.close()
            if (client_socket, addr) in self.clients:
                self.clients.remove((client_socket, addr))
            self.log('info', f'Cliente IEC104 desconectado: {addr[0]}:{addr[1]}')
    
    def build_startdt_act(self) -> bytes:
        """Construir STARTDT act"""
        # IEC104 APCI (Application Protocol Control Information)
        # Start byte: 0x68
        # Length: 4
        # Control field: STARTDT act (0x07)
        return struct.pack('BBBB', 0x68, 0x04, 0x07, 0x00)
    
    def build_iec104_response(self, request: bytes) -> bytes:
        """Construir respuesta IEC104"""
        try:
            if len(request) < 6:
                return None
            
            # STARTDT con (confirmación)
            if request[2] == 0x07:
                return struct.pack('BBBB', 0x68, 0x04, 0x0B, 0x00)
            
            # Respuesta genérica
            return struct.pack('BBBB', 0x68, 0x04, 0x83, 0x00)  # STOPDT con
            
        except Exception as e:
            self.log('error', f'Error construyendo respuesta IEC104: {e}')
        return None
    
    def stop(self):
        """Detener servidor IEC104"""
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
            self.log('info', 'Servidor IEC104 detenido')
        except Exception as e:
            self.log('error', f'Error deteniendo simulador IEC104: {e}')
    
    def get_status(self) -> Dict:
        """Obtener estado"""
        return {
            **self.get_info(),
            'connections': len(self.clients),
            'ioa_count': len(self.ioa)
        }
    
    def update_config(self, config: Dict):
        """Actualizar configuración"""
        self.config.update(config)
        self.log('info', 'Configuración actualizada')

