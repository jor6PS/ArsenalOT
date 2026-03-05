import asyncio
from typing import Dict
from fastapi import WebSocket, WebSocketDisconnect

class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
    
    async def connect(self, websocket: WebSocket, scan_id: str):
        await websocket.accept()
        self.active_connections[scan_id] = websocket
    
    def disconnect(self, scan_id: str):
        if scan_id in self.active_connections:
            del self.active_connections[scan_id]
    
    async def send_progress(self, scan_id: str, message: dict):
        if scan_id not in self.active_connections:
            return  # Conexión no existe, no intentar enviar
        
        websocket = self.active_connections[scan_id]
        
        # Verificar estado de la conexión
        try:
            # Intentar enviar el mensaje
            await websocket.send_json(message)
        except (WebSocketDisconnect, ConnectionError, RuntimeError, asyncio.CancelledError):
            # Conexión cerrada o error, desconectar limpiamente
            self.disconnect(scan_id)
        except Exception as e:
            # Verificar si el error es por conexión cerrada
            error_str = str(e).lower()
            if any(keyword in error_str for keyword in ['closed', 'disconnect', 'connection']):
                # Conexión cerrada, solo desconectar sin loguear
                self.disconnect(scan_id)
            else:
                # Otro error, desconectar y loguear solo si no es un error de conexión
                print(f"Error enviando progreso a scan {scan_id}: {e}")
                self.disconnect(scan_id)

manager = ConnectionManager()
