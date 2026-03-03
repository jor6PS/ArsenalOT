"""
Clase base para simuladores de protocolos industriales
"""
import logging
import threading
import queue
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Callable
from datetime import datetime

logger = logging.getLogger(__name__)

class ProtocolSimulator(ABC):
    """Clase base abstracta para todos los simuladores de protocolos"""
    
    def __init__(self, name: str, port: int, protocol: str):
        self.name = name
        self.port = port
        self.protocol = protocol
        self.is_running = False
        self.thread = None
        self.log_queue = queue.Queue()
        self.config = {}
        self.log_callbacks: List[Callable] = []
        
    def add_log_callback(self, callback: Callable):
        """Añadir callback para logs"""
        self.log_callbacks.append(callback)
    
    def log(self, level: str, message: str, data: Optional[Dict] = None):
        """Registrar un log"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'level': level,
            'message': message,
            'protocol': self.protocol,
            'port': self.port,
            'data': data or {}
        }
        
        # Añadir a cola
        self.log_queue.put(log_entry)
        
        # Llamar callbacks
        for callback in self.log_callbacks:
            try:
                callback(log_entry)
            except Exception as e:
                logger.error(f"Error en callback de log: {e}")
        
        # Log estándar
        log_func = getattr(logger, level.lower(), logger.info)
        log_func(f"[{self.protocol}] {message}")
    
    def get_logs(self, limit: int = 100) -> List[Dict]:
        """Obtener logs recientes"""
        logs = []
        temp_queue = queue.Queue()
        
        # Extraer todos los logs
        while not self.log_queue.empty():
            temp_queue.put(self.log_queue.get())
        
        # Devolver los últimos 'limit' logs
        all_logs = []
        while not temp_queue.empty():
            all_logs.append(temp_queue.get())
        
        return all_logs[-limit:] if len(all_logs) > limit else all_logs
    
    @abstractmethod
    def start(self, config: Dict) -> bool:
        """Iniciar el simulador"""
        pass
    
    @abstractmethod
    def stop(self):
        """Detener el simulador"""
        pass
    
    @abstractmethod
    def get_status(self) -> Dict:
        """Obtener estado del simulador"""
        pass
    
    @abstractmethod
    def update_config(self, config: Dict):
        """Actualizar configuración"""
        pass
    
    def get_info(self) -> Dict:
        """Obtener información del simulador"""
        return {
            'name': self.name,
            'protocol': self.protocol,
            'port': self.port,
            'is_running': self.is_running,
            'config': self.config
        }

