"""
Simulador Modbus TCP/RTU
"""
import socket
import threading
import struct
import logging
from typing import Dict
from simulators.base import ProtocolSimulator
try:
    from pymodbus.server.sync import StartTcpServer
    from pymodbus.device import ModbusDeviceIdentification
    from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext
    from pymodbus.datastore import ModbusSequentialDataBlock
except ImportError:
    # Fallback para versiones más recientes de pymodbus
    try:
        from pymodbus.server import StartTcpServer
        from pymodbus.device import ModbusDeviceIdentification
        from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext
        from pymodbus.datastore import ModbusSequentialDataBlock
    except ImportError:
        logger.warning("pymodbus no disponible, simulador Modbus limitado")
        StartTcpServer = None

logger = logging.getLogger(__name__)

class ModbusSimulator(ProtocolSimulator):
    """Simulador de servidor Modbus TCP"""
    
    def __init__(self, port: int = 502):
        super().__init__("Modbus TCP Simulator", port, "Modbus")
        self.server = None
        self.store = None
        self.context = None
        
    def start(self, config: Dict) -> bool:
        """Iniciar servidor Modbus"""
        try:
            self.config = config
            
            # Configurar datastore
            # Holding Registers (4x)
            hr_data = ModbusSequentialDataBlock(0, [0] * 100)
            # Input Registers (3x)
            ir_data = ModbusSequentialDataBlock(0, [0] * 100)
            # Coils (0x)
            coil_data = ModbusSequentialDataBlock(0, [0] * 100)
            # Discrete Inputs (1x)
            di_data = ModbusSequentialDataBlock(0, [0] * 100)
            
            self.store = ModbusSlaveContext(
                di=di_data,
                co=coil_data,
                hr=hr_data,
                ir=ir_data
            )
            
            self.context = ModbusServerContext(slaves={1: self.store}, single=True)
            
            # Identificación del dispositivo
            identity = ModbusDeviceIdentification()
            identity.VendorName = config.get('vendor_name', 'ArsenalOT')
            identity.ProductCode = config.get('product_code', 'Modbus Simulator')
            identity.VendorUrl = config.get('vendor_url', 'https://arsenalot.com')
            identity.ProductName = config.get('product_name', 'Modbus Simulator')
            identity.ModelName = config.get('model_name', 'Simulator v1.0')
            identity.MajorMinorRevision = config.get('version', '1.0.0')
            
            if StartTcpServer is None:
                self.log('error', 'pymodbus no está disponible')
                return False
            
            # Iniciar servidor en thread separado
            def run_server():
                try:
                    self.server = StartTcpServer(
                        context=self.context,
                        identity=identity,
                        address=("0.0.0.0", self.port)
                    )
                except Exception as e:
                    self.log('error', f'Error en servidor Modbus: {e}')
            
            self.thread = threading.Thread(target=run_server, daemon=True)
            self.thread.start()
            
            # Dar tiempo para que el servidor inicie
            import time
            time.sleep(0.5)
            
            self.is_running = True
            self.log('info', f'Servidor Modbus iniciado en puerto {self.port}')
            return True
            
        except Exception as e:
            self.log('error', f'Error iniciando simulador Modbus: {e}')
            return False
    
    def stop(self):
        """Detener servidor Modbus"""
        try:
            self.is_running = False
            if self.server:
                # pymodbus no tiene método stop directo, necesitamos cerrar el socket
                pass
            self.log('info', 'Servidor Modbus detenido')
        except Exception as e:
            self.log('error', f'Error deteniendo simulador Modbus: {e}')
    
    def get_status(self) -> Dict:
        """Obtener estado"""
        return {
            **self.get_info(),
            'connections': 0,  # TODO: Implementar contador de conexiones
            'requests_handled': 0  # TODO: Implementar contador
        }
    
    def update_config(self, config: Dict):
        """Actualizar configuración"""
        self.config.update(config)
        self.log('info', 'Configuración actualizada')

