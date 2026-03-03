"""
Gestor de Simuladores de Protocolos Industriales
"""
import logging
from typing import Dict, Optional, List
from simulators import (
    ModbusSimulator, FinsSimulator, S7commSimulator, Dnp3Simulator,
    Iec104Simulator, EthernetIPSimulator, BacnetSimulator, OpcuaSimulator
)

logger = logging.getLogger(__name__)

class SimulatorManager:
    """Gestor centralizado de todos los simuladores"""
    
    # Configuración de protocolos disponibles
    PROTOCOLS = {
        'modbus': {
            'name': 'Modbus TCP',
            'port': 502,
            'class': ModbusSimulator,
            'description': 'Protocolo Modbus TCP para comunicación industrial',
            'default_config': {
                'vendor_name': 'ArsenalOT',
                'product_code': 'Modbus Simulator',
                'vendor_url': 'https://arsenalot.com',
                'product_name': 'Modbus Simulator',
                'model_name': 'Simulator v1.0',
                'version': '1.0.0'
            }
        },
        'fins': {
            'name': 'FINS (Omron)',
            'port': 9600,
            'class': FinsSimulator,
            'description': 'Factory Interface Network Service de Omron',
            'default_config': {}
        },
        's7comm': {
            'name': 'S7comm (Siemens)',
            'port': 102,
            'class': S7commSimulator,
            'description': 'Protocolo S7comm de Siemens para PLCs',
            'default_config': {}
        },
        'dnp3': {
            'name': 'DNP3',
            'port': 20000,
            'class': Dnp3Simulator,
            'description': 'Distributed Network Protocol para sistemas SCADA',
            'default_config': {}
        },
        'iec104': {
            'name': 'IEC 60870-5-104',
            'port': 2404,
            'class': Iec104Simulator,
            'description': 'Protocolo IEC 104 para control remoto',
            'default_config': {}
        },
        'ethernetip': {
            'name': 'Ethernet/IP',
            'port': 44818,
            'class': EthernetIPSimulator,
            'description': 'Ethernet Industrial Protocol',
            'default_config': {}
        },
        'bacnet': {
            'name': 'BACnet',
            'port': 47808,
            'class': BacnetSimulator,
            'description': 'Building Automation and Control Networks',
            'default_config': {}
        },
        'opcua': {
            'name': 'OPC UA',
            'port': 4840,
            'class': OpcuaSimulator,
            'description': 'OPC Unified Architecture',
            'default_config': {}
        }
    }
    
    def __init__(self):
        self.simulators: Dict[str, Dict] = {}  # {simulator_id: {'simulator': instance, 'config': config}}
    
    def create_simulator(self, protocol: str, port: Optional[int] = None, config: Optional[Dict] = None) -> Optional[str]:
        """Crear un nuevo simulador"""
        if protocol not in self.PROTOCOLS:
            logger.error(f"Protocolo desconocido: {protocol}")
            return None
        
        protocol_info = self.PROTOCOLS[protocol]
        simulator_port = port or protocol_info['port']
        simulator_class = protocol_info['class']
        
        # Verificar que el puerto no esté en uso
        if self.is_port_in_use(simulator_port):
            logger.error(f"Puerto {simulator_port} ya está en uso")
            return None
        
        try:
            simulator = simulator_class(simulator_port)
            simulator_id = f"{protocol}_{simulator_port}"
            
            # Configuración por defecto + configuración personalizada
            default_config = protocol_info.get('default_config', {}).copy()
            if config:
                default_config.update(config)
            
            self.simulators[simulator_id] = {
                'simulator': simulator,
                'protocol': protocol,
                'port': simulator_port,
                'config': default_config,
                'created_at': None
            }
            
            logger.info(f"Simulador {simulator_id} creado")
            return simulator_id
            
        except Exception as e:
            logger.error(f"Error creando simulador {protocol}: {e}")
            return None
    
    def start_simulator(self, simulator_id: str) -> bool:
        """Iniciar un simulador"""
        if simulator_id not in self.simulators:
            logger.error(f"Simulador {simulator_id} no encontrado")
            return False
        
        simulator_data = self.simulators[simulator_id]
        simulator = simulator_data['simulator']
        
        if simulator.is_running:
            logger.warning(f"Simulador {simulator_id} ya está corriendo")
            return True
        
        try:
            success = simulator.start(simulator_data['config'])
            if success:
                simulator_data['created_at'] = simulator.get_info().get('created_at')
            return success
        except Exception as e:
            logger.error(f"Error iniciando simulador {simulator_id}: {e}")
            return False
    
    def stop_simulator(self, simulator_id: str) -> bool:
        """Detener un simulador"""
        if simulator_id not in self.simulators:
            logger.error(f"Simulador {simulator_id} no encontrado")
            return False
        
        simulator = self.simulators[simulator_id]['simulator']
        
        try:
            simulator.stop()
            return True
        except Exception as e:
            logger.error(f"Error deteniendo simulador {simulator_id}: {e}")
            return False
    
    def remove_simulator(self, simulator_id: str) -> bool:
        """Eliminar un simulador"""
        if simulator_id not in self.simulators:
            return False
        
        simulator_data = self.simulators[simulator_id]
        simulator = simulator_data['simulator']
        
        # Detener si está corriendo
        if simulator.is_running:
            simulator.stop()
        
        del self.simulators[simulator_id]
        logger.info(f"Simulador {simulator_id} eliminado")
        return True
    
    def get_simulator(self, simulator_id: str) -> Optional[Dict]:
        """Obtener información de un simulador"""
        if simulator_id not in self.simulators:
            return None
        
        simulator_data = self.simulators[simulator_id]
        simulator = simulator_data['simulator']
        
        return {
            'id': simulator_id,
            'protocol': simulator_data['protocol'],
            'port': simulator_data['port'],
            'status': simulator.get_status(),
            'info': simulator.get_info(),
            'config': simulator_data['config']
        }
    
    def list_simulators(self) -> List[Dict]:
        """Listar todos los simuladores"""
        return [self.get_simulator(sim_id) for sim_id in self.simulators.keys()]
    
    def get_simulator_logs(self, simulator_id: str, limit: int = 100) -> List[Dict]:
        """Obtener logs de un simulador"""
        if simulator_id not in self.simulators:
            return []
        
        simulator = self.simulators[simulator_id]['simulator']
        return simulator.get_logs(limit)
    
    def update_simulator_config(self, simulator_id: str, config: Dict) -> bool:
        """Actualizar configuración de un simulador"""
        if simulator_id not in self.simulators:
            return False
        
        simulator_data = self.simulators[simulator_id]
        simulator = simulator_data['simulator']
        
        # Actualizar configuración
        simulator_data['config'].update(config)
        simulator.update_config(config)
        
        return True
    
    def is_port_in_use(self, port: int) -> bool:
        """Verificar si un puerto está en uso"""
        for sim_data in self.simulators.values():
            if sim_data['port'] == port and sim_data['simulator'].is_running:
                return True
        return False
    
    def get_available_protocols(self) -> List[Dict]:
        """Obtener lista de protocolos disponibles"""
        return [
            {
                'id': protocol_id,
                'name': info['name'],
                'port': info['port'],
                'description': info['description'],
                'default_config': info.get('default_config', {})
            }
            for protocol_id, info in self.PROTOCOLS.items()
        ]

