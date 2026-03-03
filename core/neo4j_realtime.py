"""
Módulo para actualización en tiempo real de Neo4j durante escaneos
"""
from py2neo import Graph, Node, Relationship
import logging
from typing import Dict, Optional, Callable

logger = logging.getLogger(__name__)


class Neo4jRealtimeUpdater:
    """Actualizador en tiempo real de Neo4j durante escaneos"""
    
    def __init__(self, bolt_url: str, username: str, password: str):
        self.bolt_url = bolt_url
        self.username = username
        self.password = password
        self.graph = None
        self._connect()
    
    def _connect(self):
        """Conectar a Neo4j"""
        try:
            self.graph = Graph(self.bolt_url, auth=(self.username, self.password))
            # Verificar conexión
            self.graph.run("MATCH (n) RETURN count(n) LIMIT 1")
            logger.info("Conectado a Neo4j para actualización en tiempo real")
        except Exception as e:
            logger.error(f"Error conectando a Neo4j: {e}")
            self.graph = None
    
    def is_connected(self) -> bool:
        """Verificar si hay conexión activa"""
        if not self.graph:
            return False
        try:
            self.graph.run("RETURN 1")
            return True
        except:
            return False
    
    def update_host(self, org: str, location: str, subnet: str, ip: str, 
                   hostname: Optional[str] = None, **properties):
        """Actualizar o crear nodo de host/IP en tiempo real"""
        if not self.is_connected():
            return False
        
        try:
            # Crear o actualizar nodo de organización
            org_node = self._get_or_create_node(
                "ORG", {"org": org.upper()}, 
                name=org.upper()
            )
            
            # Crear o actualizar nodo de ubicación/segmento
            seg_node = self._get_or_create_node(
                "SEG", {"org": org.upper(), "SEG": location.upper()},
                name=location.upper()
            )
            self._create_relationship(org_node, seg_node, "HAS_SEG")
            
            # Crear o actualizar nodo de subred
            subnet_node = self._get_or_create_node(
                "Subred", {"org": org.upper(), "SEG": location.upper(), "Subred": subnet},
                name=subnet
            )
            self._create_relationship(seg_node, subnet_node, "HAS_SUBNET")
            
            # Crear o actualizar nodo de IP
            ip_props = {
                "org": org.upper(),
                "SEG": location.upper(),
                "Subred": subnet,
                "IP": ip
            }
            if hostname:
                ip_props["hostname"] = hostname
            
            ip_node = self._get_or_create_node("IP", {"IP": ip, "org": org.upper()}, **ip_props)
            self._create_relationship(subnet_node, ip_node, "HAS_IP")
            
            return True
        except Exception as e:
            logger.error(f"Error actualizando host {ip}: {e}")
            return False
    
    def update_port(self, org: str, location: str, subnet: str, ip: str, 
                   port: str, port_data: Dict):
        """
        Actualizar o crear nodo de puerto en tiempo real
        Sigue la estructura exacta del JSON: ORG -> LOCATION (SEG) -> SUBNET -> IP -> PORT
        Guarda TODAS las propiedades del puerto del JSON
        """
        if not self.is_connected():
            return False
        
        try:
            import json
            
            # Asegurar que existe la jerarquía completa
            org_node = self._get_or_create_node(
                "ORG", {"org": org.upper()}, name=org.upper()
            )
            
            seg_node = self._get_or_create_node(
                "SEG", {"org": org.upper(), "SEG": location.upper()},
                name=location.upper()
            )
            self._create_relationship(org_node, seg_node, "HAS_SEG")
            
            subnet_node = self._get_or_create_node(
                "Subred", {
                    "org": org.upper(), 
                    "SEG": location.upper(), 
                    "Subred": subnet
                },
                name=subnet
            )
            self._create_relationship(seg_node, subnet_node, "HAS_SUBNET")
            
            # Obtener o crear nodo IP
            ip_node = self.graph.nodes.match("IP", IP=ip, org=org.upper()).first()
            if not ip_node:
                # Crear IP con propiedades básicas
                ip_props = {
                    "org": org.upper(),
                    "SEG": location.upper(),
                    "Subred": subnet,
                    "IP": ip
                }
                # Añadir hostname si está en port_data
                if 'Hostname' in port_data and port_data['Hostname']:
                    ip_props["hostname"] = port_data['Hostname']
                
                ip_node = self._get_or_create_node("IP", {"IP": ip, "org": org.upper()}, **ip_props)
                self._create_relationship(subnet_node, ip_node, "HAS_IP")
            
            if not ip_node:
                logger.warning(f"No se pudo obtener/crear nodo IP para {ip}")
                return False
            
            # Crear propiedades del puerto siguiendo la estructura exacta del JSON
            port_match_props = {
                "org": org.upper(),
                "SEG": location.upper(),
                "Subred": subnet,
                "IP": ip,
                "number": port
            }
            
            # Copiar TODAS las propiedades del puerto del JSON
            port_props = {**port_match_props}
            for key, value in port_data.items():
                if value not in [None, "", "null"]:
                    # Convertir valores complejos a JSON string
                    if isinstance(value, (dict, list)):
                        port_props[key] = json.dumps(value) if value else ""
                    elif isinstance(value, bool):
                        port_props[key] = value
                    else:
                        port_props[key] = str(value) if value else ""
            
            # Crear o actualizar nodo de puerto con todas las propiedades
            port_node = self._get_or_create_node(
                "Port",
                {"org": org.upper(), "IP": ip, "number": port},
                **port_props
            )
            
            self._create_relationship(ip_node, port_node, "HAS_PORT")
            
            return True
        except Exception as e:
            logger.error(f"Error actualizando puerto {ip}:{port}: {e}")
            return False
    
    def _get_or_create_node(self, label: str, match_props: Dict, **properties):
        """Obtener o crear un nodo, actualizando todas las propiedades"""
        try:
            import json
            
            # Procesar propiedades: convertir valores complejos a JSON string
            processed_props = {}
            for key, value in properties.items():
                if isinstance(value, (dict, list)):
                    processed_props[key] = json.dumps(value) if value else ""
                elif value is None:
                    processed_props[key] = ""
                else:
                    processed_props[key] = value
            
            node = self.graph.nodes.match(label, **match_props).first()
            if node:
                # Actualizar todas las propiedades existentes
                for key, value in processed_props.items():
                    setattr(node, key, value)
                self.graph.push(node)
                return node
            else:
                # Crear nuevo nodo con todas las propiedades
                all_props = {**match_props, **processed_props}
                node = Node(label, **all_props)
                self.graph.create(node)
                return node
        except Exception as e:
            logger.error(f"Error en _get_or_create_node: {e}")
            raise
    
    def _create_relationship(self, start_node, end_node, rel_type: str, **properties):
        """Crear relación si no existe"""
        if not start_node or not end_node:
            return None
        
        try:
            # Verificar si la relación ya existe
            rel = self.graph.match((start_node, end_node), r_type=rel_type).first()
            if rel:
                return rel
            
            # Crear nueva relación
            rel = Relationship(start_node, rel_type, end_node, **properties)
            self.graph.create(rel)
            return rel
        except Exception as e:
            logger.error(f"Error creando relación: {e}")
            return None
    
    def batch_update(self, updates: list):
        """Actualizar múltiples elementos en un batch"""
        if not self.is_connected():
            return False
        
        try:
            tx = self.graph.begin()
            for update in updates:
                if update['type'] == 'host':
                    # Actualizar host
                    pass
                elif update['type'] == 'port':
                    # Actualizar puerto
                    pass
            self.graph.commit(tx)
            return True
        except Exception as e:
            logger.error(f"Error en batch_update: {e}")
            self.graph.rollback(tx)
            return False

