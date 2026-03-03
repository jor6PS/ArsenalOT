"""
Neo4j Importer Module - Adaptado para uso en aplicación web
"""
from py2neo import Graph
import os
import json
import logging
import getpass
from typing import Dict, Optional

logger = logging.getLogger(__name__)

class Neo4jImporter:
    """Clase para importar resultados a Neo4j"""
    
    def test_connection(self, ip: str, username: Optional[str] = None, 
                       password: Optional[str] = None) -> Dict:
        """
        Probar conexión a Neo4j
        
        Returns:
            Dict con resultado de la conexión
        """
        try:
            if username is None:
                username = "neo4j"
            if password is None:
                password = "neo4j"
            
            graph = Graph(f"bolt://{ip}:7687", auth=(username, password))
            graph.run("MATCH (n) RETURN count(n)")
            
            return {'success': True, 'message': 'Conexión exitosa'}
        except Exception as e:
            error_msg = str(e).lower()
            if "authentication" in error_msg or "failed to authenticate" in error_msg:
                return {'success': False, 'error': 'Error de autenticación. Verifica las credenciales.'}
            elif "connection" in error_msg or "refused" in error_msg:
                return {'success': False, 'error': f'No se pudo conectar a Neo4j en {ip}:7687'}
            else:
                return {'success': False, 'error': f'Error: {str(e)}'}
    
    def import_all_results(self, ip: str, username: Optional[str] = None,
                          password: Optional[str] = None) -> Dict:
        """
        Importar todos los resultados a Neo4j
        
        Returns:
            Dict con resultado de la importación
        """
        try:
            # Conectar a Neo4j
            if username is None:
                username = "neo4j"
            if password is None:
                password = "neo4j"
            
            graph = Graph(f"bolt://{ip}:7687", auth=(username, password))
            graph.run("MATCH (n) RETURN count(n)")  # Verificar conexión
            
            # Buscar archivos JSON siguiendo la estructura exacta
            json_files = self._search_json_files('results/')
            
            if not json_files:
                return {'success': False, 'error': 'No se encontraron archivos scan_result.json para importar'}
            
            # Procesar archivos
            ips_processed = self._process_json_files(graph, json_files)
            
            return {
                'success': True,
                'ips_processed': ips_processed,
                'message': f'Importación exitosa. {ips_processed} IPs procesadas.'
            }
            
        except Exception as e:
            logger.error(f"Error importando a Neo4j: {e}")
            return {'success': False, 'error': str(e)}
    
    def _search_json_files(self, folder_path: str) -> Dict:
        """Buscar todos los archivos scan_result.json siguiendo la estructura exacta"""
        json_files = []
        if not os.path.exists(folder_path):
            return json_files
        
        # Buscar archivos scan_result.json en results/ORG/scans/LOCATION/scan_result.json
        for root, _, files in os.walk(folder_path):
            if 'scan_result.json' in files:
                json_path = os.path.join(root, 'scan_result.json')
                json_files.append(json_path)
        
        return json_files
    
    def _process_json_files(self, graph: Graph, json_files: list) -> int:
        """
        Procesar archivos JSON y crear nodos en Neo4j siguiendo la estructura exacta:
        ORG -> LOCATION (SEG) -> SUBNET -> IP -> PORT
        """
        from py2neo import Node, Relationship
        
        ips_processed = 0
        
        def create_or_merge_node(label, match_props, **properties):
            """Crear o actualizar un nodo"""
            # Convertir valores complejos a JSON string para Neo4j
            processed_props = {}
            for k, v in properties.items():
                if isinstance(v, (dict, list, set)):
                    processed_props[k] = json.dumps(v) if v else ""
                elif v is None:
                    processed_props[k] = ""
                else:
                    processed_props[k] = v
            
            node = graph.nodes.match(label, **match_props).first()
            if node:
                # Actualizar propiedades existentes
                for key, value in processed_props.items():
                    setattr(node, key, value)
                graph.push(node)
            else:
                # Crear nuevo nodo
                all_props = {**match_props, **processed_props}
                node = Node(label, **all_props)
                graph.create(node)
            return node
        
        def create_or_update_relationship(start_node, end_node, rel_type, **properties):
            """Crear o actualizar una relación"""
            if not start_node or not end_node:
                return None
            
            # Verificar si la relación ya existe
            existing_rel = graph.match((start_node, end_node), r_type=rel_type).first()
            if existing_rel:
                return existing_rel
            
            # Crear nueva relación
            rel = Relationship(start_node, rel_type, end_node, **properties)
            graph.create(rel)
            return rel
        
        for json_file in json_files:
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    try:
                        data = json.load(f)
                    except json.JSONDecodeError as e:
                        logger.error(f"Error al leer JSON {json_file}: {e}")
                        continue
                
                logger.info(f"Procesando archivo {json_file}...")
                
                # Estructura: ORG -> LOCATION (SEG) -> SUBNET -> IP -> PORT
                for org, org_data in data.items():
                    if not isinstance(org_data, dict):
                        continue
                    
                    # Crear nodo ORG
                    org_node = create_or_merge_node("ORG", {"org": org.upper()}, name=org.upper())
                    
                    for location, location_data in org_data.items():
                        if not isinstance(location_data, dict):
                            continue
                        
                        # Crear nodo SEG (LOCATION)
                        seg_node = create_or_merge_node(
                            "SEG", 
                            {"org": org.upper(), "SEG": location.upper()},
                            name=location.upper()
                        )
                        create_or_update_relationship(org_node, seg_node, "HAS_SEG")
                        
                        for subnet, subnet_data in location_data.items():
                            if not isinstance(subnet_data, dict):
                                continue
                            
                            # Crear nodo Subred
                            subnet_node = create_or_merge_node(
                                "Subred", 
                                {
                                    "org": org.upper(), 
                                    "SEG": location.upper(), 
                                    "Subred": subnet
                                },
                                name=subnet
                            )
                            create_or_update_relationship(seg_node, subnet_node, "HAS_SUBNET")
                            
                            for ip, ip_data in subnet_data.items():
                                if not isinstance(ip_data, dict):
                                    continue
                                
                                # Extraer hostname si existe en algún puerto
                                hostname = None
                                for port_key, port_data in ip_data.items():
                                    if isinstance(port_data, dict) and 'Hostname' in port_data:
                                        hostname = port_data.get('Hostname')
                                        break
                                
                                # Crear nodo IP con todas sus propiedades
                                ip_props = {
                                    "org": org.upper(),
                                    "SEG": location.upper(),
                                    "Subred": subnet,
                                    "IP": ip
                                }
                                if hostname:
                                    ip_props["hostname"] = hostname
                                
                                # Verificar si es dispositivo OT
                                is_ot_device = ip_data.get('_is_ot_device', False)
                                if is_ot_device:
                                    ip_props["is_ot_device"] = True
                                    ot_protocols = ip_data.get('_ot_protocols', [])
                                    if ot_protocols:
                                        ip_props["ot_protocols"] = json.dumps(ot_protocols) if isinstance(ot_protocols, list) else ot_protocols
                                
                                ip_node = create_or_merge_node("IP", {"IP": ip, "org": org.upper()}, **ip_props)
                                create_or_update_relationship(subnet_node, ip_node, "HAS_IP")
                                ips_processed += 1
                                
                                # Procesar puertos (clave es "PORT/PROTO")
                                for port_key, port_data in ip_data.items():
                                    # Ignorar propiedades especiales que empiezan con _
                                    if port_key.startswith('_'):
                                        continue
                                    
                                    if not isinstance(port_data, dict):
                                        continue
                                    
                                    # Crear nodo Port con TODAS las propiedades del JSON
                                    port_match_props = {
                                        "org": org.upper(),
                                        "SEG": location.upper(),
                                        "Subred": subnet,
                                        "IP": ip,
                                        "number": port_key
                                    }
                                    
                                    # Copiar todas las propiedades del puerto del JSON
                                    port_props = {**port_match_props}
                                    for prop_key, prop_value in port_data.items():
                                        if prop_value not in [None, "", "null"]:
                                            # Convertir valores complejos a string
                                            if isinstance(prop_value, (dict, list)):
                                                port_props[prop_key] = json.dumps(prop_value)
                                            elif isinstance(prop_value, bool):
                                                port_props[prop_key] = prop_value
                                            else:
                                                port_props[prop_key] = str(prop_value) if prop_value else ""
                                    
                                    port_node = create_or_merge_node("Port", port_match_props, **port_props)
                                    create_or_update_relationship(ip_node, port_node, "HAS_PORT")
            
            except Exception as e:
                logger.error(f"Error procesando archivo {json_file}: {e}")
                continue
        
        return ips_processed

