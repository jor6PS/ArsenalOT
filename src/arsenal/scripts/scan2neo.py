#!/usr/bin/env python3
"""
Importar resultados de escaneos desde scans.db a Neo4j
Combina múltiples escaneos de la misma organización/ubicación
conservando siempre la información más completa
"""

from py2neo import Graph, Node, Relationship
import argparse
import sqlite3
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from getpass import getpass


def connect_to_neo4j(ip: str, username: str = None, password: str = None) -> Graph:
    """Conectar a la base de datos Neo4j."""
    # Intentar usar variables de entorno primero
    username = username or os.getenv("NEO4J_USERNAME")
    password = password or os.getenv("NEO4J_PASSWORD")
    
    try:
        if username and password:
            graph = Graph(f"bolt://{ip}:7687", auth=(username, password))
        else:
            graph = Graph(f"bolt://{ip}:7687", auth=("neo4j", "neo4j1"))
        
        graph.run("MATCH (n) RETURN count(n)")  # Verificar la conexión
        return graph
    except Exception as e:
        if "Failed to authenticate" in str(e):
            # Si la autenticación falla, pedir credenciales al usuario
            if not username:
                username = input("Usuario Neo4j: ")
            if not password:
                password = getpass("Contraseña Neo4j: ")
            return Graph(f"bolt://{ip}:7687", auth=(username, password))
        raise e


def get_info_completeness(service_name: str, product: str, version: str, 
                         extrainfo: str, cpe: str) -> int:
    """Calcula un score de completitud de información (mayor = más completo)."""
    score = 0
    if service_name:
        score += 1
    if product:
        score += 2
    if version:
        score += 3
    if extrainfo:
        score += 1
    if cpe:
        score += 2
    return score


def merge_port_data(data1: Dict, data2: Dict) -> Dict:
    """Combina dos entradas de puerto conservando la información más completa."""
    # Calcular completitud
    score1 = get_info_completeness(
        data1.get('service_name', ''),
        data1.get('product', ''),
        data1.get('version', ''),
        data1.get('extrainfo', ''),
        data1.get('cpe', '')
    )
    score2 = get_info_completeness(
        data2.get('service_name', ''),
        data2.get('product', ''),
        data2.get('version', ''),
        data2.get('extrainfo', ''),
        data2.get('cpe', '')
    )
    
    # Usar el que tenga más información como base
    base = data1 if score1 >= score2 else data2
    other = data2 if score1 >= score2 else data1
    
    # Combinar campos, priorizando valores no vacíos
    merged = base.copy()
    for key in ['service_name', 'product', 'version', 'extrainfo', 'cpe', 'hostname']:
        if not merged.get(key) and other.get(key):
            merged[key] = other[key]
        elif merged.get(key) and other.get(key) and merged[key] != other[key]:
            # Si ambos tienen valor diferente, usar el más largo (más detallado)
            if len(str(other[key])) > len(str(merged[key])):
                merged[key] = other[key]
    
    # Combinar enriquecimientos
    if 'enrichments' not in merged:
        merged['enrichments'] = {}
    if 'enrichments' in other:
        merged['enrichments'].update(other['enrichments'])
    
    return merged


class RowDict:
    """Clase auxiliar para simular sqlite3.Row cuando agregamos hosts sin puertos."""
    def __init__(self, data):
        self._data = data
    def __getitem__(self, key):
        return self._data.get(key)
    def get(self, key, default=None):
        return self._data.get(key, default)


def get_combined_scans_data(db_path: str, org: str = None, location: str = None) -> Dict:
    """Obtiene y combina datos de múltiples escaneos desde la BD."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Construir query para obtener escaneos
    query = """
        SELECT id, organization_name, location, started_at, completed_at
        FROM scans
        WHERE status = 'completed'
    """
    params = []
    
    if org:
        query += " AND organization_name = ?"
        params.append(org.upper())
    
    if location:
        query += " AND location = ?"
        params.append(location.upper())
    
    query += " ORDER BY started_at DESC"
    
    scans = cursor.execute(query, params).fetchall()
    
    # Estructura de datos combinada: org -> location -> subnet -> ip -> port -> data
    combined_data = {}
    
    for scan in scans:
        scan_id = scan['id']
        org_name = scan['organization_name']
        loc_name = scan['location']
        
        # Obtener resultados de este escaneo (incluyendo hosts sin puertos abiertos)
        # Primero obtener hosts con puertos abiertos (solo IPs privadas)
        results = cursor.execute("""
            SELECT h.ip_address, h.hostname, h.subnet, sr.port, sr.protocol, sr.state,
                   sr.service_name, sr.product, sr.version, sr.extrainfo,
                   sr.cpe, sr.reason, sr.confidence
            FROM scan_results sr
            JOIN hosts h ON h.id = sr.host_id
            WHERE sr.scan_id = ?
            AND (h.is_private = 1 OR h.is_private IS NULL)
            ORDER BY h.ip_address, sr.port
        """, (scan_id,)).fetchall()
        
        # También obtener hosts que fueron escaneados pero no tienen puertos abiertos
        # Buscar hosts que están en la tabla hosts pero no tienen scan_results para este scan_id
        # Esto incluye hosts descubiertos por host discovery o Nmap que están "up" pero sin puertos abiertos
        scan_info = cursor.execute("""
            SELECT target_range, started_at, completed_at FROM scans WHERE id = ?
        """, (scan_id,)).fetchone()
        
        if scan_info:
            target_range = scan_info[0]
            scan_start = scan_info[1]
            scan_end = scan_info[2] or scan_start
            
            # Método 1: Buscar hosts en el target_range que no tienen resultados
            # Saltar este método si es un escaneo pasivo (target_range = "0.0.0.0/0")
            if target_range and target_range != "0.0.0.0/0":
                import ipaddress
                try:
                    # Intentar parsear como IP individual o red
                    if '/' in target_range:
                        network = ipaddress.ip_network(target_range, strict=False)
                        # Para redes grandes, limitar el número de IPs a verificar (máximo 256)
                        if network.num_addresses > 256:
                            # Solo verificar las primeras 256 IPs de la red
                            target_ips = [str(ip) for ip in list(network.hosts())[:256]]
                        else:
                            target_ips = [str(ip) for ip in network.hosts()]
                    else:
                        target_ips = [target_range]
                    
                    # Buscar hosts en este rango que no tienen resultados (solo IPs privadas)
                    for target_ip in target_ips:
                        host_check = cursor.execute("""
                            SELECT h.id, h.ip_address, h.hostname, h.subnet
                            FROM hosts h
                            WHERE h.ip_address = ?
                            AND (h.is_private = 1 OR h.is_private IS NULL)
                            AND NOT EXISTS (
                                SELECT 1 FROM scan_results sr 
                                WHERE sr.host_id = h.id AND sr.scan_id = ?
                            )
                        """, (target_ip, scan_id)).fetchone()
                        
                        if host_check:
                            # Crear un objeto tipo Row para mantener consistencia
                            host_row = RowDict({
                                'ip_address': host_check[1],
                                'hostname': host_check[2],
                                'subnet': host_check[3],
                                'port': None,
                                'protocol': None,
                                'state': 'up',
                                'service_name': None,
                                'product': None,
                                'version': None,
                                'extrainfo': None,
                                'cpe': None,
                                'reason': 'no open ports',
                                'confidence': None
                            })
                            results.append(host_row)
                except Exception as e:
                    # Si falla el parsing del rango, continuar con método alternativo
                    pass
            
            # Método 2: Buscar hosts descubiertos durante el período del escaneo
            
            # Método 2: Buscar hosts descubiertos durante el período del escaneo
            # que no tienen resultados para este scan_id
            # Esto captura hosts descubiertos por host discovery que luego fueron escaneados sin puertos
            try:
                hosts_discovered_during_scan = cursor.execute("""
                    SELECT DISTINCT h.id, h.ip_address, h.hostname, h.subnet
                    FROM hosts h
                    WHERE (h.first_seen <= ? AND h.last_seen >= ?)
                    AND (h.is_private = 1 OR h.is_private IS NULL)
                    AND NOT EXISTS (
                        SELECT 1 FROM scan_results sr 
                        WHERE sr.host_id = h.id AND sr.scan_id = ?
                    )
                    AND NOT EXISTS (
                        SELECT 1 FROM scan_results sr2
                        JOIN hosts h2 ON h2.id = sr2.host_id
                        WHERE h2.ip_address = h.ip_address AND sr2.scan_id = ?
                    )
                """, (scan_end, scan_start, scan_id, scan_id)).fetchall()
                
                for host_check in hosts_discovered_during_scan:
                    # Verificar que no esté ya en results
                    already_added = any(
                        r.get('ip_address') == host_check[1] and r.get('port') is None 
                        for r in results
                    )
                    if not already_added:
                        host_row = RowDict({
                            'ip_address': host_check[1],
                            'hostname': host_check[2],
                            'subnet': host_check[3],
                            'port': None,
                            'protocol': None,
                            'state': 'up',
                            'service_name': None,
                            'product': None,
                            'version': None,
                            'extrainfo': None,
                            'cpe': None,
                            'reason': 'no open ports',
                            'confidence': None
                        })
                        results.append(host_row)
            except Exception as e:
                pass  # Si falla, continuar sin estos hosts
        
        # Inicializar estructura si no existe
        if org_name not in combined_data:
            combined_data[org_name] = {}
        if loc_name not in combined_data[org_name]:
            combined_data[org_name][loc_name] = {}
        
        # Procesar cada resultado
        for row in results:
            ip = row['ip_address']
            hostname = row['hostname']
            # Usar subnet o inferirlo de la IP si es None
            subnet = row['subnet']
            if not subnet:
                # Intentar inferir subnet de la IP (primeros 3 octetos)
                try:
                    ip_parts = ip.split('.')
                    if len(ip_parts) == 4:
                        subnet = '.'.join(ip_parts[:3]) + '.0/24'
                    else:
                        subnet = "Unknown"
                except:
                    subnet = "Unknown"
            port = row['port']
            proto = row['protocol']
            
            # Inicializar estructura de subred
            if subnet not in combined_data[org_name][loc_name]:
                combined_data[org_name][loc_name][subnet] = {}
            if ip not in combined_data[org_name][loc_name][subnet]:
                combined_data[org_name][loc_name][subnet][ip] = {}
            
            # Si no hay puerto (host sin puertos abiertos)
            if port is None or port == 0:
                # Host sin puertos abiertos
                if 'no_ports' not in combined_data[org_name][loc_name][subnet][ip]:
                    combined_data[org_name][loc_name][subnet][ip]['no_ports'] = {
                        'hostname': hostname,
                        'state': row['state'] or 'up',
                        'service_name': '',
                        'product': '',
                        'version': '',
                        'extrainfo': '',
                        'cpe': '',
                        'reason': row['reason'] if row['reason'] is not None else 'no open ports',
                        'conf': 0,
                        'enrichments': {}
                    }
                continue
            
            port_key = f"{port}/{proto}"
            
            # Preparar datos del puerto
            port_data = {
                'hostname': hostname,
                'state': row['state'],
                'service_name': row['service_name'],
                'product': row['product'],
                'version': row['version'],
                'extrainfo': row['extrainfo'],
                'cpe': row['cpe'],
                'reason': row['reason'],
                'conf': row['confidence'] or 0,
                'enrichments': {}
            }
            
            # Obtener enriquecimientos
            enrichments = cursor.execute("""
                SELECT enrichment_type, data FROM enrichments
                WHERE scan_result_id = (
                    SELECT id FROM scan_results
                    WHERE scan_id = ? AND host_id = (
                        SELECT id FROM hosts WHERE ip_address = ?
                    ) AND port = ? AND protocol = ?
                )
            """, (scan_id, ip, port, proto)).fetchall()
            
            for enr_type, enr_data in enrichments:
                port_data['enrichments'][enr_type] = enr_data
            
            # Obtener vulnerabilidades
            vulnerabilities = cursor.execute("""
                SELECT vulnerability_id, vulnerability_name, severity, description,
                       cve_id, cvss_score, script_source, script_output
                FROM vulnerabilities
                WHERE scan_result_id = (
                    SELECT id FROM scan_results
                    WHERE scan_id = ? AND host_id = (
                        SELECT id FROM hosts WHERE ip_address = ?
                    ) AND port = ? AND protocol = ?
                )
            """, (scan_id, ip, port, proto)).fetchall()
            
            if vulnerabilities:
                port_data['vulnerabilities'] = []
                for vuln_row in vulnerabilities:
                    port_data['vulnerabilities'].append({
                        'vulnerability_id': vuln_row['vulnerability_id'],
                        'vulnerability_name': vuln_row['vulnerability_name'],
                        'severity': vuln_row['severity'],
                        'description': vuln_row['description'],
                        'cve_id': vuln_row['cve_id'],
                        'cvss_score': vuln_row['cvss_score'],
                        'script_source': vuln_row['script_source']
                    })
            
            # Combinar con datos existentes si ya existe este puerto
            if port_key in combined_data[org_name][loc_name][subnet][ip]:
                existing_data = combined_data[org_name][loc_name][subnet][ip][port_key]
                port_data = merge_port_data(existing_data, port_data)
            
            combined_data[org_name][loc_name][subnet][ip][port_key] = port_data
    
    conn.close()
    return combined_data


def create_or_merge_node(graph: Graph, label: str, match_props: Dict, **properties) -> Node:
    """Crear o actualizar un nodo en Neo4j."""
    # Limpiar propiedades None y convertir a strings si es necesario
    clean_props = {}
    for k, v in properties.items():
        if v is not None:
            if isinstance(v, (dict, list)):
                import json
                clean_props[k] = json.dumps(v)
            else:
                clean_props[k] = str(v)
    
    node = graph.nodes.match(label, **match_props).first()
    if node:
        node.update(clean_props)
        graph.push(node)
    else:
        clean_props.update(match_props)
        node = Node(label, **clean_props)
        graph.create(node)
    return node


def create_or_update_relationship(graph: Graph, start_node: Node, end_node: Node, 
                                 rel_type: str, **properties) -> Relationship:
    """Crear o actualizar una relación entre nodos."""
    if start_node and end_node:
        # Verificar si la relación ya existe
        existing_rel = graph.match((start_node, end_node), r_type=rel_type).first()
        if existing_rel:
            existing_rel.update(properties)
            graph.push(existing_rel)
            return existing_rel
        else:
            rel = Relationship(start_node, rel_type, end_node, **properties)
            graph.create(rel)
            return rel
    return None


def process_to_neo4j(graph: Graph, combined_data: Dict):
    """Procesa los datos combinados y los importa a Neo4j."""
    ip_ports_map = {}
    
    for org, org_data in combined_data.items():
        # Nodo de organización
        org_node = create_or_merge_node(graph, "ORG", {"org": org})
        
        for location, location_data in org_data.items():
            # Nodo de segmento/ubicación
            seg_node = create_or_merge_node(graph, "SEG", {
                "org": org,
                "SEG": location
            })
            create_or_update_relationship(graph, org_node, seg_node, "HAS_SEG")
            
            for subnet, subnet_data in location_data.items():
                # Nodo de subred
                subnet_node = create_or_merge_node(graph, "Subred", {
                    "org": org,
                    "SEG": location,
                    "Subred": subnet
                })
                create_or_update_relationship(graph, seg_node, subnet_node, "HAS_SUBNET")
                
                for ip, ip_data in subnet_data.items():
                    # Nodo de IP
                    ip_node = create_or_merge_node(graph, "IP", {
                        "org": org,
                        "SEG": location,
                        "Subred": subnet,
                        "IP": ip
                    })
                    create_or_update_relationship(graph, subnet_node, ip_node, "HAS_IP")
                    
                    ip_ports_map[ip] = {}
                    
                    for port_key, port_data in ip_data.items():
                        # Saltar entrada especial 'no_ports' - el host ya está registrado
                        if port_key == 'no_ports':
                            # Actualizar el nodo IP con información del host sin puertos
                            ip_node.update({
                                "Hostname": port_data.get('hostname', ''),
                                "State": port_data.get('state', ''),
                                "Note": "Host up but no open ports detected"
                            })
                            graph.push(ip_node)
                            continue
                        
                        # Nodo de puerto
                        port_node = create_or_merge_node(graph, "Port", {
                            "org": org,
                            "SEG": location,
                            "Subred": subnet,
                            "IP": ip,
                            "number": port_key
                        })
                        create_or_update_relationship(graph, ip_node, port_node, "HAS_PORT")
                        
                        # Actualizar propiedades del puerto con toda la información
                        port_props = {
                            "Hostname": port_data.get('hostname', ''),
                            "State": port_data.get('state', ''),
                            "Name": port_data.get('service_name', ''),
                            "Product": port_data.get('product', ''),
                            "Version": port_data.get('version', ''),
                            "Extrainfo": port_data.get('extrainfo', ''),
                            "Cpe": port_data.get('cpe', ''),
                            "Reason": port_data.get('reason', ''),
                            "Conf": port_data.get('conf', 0)
                        }
                        
                        # Agregar enriquecimientos
                        for enr_type, enr_data in port_data.get('enrichments', {}).items():
                            port_props[enr_type] = enr_data
                        
                        # Agregar vulnerabilidades
                        vulnerabilities = port_data.get('vulnerabilities', [])
                        if vulnerabilities:
                            vuln_list = []
                            for vuln in vulnerabilities:
                                vuln_str = f"{vuln.get('cve_id', vuln.get('vulnerability_id', 'Unknown'))}"
                                if vuln.get('severity'):
                                    vuln_str += f" ({vuln['severity']})"
                                vuln_list.append(vuln_str)
                            port_props['Vuln'] = ', '.join(vuln_list)
                            
                            # Agregar información detallada de vulnerabilidades
                            for idx, vuln in enumerate(vulnerabilities, 1):
                                if vuln.get('cve_id'):
                                    port_props[f'CVE_{idx}'] = vuln['cve_id']
                                if vuln.get('cvss_score'):
                                    port_props[f'CVSS_{idx}'] = vuln['cvss_score']
                        
                        port_node.update(port_props)
                        graph.push(port_node)
                        
                        ip_ports_map[ip][port_key] = port_props
    
    return ip_ports_map


def main():
    """Función principal para ejecutar el script."""
    parser = argparse.ArgumentParser(
        description='Importar resultados de escaneos desde scans.db a Neo4j'
    )
    parser.add_argument('-r', '--ip', type=str, required=True, 
                       help='IP de la base de datos Neo4j')
    parser.add_argument('-o', '--org', type=str, default=None,
                       help='Filtrar por organización específica (opcional)')
    parser.add_argument('-s', '--location', type=str, default=None,
                       help='Filtrar por ubicación específica (opcional)')
    parser.add_argument('-d', '--db', type=str, default='results/scans.db',
                       help='Ruta a la base de datos scans.db (default: results/scans.db)')
    args = parser.parse_args()
    
    # Verificar que existe la BD
    db_path = Path(args.db)
    if not db_path.exists():
        print(f"❌ Error: No se encuentra la base de datos en {db_path}")
        return
    
    print(f"📁 Leyendo datos de: {db_path}")
    
    # Conectar a Neo4j
    print(f"🔗 Conectando a Neo4j en {args.ip}...")
    try:
        graph = connect_to_neo4j(args.ip)
        print("✅ Conexión exitosa a Neo4j")
    except Exception as e:
        print(f"❌ Error conectando a Neo4j: {e}")
        return
    
    # Obtener y combinar datos
    print("\n📊 Combinando escaneos...")
    combined_data = get_combined_scans_data(
        str(db_path),
        org=args.org,
        location=args.location
    )
    
    if not combined_data:
        print("⚠️  No se encontraron escaneos completados para importar.")
        return
    
    # Mostrar resumen
    total_hosts = 0
    total_hosts_with_ports = 0
    total_hosts_without_ports = 0
    for org_data in combined_data.values():
        for loc_data in org_data.values():
            for subnet_data in loc_data.values():
                for ip_data in subnet_data.values():
                    total_hosts += 1
                    if 'no_ports' in ip_data:
                        total_hosts_without_ports += 1
                    elif ip_data:  # Tiene al menos un puerto
                        total_hosts_with_ports += 1
    
    # Verificar organizaciones sin escaneos completados
    conn_check = sqlite3.connect(str(db_path))
    cursor_check = conn_check.cursor()
    all_orgs = cursor_check.execute("SELECT DISTINCT name FROM organizations").fetchall()
    all_orgs_set = {row[0] for row in all_orgs}
    completed_orgs_set = set(combined_data.keys())
    missing_orgs = all_orgs_set - completed_orgs_set
    
    if missing_orgs:
        print(f"⚠️  Organizaciones sin escaneos completados (no se importarán): {', '.join(missing_orgs)}")
        # Verificar estado de estos escaneos
        for org in missing_orgs:
            statuses = cursor_check.execute("""
                SELECT status, COUNT(*) FROM scans 
                WHERE organization_name = ? GROUP BY status
            """, (org,)).fetchall()
            if statuses:
                status_str = ', '.join([f"{s[0]}: {s[1]}" for s in statuses])
                print(f"   - {org}: {status_str}")
    conn_check.close()
    
    print(f"\n✅ Datos combinados de {len(combined_data)} organización(es) con escaneos completados")
    print(f"   Total de hosts únicos: {total_hosts}")
    if total_hosts_without_ports > 0:
        print(f"   - Hosts con puertos abiertos: {total_hosts_with_ports}")
        print(f"   - Hosts sin puertos abiertos: {total_hosts_without_ports}")
    
    # Importar a Neo4j
    print("\n🚀 Importando a Neo4j...")
    try:
        ip_ports_map = process_to_neo4j(graph, combined_data)
        print(f"✅ Importación completada exitosamente")
        print(f"   Hosts procesados: {len(ip_ports_map)}")
    except Exception as e:
        print(f"❌ Error durante la importación: {e}")
        import traceback
        traceback.print_exc()
        return


if __name__ == "__main__":
    main()
