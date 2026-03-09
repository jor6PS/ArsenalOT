#!/usr/bin/env python3
"""
Importar resultados de escaneos desde scans.db a Neo4j (Versión oficial - Remodelado)
Implementa:
- Aislamiento por origen (DISCOVERY_SOURCE).
- Correlación inteligente (PROBABLY_SAME_HOST).
- Metadatos de escaneo explícitos (Escaneo_Activo_ID / Escaneo_Pasivo_ID).
- Limpieza de nombres de subred.
- Nodos de SERVICIO independientes.
"""

import argparse
import sqlite3
import os
import json
import ipaddress
import shutil
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set
from getpass import getpass
from py2neo import Graph, Node, Relationship

def is_ip_in_network(ip_str: str, network_str: str) -> bool:
    """Check if an IP address belongs to a network range."""
    try:
        if not ip_str or not network_str:
            return False
        ip = ipaddress.ip_address(ip_str)
        if '/' not in network_str:
            return str(ip) == network_str
        network = ipaddress.ip_network(network_str, strict=False)
        return ip in network
    except ValueError:
        return False

def connect_to_neo4j(ip: str, username: str = None, password: str = None) -> Graph:
    """Conectar a la base de datos Neo4j."""
    username = username or os.getenv("NEO4J_USERNAME") or "neo4j"
    password = password or os.getenv("NEO4J_PASSWORD") or "neo4j1"
    
    try:
        graph = Graph(f"bolt://{ip}:7687", auth=(username, password))
        graph.run("RETURN 1")
        return graph
    except Exception as e:
        if "Failed to authenticate" in str(e):
            if not username:
                username = input("Usuario Neo4j: ")
            if not password:
                password = getpass("Contraseña Neo4j: ")
            return Graph(f"bolt://{ip}:7687", auth=(username, password))
        raise e

def get_scans_data(db_path: str, org: str = None, location: str = None) -> List[Dict]:
    """Obtiene los datos de los escaneos de la base de datos."""
    # Copiar la base de datos a un directorio temporal para evitar problemas de permisos
    temp_dir = tempfile.mkdtemp()
    temp_db_path = os.path.join(temp_dir, "scans.db")
    shutil.copy2(db_path, temp_db_path)
    
    conn = sqlite3.connect(temp_db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # 1. Obtener redes y dispositivos críticos
    network_names_map = {}
    try:
        networks = cursor.execute("SELECT organization_name, network_name, network_range FROM networks").fetchall()
        for net in networks:
            o_n = net['organization_name'].upper()
            if o_n not in network_names_map: network_names_map[o_n] = {}
            network_names_map[o_n][net['network_range']] = net['network_name']
    except: pass
    
    critical_ips_map = {}
    try:
        crit_devs = cursor.execute("SELECT organization_name, ips FROM critical_devices").fetchall()
        for dev in crit_devs:
            o_n = dev['organization_name'].upper()
            if o_n not in critical_ips_map: critical_ips_map[o_n] = set()
            for ip_a in dev['ips'].split(','):
                if ip_a.strip(): critical_ips_map[o_n].add(ip_a.strip())
    except: pass

    # 2. Filtrar escaneos
    query_scans = "SELECT * FROM scans WHERE status = 'completed'"
    params = []
    if org:
        query_scans += " AND organization_name = ?"
        params.append(org.upper())
    if location:
        query_scans += " AND location = ?"
        params.append(location.upper())
    
    scans = cursor.execute(query_scans, params).fetchall()
    all_data = []

    for scan in scans:
        scan_id = scan['id']
        scan_dict = dict(scan)
        scan_dict['hosts'] = []
        scan_dict['passive_conversations'] = []
        
        o_name = scan['organization_name'].upper()
        
        # Obtener resultados activos
        query_results = """
            SELECT h.*, sr.*, sr.id as scan_result_id
            FROM scan_results sr
            JOIN hosts h ON h.id = sr.host_id
            WHERE sr.scan_id = ?
        """
        results = cursor.execute(query_results, (scan_id,)).fetchall()
        
        # Agrupar por host (Escaneos activos)
        active_hosts_map = {}
        for row in results:
            ip = row['ip_address']
            if ip not in active_hosts_map:
                subnet = None
                if o_name in network_names_map:
                    for net_range in network_names_map[o_name].keys():
                        if is_ip_in_network(ip, net_range):
                            subnet = net_range
                            break
                if not subnet:
                    subnet = row['subnet'] or "Unknown"
                
                subnet_name = network_names_map.get(o_name, {}).get(subnet) or subnet

                active_hosts_map[ip] = {
                    'ip': ip,
                    'hostname': row['hostname'] or '',
                    'organization': o_name,
                    'mi_ip': scan['myip'] or 'N/A',
                    'subred': subnet,
                    'nombre_subred': subnet_name,
                    'is_critical': ip in critical_ips_map.get(o_name, set()),
                    'vendor': row['vendor'],
                    'mac': row['mac_address'],
                    'os_info': row['os_info_json'],
                    'services': []
                }
            
            if row['port'] is not None:
                enrs = cursor.execute("SELECT enrichment_type, data FROM enrichments WHERE scan_result_id = ?", (row['scan_result_id'],)).fetchall()
                vulns = cursor.execute("SELECT * FROM vulnerabilities WHERE scan_result_id = ?", (row['scan_result_id'],)).fetchall()
                
                active_hosts_map[ip]['services'].append({
                    'port': row['port'],
                    'protocol': row['protocol'],
                    'name': row['service_name'],
                    'product': row['product'],
                    'version': row['version'],
                    'extrainfo': row['extrainfo'],
                    'scripts': row['scripts_json'],
                    'enrichments': [dict(e) for e in enrs],
                    'vulnerabilities': [dict(v) for v in vulns]
                })

        scan_dict['hosts'] = list(active_hosts_map.values())
        
        # Conversaciones pasivas
        conversations_rows = cursor.execute("SELECT * FROM passive_conversations WHERE scan_id = ?", (scan_id,)).fetchall()
        conversations = [dict(c) for c in conversations_rows]
        scan_dict['passive_conversations'] = conversations
        
        if scan['scan_mode'] == 'passive':
            passive_ips_info = {} 
            for conv in conversations:
                passive_ips_info[conv['src_ip']] = conv['src_mac']
                passive_ips_info[conv['dst_ip']] = conv['dst_mac']
            
            for ip, mac in passive_ips_info.items():
                h_info = cursor.execute("SELECT * FROM hosts WHERE ip_address = ?", (ip,)).fetchone()
                subnet = None
                if o_name in network_names_map:
                    for net_range in network_names_map[o_name].keys():
                        if is_ip_in_network(ip, net_range):
                            subnet = net_range
                            break
                if not subnet and h_info:
                    subnet = h_info['subnet']
                
                subnet_name = network_names_map.get(o_name, {}).get(subnet) or subnet or "Passive Detection"
                
                scan_dict['hosts'].append({
                    'ip': ip,
                    'hostname': h_info['hostname'] if h_info else '',
                    'organization': o_name,
                    'mi_ip': scan['myip'] or 'N/A',
                    'subred': subnet or 'N/A',
                    'nombre_subred': subnet_name,
                    'is_critical': ip in critical_ips_map.get(o_name, set()),
                    'vendor': h_info['vendor'] if h_info else '',
                    'mac': mac or (h_info['mac_address'] if h_info else ''),
                    'os_info': h_info['os_info_json'] if h_info else '',
                    'services': [] 
                })
        
        all_data.append(scan_dict)
        
    conn.close()
    try: shutil.rmtree(temp_dir)
    except: pass
    return all_data

def process_to_neo4j_v2(graph: Graph, all_scans: List[Dict]):
    """Procesa los datos e importa a Neo4j con correlación y metadatos mejorados."""
    
    # Track de hosts creados para correlación posterior (IP -> List[Node])
    ip_nodes_map = {}

    for scan in all_scans:
        org_name = scan['organization_name'].upper()
        scan_mode = scan['scan_mode'] or 'active'
        is_active = scan_mode != 'passive'
        
        # 1. Nodo ORGANIZACION
        org_node = Node("ORGANIZACION", name=org_name)
        graph.merge(org_node, "ORGANIZACION", "name")
        
        # 2. Nodo ESCANEO (Metadatos Explícitos solicitados)
        scan_label = "ESCANEO_ACTIVO" if is_active else "ESCANEO_PASIVO"
        scan_props = {
            'id': scan['id'],
            'type': scan['scan_type'],
            'target': scan['target_range'],
            'started_at': scan['started_at'],
            'completed_at': scan['completed_at']
        }
        # Metadatos explícitos: Escaneo_Activo_ID o Escaneo_Pasivo_ID
        if is_active:
            scan_props['Escaneo_Activo_ID'] = scan['id']
        else:
            scan_props['Escaneo_Pasivo_ID'] = scan['id']

        scan_node = Node(scan_label, **scan_props)
        graph.merge(scan_node, scan_label, "id")
        
        # Relación ORG -> ESCANEO
        rel_org_scan = Relationship(org_node, "SCAN_TYPE", scan_node)
        graph.merge(rel_org_scan)
        
        from_node = None
        discovery_source = ""
        if is_active:
            # 3. Nodo ORIGEN (FROM)
            myip = scan['myip'] or 'N/A'
            subnet_display_name = scan['location'].replace("Network ", "")
            from_node = Node("ORIGEN", 
                             ORGANIZACION=org_name,
                             MI_IP=myip,
                             SUBRED=scan['target_range'], 
                             NOMBRE_SUBRED=subnet_display_name)
            graph.merge(from_node, "ORIGEN", ("ORGANIZACION", "MI_IP", "SUBRED"))
            
            # Relación ESCANEO_ACTIVO -> ORIGEN
            rel_scan_from = Relationship(scan_node, "EXECUTED_FROM", from_node)
            graph.merge(rel_scan_from)
            discovery_source = f"Active:{myip}_{scan['id']}"
        else:
            discovery_source = f"Passive:{scan['id']}"

        # 4. Nodos HOST
        for h in scan['hosts']:
            clean_host_subnet_name = h['nombre_subred'].replace("Network ", "")
            
            host_props = {
                'IP': h['ip'],
                'HOSTNAME': h['hostname'],
                'ORGANIZACION': h['organization'],
                'MI_IP': h['mi_ip'],
                'SUBRED': h['subred'],
                'CRITICO_POR_IP': "SÍ" if h['is_critical'] else "NO",
                'NOMBRE_SUBRED': clean_host_subnet_name,
                'VENDOR': h['vendor'] or '',
                'MAC': h['mac'] or '',
                'OS': h['os_info'] or '',
                'DISCOVERY_SOURCE': discovery_source
            }
            
            host_node = Node("HOST", **host_props)
            graph.merge(host_node, "HOST", ("ORGANIZACION", "IP", "DISCOVERY_SOURCE"))
            
            # Guardar para correlación posterior
            if h['ip'] not in ip_nodes_map: ip_nodes_map[h['ip']] = []
            ip_nodes_map[h['ip']].append(host_node)

            if is_active and from_node:
                rel_from_host = Relationship(from_node, "DISCOVERED_HOST", host_node)
                graph.merge(rel_from_host)
            else:
                rel_scan_host = Relationship(scan_node, "DETECTED_HOST", host_node)
                graph.merge(rel_scan_host)

            # 5. Nodos de SERVICIO
            for s in h['services']:
                service_id = f"{h['ip']}_{s['port']}_{s['protocol']}_{discovery_source}"
                service_props = {
                    'id': service_id,
                    'port': s['port'],
                    'protocol': s['protocol'],
                    'name': s['name'] or 'unknown',
                    'product': s['product'] or '',
                    'version': s['version'] or '',
                    'vulnerabilities': ", ".join([v.get('cve_id') or v.get('vulnerability_id') for v in s['vulnerabilities']]) if s['vulnerabilities'] else ''
                }
                service_node = Node("SERVICE", **service_props)
                graph.merge(service_node, "SERVICE", "id")
                
                rel_host_service = Relationship(host_node, "HAS_SERVICE", service_node)
                graph.merge(rel_host_service)

        # 6. Relaciones entre HOSTS (Pasivo)
        if not is_active:
            for conv in scan['passive_conversations']:
                src_ip = conv['src_ip']
                dst_ip = conv['dst_ip']
                
                src_node = graph.nodes.match("HOST", ORGANIZACION=org_name, IP=src_ip, DISCOVERY_SOURCE=discovery_source).first()
                dst_node = graph.nodes.match("HOST", ORGANIZACION=org_name, IP=dst_ip, DISCOVERY_SOURCE=discovery_source).first()
                
                if src_node and dst_node:
                    rel_comm = Relationship(src_node, "COMMUNICATES_WITH", dst_node, 
                                            protocol=conv['protocol'],
                                            port=conv['dst_port'],
                                            last_seen=conv['last_seen'])
                    graph.merge(rel_comm)

    # 7. NUEVO: Correlación PROBABLY_SAME_HOST
    print("🧠 Correlacionando hosts con misma IP...")
    for ip, nodes in ip_nodes_map.items():
        if len(nodes) > 1:
            # Crear relaciones entre todos los nodos que comparten IP pero distinto source
            for i in range(len(nodes)):
                for j in range(i + 1, len(nodes)):
                    if nodes[i]['DISCOVERY_SOURCE'] != nodes[j]['DISCOVERY_SOURCE']:
                        rel_same = Relationship(nodes[i], "PROBABLY_SAME_HOST", nodes[j], ip=ip)
                        graph.merge(rel_same)

def main():
    parser = argparse.ArgumentParser(description='Importar resultados de escaneos a Neo4j (Consolidado - Remodelado)')
    parser.add_argument('-r', '--ip', type=str, required=True, help='IP de Neo4j')
    parser.add_argument('-o', '--org', type=str, default=None, help='Organización')
    parser.add_argument('-s', '--location', type=str, default=None, help='Ubicación')
    parser.add_argument('-d', '--db', type=str, default='results/scans.db', help='Ruta scans.db')
    args = parser.parse_args()
    
    db_path = Path(args.db)
    if not db_path.exists():
        print(f"❌ Error: {db_path} no existe")
        return
    
    try:
        graph = connect_to_neo4j(args.ip)
        print(f"✅ Conectado a Neo4j en {args.ip}")
    except Exception as e:
        print(f"❌ Error Neo4j: {e}")
        return
    
    print("📊 Obteniendo datos enriquecidos...")
    all_scans_data = get_scans_data(str(db_path), args.org, args.location)
    
    print(f"🚀 Procesando {len(all_scans_data)} escaneos con correlación inteligente...")
    process_to_neo4j_v2(graph, all_scans_data)
    print("✅ Exportación consolidada completada exitosamente")

if __name__ == "__main__":
    main()
