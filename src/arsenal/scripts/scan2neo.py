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
    # Copiar la base de datos y sus archivos temporales a un directorio temporal
    temp_dir = tempfile.mkdtemp()
    temp_db_path = os.path.join(temp_dir, "scans.db")
    
    # Copiar main DB
    shutil.copy2(db_path, temp_db_path)
    
    # Copiar WAL y SHM si existen para asegurar que leemos los datos más recientes
    wal_path = f"{db_path}-wal"
    shm_path = f"{db_path}-shm"
    if os.path.exists(wal_path):
        shutil.copy2(wal_path, f"{temp_db_path}-wal")
    if os.path.exists(shm_path):
        shutil.copy2(shm_path, f"{temp_db_path}-shm")
    
    conn = sqlite3.connect(temp_db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # 1. Obtener redes y dispositivos críticos
    network_names_map = {}
    try:
        networks = cursor.execute("SELECT organization_name, network_name, network_range, system_name FROM networks").fetchall()
        for net in networks:
            o_n = net['organization_name'].upper()
            if o_n not in network_names_map: network_names_map[o_n] = {}
            network_names_map[o_n][net['network_range']] = {
                'name': net['network_name'],
                'system': net['system_name']
            }
    except: pass
    
    critical_ips_map = {}
    try:
        crit_devs = cursor.execute("SELECT organization_name, name, reason, ips FROM critical_devices").fetchall()
        for dev in crit_devs:
            o_n = dev['organization_name'].upper()
            if o_n not in critical_ips_map: critical_ips_map[o_n] = {}
            for ip_a in dev['ips'].split(','):
                ip_clean = ip_a.strip()
                if ip_clean:
                    critical_ips_map[o_n][ip_clean] = {
                        'name': dev['name'],
                        'reason': dev['reason']
                    }
    except: pass

    # 2. Filtrar escaneos (incluir pasivos aunque no estén 'completed' para mayor visibilidad)
    query_scans = "SELECT * FROM scans WHERE (status = 'completed' OR (scan_mode = 'passive' AND status != 'failed'))"
    params = []
    if org:
        query_scans += " AND UPPER(organization_name) = UPPER(?)"
        params.append(org)
    if location:
        query_scans += " AND UPPER(location) = UPPER(?)"
        params.append(location)
    
    scans = cursor.execute(query_scans, params).fetchall()
    all_data = []

    for scan in scans:
        scan_id = scan['id']
        scan_dict = dict(scan)
        scan_dict['hosts'] = []
        scan_dict['passive_conversations'] = []
        
        o_name = scan['organization_name'].upper()
        
        query_results = """
            SELECT h.ip_address, h.subnet, h.first_seen, sr.*, sr.id as scan_result_id,
                   m.hostname as isolation_hostname,
                   m.hostnames_json as isolation_hostnames,
                   m.mac_address as isolation_mac,
                   m.vendor as isolation_vendor,
                   m.os_info_json as isolation_os,
                   m.host_scripts_json as isolation_scripts,
                   m.interfaces_json as isolation_interfaces,
                   h.interfaces_json as global_interfaces,
                   m.last_seen as isolation_last_seen
            FROM scan_results sr
            JOIN hosts h ON h.id = sr.host_id
            LEFT JOIN host_scan_metadata m ON m.scan_id = sr.scan_id AND m.host_id = sr.host_id
            WHERE sr.scan_id = ?
        """
        results = cursor.execute(query_results, (scan_id,)).fetchall()
        
        # Agrupar por host (Escaneos activos)
        active_hosts_map = {}
        for row in results:
            ip = row['ip_address']
            if ip not in active_hosts_map:
                subnet = None
                # 1. Intentar match por rango exacto si está en la DB
                if o_name in network_names_map:
                    # Match por network_range (más rápido)
                    for net_range in network_names_map[o_name].keys():
                        if is_ip_in_network(ip, net_range):
                            subnet = net_range
                            break
                
                # 1.5. Intentar match con el target_range del propio escaneo
                if not subnet and scan['target_range'] and scan['target_range'] != "0.0.0.0/0":
                    if is_ip_in_network(ip, scan['target_range']):
                        subnet = scan['target_range']
                
                # 2. Si no hay match en redes conocidas, usar el registrado o Unknown
                if not subnet:
                    subnet = row['subnet'] or "Unknown"
                
                net_info = network_names_map.get(o_name, {}).get(subnet, {})
                subnet_name = net_info.get('name') or "Unknown" if subnet != "Unknown" else "Unknown"
                system_name = net_info.get('system') or "Internal"

                is_crit = ip in critical_ips_map.get(o_name, {})
                crit_info = critical_ips_map.get(o_name, {}).get(ip, {})

                # AISLAMIENTO ESTRICTO: Solo lo que diga el escaneo (metadata)
                active_hosts_map[ip] = {
                    'ip': ip,
                    'hostname': row['isolation_hostname'] or '',
                    'organization': o_name,
                    'mi_ip': scan['myip'] or 'N/A',
                    'vendor': row['isolation_vendor'] or '',
                    'mac': row['isolation_mac'] or '',
                    'os_info': row['isolation_os'] or '',
                    'hostnames': ", ".join([s.strip('\x00') for s in json.loads(row['isolation_hostnames'])]) if row['isolation_hostnames'] else '',
                    'interfaces': ", ".join([s.strip('\x00') for s in json.loads(row['isolation_interfaces'] or row['global_interfaces'])]) if (row['isolation_interfaces'] or row['global_interfaces']) else '',
                    'scripts': row['isolation_scripts'] or '',
                    'timestamp': row['isolation_last_seen'] or row['discovered_at'],
                    'network_range': subnet if subnet and subnet != "Unknown" else None,
                    'network_name': subnet_name,
                    'network_system': system_name,
                    'is_critical': is_crit,
                    'critical_name': crit_info.get('name'),
                    'critical_reason': crit_info.get('reason'),
                    'services': []
                }
            
            if row['port'] is not None:
                enrs = cursor.execute("SELECT enrichment_type, data FROM enrichments WHERE scan_result_id = ?", (row['scan_result_id'],)).fetchall()
                vulns = cursor.execute("SELECT * FROM vulnerabilities WHERE scan_result_id = ?", (row['scan_result_id'],)).fetchall()
                
                service_dict = {
                    'port': row['port'],
                    'protocol': row['protocol'],
                    'name': row['service_name'],
                    'product': row['product'],
                    'version': row['version'],
                    'extrainfo': row['extrainfo'],
                    'scripts': row['scripts_json'],
                    'vulnerabilities': [dict(v) for v in vulns]
                }
                
                # Procesar enriquecimientos como propiedades del servicio
                for e in enrs:
                    etype = e['enrichment_type']
                    if etype == 'Screenshot':
                        service_dict['SCREENSHOT'] = e['data']
                    elif etype == 'Websource':
                        service_dict['WEBSOURCE'] = e['data']
                    elif etype == 'IOXIDResolver':
                        service_dict['IOXID'] = e['data']
                    else:
                        service_dict[f'ENRICHMENT_{etype.upper()}'] = e['data']
                
                active_hosts_map[ip]['services'].append(service_dict)

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
            
            # Obtener todos los hosts en una sola consulta
            unique_ips = list(passive_ips_info.keys())
            h_info_map = {}
            if unique_ips:
                # SQLite tiene un límite de variables, pero para IPs únicas suele estar bien
                # No obstante, por seguridad dividimos en fragmentos de 500
                for i in range(0, len(unique_ips), 500):
                    batch_ips = unique_ips[i:i+500]
                    placeholders = ','.join(['?'] * len(batch_ips))
                    # JOIN con host_scan_metadata para aislamiento
                    query_h = f"""
                        SELECT h.ip_address, h.subnet, h.first_seen, 
                               m.hostname as isolation_hostname,
                               m.hostnames_json as isolation_hostnames,
                               m.mac_address as isolation_mac,
                               m.interfaces_json as isolation_interfaces,
                               h.interfaces_json as global_interfaces,
                               m.last_seen as isolation_last_seen
                        FROM hosts h
                        LEFT JOIN host_scan_metadata m ON m.host_id = h.id AND m.scan_id = ?
                        WHERE h.ip_address IN ({placeholders})
                    """
                    rows = cursor.execute(query_h, [scan_id] + batch_ips).fetchall()
                    for row in rows:
                        h_info_map[row['ip_address']] = dict(row)

            for ip, mac in passive_ips_info.items():
                h_info = h_info_map.get(ip)
                subnet = None
                if o_name in network_names_map:
                    for net_range in network_names_map[o_name].keys():
                        if is_ip_in_network(ip, net_range):
                            subnet = net_range
                            break
                if not subnet and h_info:
                    subnet = h_info.get('subnet')
                
                # AISLAMIENTO ESTRICTO: No heredamos nada de la tabla global hosts
                # Solo usamos lo que diga el escaneo actual (captura o metadata)
                net_info = network_names_map.get(o_name, {}).get(subnet or "Unknown", {})
                subnet_name = net_info.get('name') or "Unknown"
                system_name = net_info.get('system') or "Internal"
                
                is_crit = ip in critical_ips_map.get(o_name, {})
                crit_info = critical_ips_map.get(o_name, {}).get(ip, {})
                
                scan_dict['hosts'].append({
                    'ip': ip,
                    'hostname': h_info.get('isolation_hostname') or '',
                    'organization': o_name,
                    'mi_ip': scan['myip'] or 'N/A',
                    'vendor': '', # Aislado para pasivo por ahora, a menos que metadata diga lo contrario
                    'mac': mac or h_info.get('isolation_mac') or '', # Captura pcap > metadata scan
                    'os_info': '', # Aislado
                    'hostnames': ", ".join([s.strip('\x00') for s in json.loads(h_info.get('isolation_hostnames'))]) if h_info and h_info.get('isolation_hostnames') else '',
                    'interfaces': ", ".join([s.strip('\x00') for s in json.loads(h_info.get('isolation_interfaces') or h_info.get('global_interfaces'))]) if h_info and (h_info.get('isolation_interfaces') or h_info.get('global_interfaces')) else '',
                    'timestamp': h_info.get('isolation_last_seen') if h_info else None,
                    'network_range': subnet if subnet and subnet != "Unknown" else None,
                    'network_name': subnet_name,
                    'network_system': system_name,
                    'is_critical': is_crit,
                    'critical_name': crit_info.get('name'),
                    'critical_reason': crit_info.get('reason'),
                    'services': [] 
                })
        
        all_data.append(scan_dict)
        
    conn.close()
    try: shutil.rmtree(temp_dir)
    except: pass
    return all_data

def process_to_neo4j_v2(graph: Graph, all_scans: List[Dict]):
    """Procesa los datos e importa a Neo4j con correlación y metadatos mejorados (OPTIMIZADO)."""
    
    # Track de hosts creados para correlación posterior (IP -> List[Node])
    ip_nodes_map = {}

    print("📊 Asegurando índices de rendimiento en Neo4j...")
    try:
        graph.run("CREATE INDEX host_org_ip_ds IF NOT EXISTS FOR (h:HOST) ON (h.ORGANIZACION, h.IP, h.DISCOVERY_SOURCE)")
    except Exception as e:
        print(f"⚠️ No se pudo crear el índice compuesto de HOST: {e}")

    for scan in all_scans:
        org_name = scan['organization_name'].upper()
        scan_mode = scan['scan_mode'] or 'active'
        is_active = scan_mode != 'passive'
        
        # 1. Nodo ORGANIZACION (Merge simple, es uno por scan o pocos)
        org_node = Node("ORGANIZACION", name=org_name)
        graph.merge(org_node, "ORGANIZACION", "name")
        
        # 2. Nodo ORIGEN (Fusionado con ESCANEO)
        myip = scan['myip'] or 'N/A'
        origin_props = {
            'NAME': "ESCANEO PASIVO" if not is_active else f"Escaneo {scan['id']}",
            'ORGANIZACION': org_name,
            'MI_IP': myip,
            'SCAN_ID': scan['id'],
            'SCAN_TYPE': scan['scan_type'],
            'SCAN_MODE': scan['scan_mode'],
            'TARGET_RANGE': scan['target_range'],
            'PCAP_FILE': scan.get('pcap_file') or ('N/A' if is_active else scan['target_range']),
            'INTERFACE': scan['interface'],
            'COMMAND': scan.get('nmap_command') or 'N/A',
            'STARTED_AT': scan['started_at'],
            'COMPLETED_AT': scan['completed_at'],
            'STATUS': scan['status'],
            'LOCATION': scan['location']
        }
        
        origin_node = Node("ORIGEN", **origin_props)
        graph.merge(origin_node, "ORIGEN", ("ORGANIZACION", "SCAN_ID"))
        
        # Relación ORG -> ORIGEN
        rel_org_origin = Relationship(org_node, "HAS_SOURCE", origin_node)
        graph.merge(rel_org_origin)
        
        discovery_source = f"{scan['scan_mode']}:{scan['id']}"

        # 4. PREPARAR DATOS PARA BULK INSERT (UNWIND)
        hosts_data = []
        services_data = []
        
        for h in scan['hosts']:
            h_props = {
                'IP': h['ip'], 'HOSTNAME': h['hostname'], 'ORGANIZACION': h['organization'],
                'CRITICO': "SÍ" if h['is_critical'] else "NO", 'RAZON_CRITICO': h.get('critical_reason', ''), 'NOMBRE_CRITICO': h.get('critical_name', ''),
                'SUBRED': h.get('network_range') or 'Unknown',
                'NOMBRE_SUBRED': h.get('network_name') or 'Unknown', 'SISTEMA': h.get('network_system') or 'N/A',
                'VENDOR': h['vendor'] or '', 'MAC': h['mac'] or '', 'OS': h['os_info'] or '',
                'HOSTNAMES': h.get('hostnames') or '', 'INTERFACES': h.get('interfaces') or '',
                'TIMESTAMP': h.get('timestamp') or '',
                'DISCOVERY_SOURCE': discovery_source
            }
            hosts_data.append(h_props)
            
            # Recolectar Servicios
            for s in h['services']:
                s_props = {
                    'host_ip': h['ip'],
                    'id': f"{h['ip']}_{s['port']}_{s['protocol']}_{discovery_source}",
                    'port': s['port'], 'protocol': s['protocol'], 'name': s['name'] or 'unknown',
                    'product': s['product'] or '', 'version': s['version'] or '',
                    'vulnerabilities': ", ".join([v.get('cve_id') or v.get('vulnerability_id') for v in s['vulnerabilities']]) if s['vulnerabilities'] else ''
                }
                
                # Añadir enriquecimientos (ahora son propiedades en s)
                for k, v in s.items():
                    if k not in ['port', 'protocol', 'name', 'product', 'version', 'extrainfo', 'scripts', 'vulnerabilities']:
                        s_props[k] = v
                
                services_data.append(s_props)

        # --- EJECUTAR BULK HOSTS ---
        print(f"📦 [Scan {scan['id']}] Exportando {len(hosts_data)} hosts...")
        # Usar UNWIND para MERGE de hosts y relaciones con ORIGEN
        graph.run("""
            UNWIND $data AS row
            MERGE (h:HOST {ORGANIZACION: row.ORGANIZACION, IP: row.IP, DISCOVERY_SOURCE: row.DISCOVERY_SOURCE})
            SET h += row
            WITH h, row
            MATCH (o:ORIGEN {ORGANIZACION: row.ORGANIZACION, SCAN_ID: $scan_id})
            MERGE (o)-[:DISCOVERED_HOST]->(h)
        """, data=hosts_data, scan_id=scan['id'])

        # --- EJECUTAR BULK SERVICES ---
        if services_data:
            print(f"📦 [Scan {scan['id']}] Exportando {len(services_data)} servicios...")
            graph.run("""
                UNWIND $data AS row
                MERGE (s:SERVICE {id: row.id})
                SET s += row
                WITH s, row
                MATCH (h:HOST {ORGANIZACION: $org, IP: row.host_ip, DISCOVERY_SOURCE: $ds})
                MERGE (h)-[:HAS_SERVICE]->(s)
            """, data=services_data, org=org_name, ds=discovery_source)


        # --- EJECUTAR BULK CONVERSACIONES (PASIVO) ---
        if not is_active and scan['passive_conversations']:
            print(f"📦 [Scan {scan['id']}] Exportando {len(scan['passive_conversations'])} conversaciones...")
            
            # Normalizar para evitar nulls en las propiedades del MERGE (causa SemanticError)
            normalized_convs = []
            for c in scan['passive_conversations']:
                normalized_convs.append({
                    'src_ip': c['src_ip'],
                    'dst_ip': c['dst_ip'],
                    'dst_port': c['dst_port'] if c['dst_port'] is not None else 0,
                    'protocol': c['protocol'] if c['protocol'] is not None else 'N/A',
                    'last_seen': c['last_seen']
                })

            # Fragmentar para evitar queries gigantescas
            batch_size = 1000
            for i in range(0, len(normalized_convs), batch_size):
                batch = normalized_convs[i:i+batch_size]
                graph.run("""
                    UNWIND $data AS conv
                    MATCH (src:HOST {ORGANIZACION: $org, IP: conv.src_ip, DISCOVERY_SOURCE: $ds})
                    MATCH (dst:HOST {ORGANIZACION: $org, IP: conv.dst_ip, DISCOVERY_SOURCE: $ds})
                    MERGE (src)-[r:COMMUNICATES_WITH {discovery_id: $scan_id, port: conv.dst_port, protocol: conv.protocol}]->(dst)
                    SET r.last_seen = conv.last_seen
                """, data=batch, org=org_name, ds=discovery_source, scan_id=scan['id'])

        # Rellenar ip_nodes_map para el paso 7 (esto requiere otra query o matcheo)
        # Como es para correlación, podemos hacerlo más eficiente después.
        for h in scan['hosts']:
            if h['ip'] not in ip_nodes_map: ip_nodes_map[h['ip']] = []
            # Guardamos solo el source para correlacionar después
            ip_nodes_map[h['ip']].append(discovery_source)

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
