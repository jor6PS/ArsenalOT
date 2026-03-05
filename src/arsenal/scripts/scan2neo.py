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
import ipaddress
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from getpass import getpass


def is_internal_ip(ip_str: str) -> bool:
    """Returns True for all non-globally-routable IP addresses (loopback, private, link-local, etc.)"""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
            or ip_obj.is_multicast
        )
    except ValueError:
        return False


def is_ip_in_network(ip_str: str, network_str: str) -> bool:
    """Check if an IP address belongs to a network range."""
    try:
        if not ip_str or not network_str:
            return False
        ip = ipaddress.ip_address(ip_str)
        # Handle cases where network_str is just an IP
        if '/' not in network_str:
            return str(ip) == network_str
        network = ipaddress.ip_network(network_str, strict=False)
        return ip in network
    except ValueError:
        return False


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



def get_combined_scans_data(db_path: str, org: str = None, location: str = None) -> Tuple[Dict, Dict, Dict, Dict]:
    """
    Obtiene y combina los datos de los escaneos de forma precisa siguiendo el 'flujo'.
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # 1. Redes conocidas (mapeo de rangos a nombres)
    network_names_map = {}
    try:
        networks = cursor.execute("SELECT organization_name, network_name, network_range FROM networks").fetchall()
        for net in networks:
            o_n = net['organization_name'].upper()
            if o_n not in network_names_map: network_names_map[o_n] = {}
            network_names_map[o_n][net['network_range']] = net['network_name']
    except: pass
    
    # 2. IPs críticas
    critical_ips_map = {}
    try:
        crit_devs = cursor.execute("SELECT organization_name, ips FROM critical_devices").fetchall()
        for dev in crit_devs:
            o_n = dev['organization_name'].upper()
            if o_n not in critical_ips_map: critical_ips_map[o_n] = set()
            for ip_a in dev['ips'].split(','):
                if ip_a.strip(): critical_ips_map[o_n].add(ip_a.strip())
    except: pass

    # 3. Estructuras de retorno
    combined_data = {}
    location_myip_map = {}
    
    # Query principal: Obtener todos los resultados (incluyendo port=NULL) con su contexto de escaneo
    query = """
        SELECT 
            h.ip_address, h.hostname, h.subnet as host_subnet, h.interfaces_json,
            sr.id as scan_result_id, sr.port, sr.protocol, sr.state, sr.service_name, 
            sr.product, sr.version, sr.extrainfo, sr.cpe, sr.reason, sr.confidence, 
            sr.discovery_method as disc_method,
            s.organization_name, s.location, s.target_range as scan_target, s.id as scan_id, s.myip
        FROM scan_results sr
        JOIN hosts h ON h.id = sr.host_id
        JOIN scans s ON s.id = sr.scan_id
        WHERE s.status = 'completed'
    """
    params = []
    if org:
        query += " AND s.organization_name = ?"
        params.append(org.upper())
    if location:
        query += " AND s.location = ?"
        params.append(location.upper())
    
    query += " ORDER BY s.started_at ASC" # ASC para que el Origen se procese primero y luego se priorice
    
    results = cursor.execute(query, params).fetchall()
    
    for row in results:
        o_name = row['organization_name'].upper()
        l_name = row['location'].upper()
        ip = row['ip_address']
        disc_method = row['disc_method']
        
        # Guardar myip de la ubicación
        if row['myip']:
            if o_name not in location_myip_map: location_myip_map[o_name] = {}
            location_myip_map[o_name][l_name] = row['myip']
            
        # DETERMINAR SUBRED basada en el contexto del escaneo (Flujo)
        subnet = None
        if o_name in network_names_map:
            for net_range in network_names_map[o_name].keys():
                if is_ip_in_network(ip, net_range):
                    subnet = net_range
                    break
        if not subnet and row['scan_target'] and row['scan_target'] != "0.0.0.0/0":
            if is_ip_in_network(ip, row['scan_target']):
                subnet = row['scan_target']
        if not subnet:
            subnet = row['host_subnet'] or ('.'.join(ip.split('.')[:3]) + '.0/24' if '.' in ip else "Unknown")

        # Inicializar combined_data
        if o_name not in combined_data: combined_data[o_name] = {}
        if l_name not in combined_data[o_name]: combined_data[o_name][l_name] = {}
        if subnet not in combined_data[o_name][l_name]: combined_data[o_name][l_name][subnet] = {}
        
        if ip not in combined_data[o_name][l_name][subnet]:
            combined_data[o_name][l_name][subnet][ip] = {
                '_meta': {
                    'hostname': row['hostname'] or '',
                    'discovery_method': disc_method or 'unknown',
                    'interfaces': row['interfaces_json']
                }
            }
        else:
            meta = combined_data[o_name][l_name][subnet][ip]['_meta']
            if row['hostname'] and (not meta['hostname'] or len(row['hostname']) > len(meta['hostname'])):
                meta['hostname'] = row['hostname']
            
            # PRIORIDAD DE ORIGEN: Enrichment no sobrescribe métodos reales
            if disc_method and disc_method != 'unknown':
                if meta['discovery_method'] in ['unknown', 'enrichment'] or disc_method != 'enrichment':
                    meta['discovery_method'] = disc_method
            
            if row['interfaces_json'] and not meta['interfaces']:
                meta['interfaces'] = row['interfaces_json']

        # Procesar Puerto / Servicio
        port = row['port']
        if port is not None:
            proto = row['protocol']
            port_key = f"{port}/{proto}"
            port_data = {
                'port': port, 'protocol': proto, 'state': row['state'],
                'service_name': row['service_name'], 'product': row['product'],
                'version': row['version'], 'extrainfo': row['extrainfo'],
                'cpe': row['cpe'], 'reason': row['reason'],
                'conf': row['confidence'] or 0, 'enrichments': {}, 'vulnerabilities': []
            }

            # Enriquecimientos
            enrs = cursor.execute("SELECT enrichment_type, data FROM enrichments WHERE scan_result_id = ?", (row['scan_result_id'],)).fetchall()
            for e_type, e_data in enrs: port_data['enrichments'][e_type] = e_data
            
            # Vulnerabilidades
            vulns = cursor.execute("SELECT * FROM vulnerabilities WHERE scan_result_id = ?", (row['scan_result_id'],)).fetchall()
            for v in vulns: port_data['vulnerabilities'].append(dict(v))

            if port_key in combined_data[o_name][l_name][subnet][ip]:
                port_data = merge_port_data(combined_data[o_name][l_name][subnet][ip][port_key], port_data)
            
            combined_data[o_name][l_name][subnet][ip][port_key] = port_data
            
    conn.close()
    return combined_data, location_myip_map, network_names_map, critical_ips_map
    
    conn.close()
    return combined_data, location_myip_map, network_names_map, critical_ips_map


    return None


def process_to_neo4j(graph: Graph, combined_data: Dict, location_myip_map: Dict, 
                    network_names_map: Dict = None, critical_ips_map: Dict = None):
    """Procesa los datos combinados y los importa a Neo4j."""
    if network_names_map is None:
        network_names_map = {}
    if critical_ips_map is None:
        critical_ips_map = {}
    
    print("   Limpiando posibles nodos duplicados antiguos...")
    # Deduplicar nodos IP creados por el bug anterior (mismo IP/org/SEG pero diferente Subred)
    graph.run("""
        MATCH (i:IP)
        WITH i.org AS org, i.SEG AS seg, i.IP AS ip, collect(i) AS nodes
        WHERE size(nodes) > 1
        UNWIND tail(nodes) AS duplicate
        DETACH DELETE duplicate
    """)
    # Deduplicar nodos Port
    graph.run("""
        MATCH (p:Port)
        WITH p.org AS org, p.SEG AS seg, p.IP AS ip, p.number AS num, collect(p) AS nodes
        WHERE size(nodes) > 1
        UNWIND tail(nodes) AS duplicate
        DETACH DELETE duplicate
    """)
    
    ip_ports_map = {}
    
    org_list = []
    seg_list = []
    subnet_list = []
    ip_list = []
    port_list = []
    
    # Primera pasada: Aplanar diccionarios en listas para UNWIND
    for org, org_data in combined_data.items():
        org_list.append({"org": org})
        
        for location, location_data in org_data.items():
            myip = location_myip_map.get(org, {}).get(location)
            # Renombrar SEG para incluir myip como solicita el usuario
            seg_full_name = f"{location} ({myip})" if myip else location
            
            seg_list.append({
                "org": org,
                "SEG": seg_full_name,
                "myip": myip
            })
            
            for subnet, subnet_data in location_data.items():
                # Si no hay nombre asignado, usar el propio rango de la subred
                net_name = network_names_map.get(org, {}).get(subnet) or subnet
                subnet_list.append({
                    "org": org,
                    "SEG": seg_full_name,
                    "Subred": subnet,
                    "subnet_name": net_name,
                    "myip": myip if myip else "N/A"
                })
                
                for ip, ip_data in subnet_data.items():
                    meta = ip_data.pop('_meta', {'hostname': '', 'discovery_method': 'unknown', 'interfaces': None})
                    ip_list.append({
                        "org": org,
                        "SEG": seg_full_name,
                        "Subred": subnet,
                        "IP": ip,
                        "Hostname": meta['hostname'],
                        "Origen descubrimiento": meta['discovery_method'],
                        "Interfaces": meta['interfaces'],
                        "myip": myip if myip else "N/A",
                        "Critical": ip in critical_ips_map.get(org, set())
                    })
                    
                    ip_ports_map[ip] = {}
                    
                    for port_key, port_data in ip_data.items():
                        if port_key == 'no_ports':
                            # Continuamos, la información del host ya está en IP gracias al _meta
                            continue
                            
                        # Limpiar propiedades de puerto que puedan ser None, y dict a JSON
                        clean_props = {
                            "Hostname": str(port_data.get('hostname', '')) if port_data.get('hostname') else '',
                            "State": str(port_data.get('state', '')) if port_data.get('state') else '',
                            "Name": str(port_data.get('service_name', '')) if port_data.get('service_name') else '',
                            "Product": str(port_data.get('product', '')) if port_data.get('product') else '',
                            "Version": str(port_data.get('version', '')) if port_data.get('version') else '',
                            "Extrainfo": str(port_data.get('extrainfo', '')) if port_data.get('extrainfo') else '',
                            "Cpe": str(port_data.get('cpe', '')) if port_data.get('cpe') else '',
                            "Reason": str(port_data.get('reason', '')) if port_data.get('reason') else '',
                            "Conf": str(port_data.get('conf', 0)) if port_data.get('conf') is not None else '0'
                        }
                        
                        # Agregar enriquecimientos
                        for enr_type, enr_data in port_data.get('enrichments', {}).items():
                            clean_props[enr_type] = str(enr_data) if not isinstance(enr_data, (dict, list)) else json.dumps(enr_data)
                        
                        # Agregar vulnerabilidades
                        vulnerabilities = port_data.get('vulnerabilities', [])
                        if vulnerabilities:
                            vuln_list = []
                            for vuln in vulnerabilities:
                                vuln_str = f"{vuln.get('cve_id', vuln.get('vulnerability_id', 'Unknown'))}"
                                if vuln.get('severity'):
                                    vuln_str += f" ({vuln['severity']})"
                                vuln_list.append(vuln_str)
                            clean_props['Vuln'] = ', '.join(vuln_list)
                            
                            for idx, vuln in enumerate(vulnerabilities, 1):
                                if vuln.get('cve_id'):
                                    clean_props[f'CVE_{idx}'] = str(vuln['cve_id'])
                                if vuln.get('cvss_score'):
                                    clean_props[f'CVSS_{idx}'] = str(vuln['cvss_score'])
                        
                        ip_ports_map[ip][port_key] = clean_props
                        
                        port_list.append({
                            "org": org,
                            "SEG": seg_full_name,
                            "Subred": subnet,
                            "IP": ip,
                            "number": port_key,
                            "props": clean_props
                        })

    print(f"   Iniciando inserción masiva (ORGS: {len(org_list)}, SEG: {len(seg_list)}, SUB: {len(subnet_list)}, IP: {len(ip_list)}, PORT: {len(port_list)})")
    import json

    # 1. ORGs
    graph.run("""
        UNWIND $orgs AS o
        MERGE (org:ORG {org: o.org})
    """, orgs=org_list)
    
    # 2. Nodo Intermedio: Test de visibilidad
    graph.run("""
        UNWIND $orgs AS o
        MATCH (org:ORG {org: o.org})
        MERGE (test:Test_de_visibilidad {org: o.org, Nombre: 'Test de visibilidad'})
        MERGE (org)-[:GRAPHTYPE]->(test)
    """, orgs=org_list)
    
    # 3. SEGs y HAS_SEG (Ahora conectan a Test de visibilidad en vez de a ORG)
    # myip es ahora parte de la identidad cardinal de SEG
    seg_clean_list = []
    for s in seg_list:
        seg_clean_list.append({
            "org": s["org"], 
            "SEG": s["SEG"], 
            "myip": s["myip"] if s["myip"] else "N/A"
        })

    graph.run("""
        UNWIND $segs AS s
        MATCH (test:Test_de_visibilidad {org: s.org})
        MERGE (seg:SEG {org: s.org, SEG: s.SEG, myip: s.myip})
        MERGE (test)-[:SCAN_FROM]->(seg)
    """, segs=seg_clean_list)
    
    # 4. Subredes y SCAN_SUBNET
    # myip se asigna y empata con el SEG de origen
    graph.run("""
        UNWIND $subnets AS sub
        MATCH (seg:SEG {org: sub.org, SEG: sub.SEG, myip: sub.myip})
        MERGE (s:Subred {org: sub.org, SEG: sub.SEG, Subred: sub.Subred, myip: sub.myip})
        SET s.subnet_name = sub.subnet_name
        MERGE (seg)-[:SCAN_SUBNET]->(s)
    """, subnets=subnet_list)
    
    # 4. Limpiar relaciones IP huérfanas antes de asentar las nuevas (IP cambiando subred)
    graph.run("""
        UNWIND $ips AS i
        MATCH (oldS:Subred)-[r:SCAN_IP]->(ip_node:IP {org: i.org, SEG: i.SEG, IP: i.IP})
        WHERE oldS.Subred <> i.Subred
        DELETE r
    """, ips=ip_list)

    # 5. IPs y SCAN_IP
    ip_clean_list = []
    for i in ip_list:
        sub = i.pop("Subred") 
        myip = i.pop("myip")
        ip_clean_list.append({"match_props": {"org": i["org"], "SEG": i["SEG"], "IP": i["IP"]}, "subnet": sub, "myip": myip, "update_props": i})

    graph.run("""
        UNWIND $ips AS row
        MATCH (sub:Subred {org: row.match_props.org, SEG: row.match_props.SEG, Subred: row.subnet, myip: row.myip})
        MERGE (ip:IP {org: row.match_props.org, SEG: row.match_props.SEG, IP: row.match_props.IP})
        SET ip += row.update_props, ip.Subred = row.subnet
        MERGE (sub)-[:SCAN_IP]->(ip)
        WITH ip, row
        WHERE row.update_props.Critical = true
        SET ip:Critical
    """, ips=ip_clean_list)

    # 6. Ports y SCAN_PORT
    graph.run("""
        UNWIND $ports AS p
        MATCH (ip:IP {org: p.org, SEG: p.SEG, IP: p.IP})
        MERGE (port:Port {org: p.org, SEG: p.SEG, IP: p.IP, number: p.number})
        SET port += p.props, port.Subred = p.Subred
        MERGE (ip)-[:SCAN_PORT]->(port)
    """, ports=port_list)
    
    # Limpiar nodos de Subred huérfanos (que ya no tienen IPs porque cambiaron de segmento)
    print("   Limpiando subredes huérfanas...")
    graph.run("""
        MATCH (s:Subred)
        WHERE NOT (s)-[:SCAN_IP]->(:IP)
        DETACH DELETE s
    """)
    
    # 7. Correlación de IPs descubiertas desde múltiples orígenes (PROBABLY_SAME_HOST)
    print("   Generando vínculos de visibilidad cruzada entre orígenes...")
    graph.run("""
        MATCH (ip1:IP), (ip2:IP)
        WHERE ip1.org = ip2.org AND ip1.IP = ip2.IP 
          AND ip1.SEG < ip2.SEG
        MERGE (ip1)-[:PROBABLY_SAME_HOST]-(ip2)
    """)
    
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
    combined_data, location_myip_map, network_names_map, critical_ips_map = get_combined_scans_data(
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
    
    import json
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
        ip_ports_map = process_to_neo4j(graph, combined_data, location_myip_map, network_names_map, critical_ips_map)
        print(f"✅ Importación completada exitosamente")
        print(f"   Hosts procesados: {len(ip_ports_map)}")
    except Exception as e:
        print(f"❌ Error durante la importación: {e}")
        import traceback
        traceback.print_exc()
        return


if __name__ == "__main__":
    main()
