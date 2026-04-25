#!/usr/bin/env python3
"""
Importar resultados de escaneos desde scans.db a Neo4j (Versión oficial - Remodelado)
Implementa:
- Aislamiento por origen (DISCOVERY_SOURCE).
- Correlación inteligente (PROBABLY_SAME_HOST).
- Metadatos de escaneo explícitos por origen.
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

def _json_items_as_text(value) -> str:
    """Convert legacy/list/dict JSON metadata to a readable comma-separated string."""
    if not value:
        return ""
    try:
        data = json.loads(value) if isinstance(value, str) else value
    except Exception:
        return str(value).strip("\x00")

    if isinstance(data, dict):
        items = []
        for key, item in data.items():
            if isinstance(item, dict):
                label = item.get("name") or item.get("hostname") or item.get("ip") or item.get("address") or key
            else:
                label = item
            if label:
                items.append(str(label).strip("\x00"))
        return ", ".join(items)
    if isinstance(data, list):
        items = []
        for item in data:
            if isinstance(item, dict):
                label = item.get("name") or item.get("hostname") or item.get("ip") or item.get("address") or json.dumps(item, ensure_ascii=False)
            else:
                label = item
            if label:
                items.append(str(label).strip("\x00"))
        return ", ".join(items)
    return str(data).strip("\x00")

def connect_to_neo4j(ip: str, username: str = None, password: str = None) -> Graph:
    """Conectar a la base de datos Neo4j."""
    username = username or os.getenv("NEO4J_USERNAME") or "neo4j"
    password = password or os.getenv("NEO4J_PASSWORD") or "change-this-neo4j-password"
    
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

def get_scans_data(db_path: str, org: str = None, location: str = None,
                   scan_id: int = None) -> List[Dict]:
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

    # 2. Filtrar escaneos vigentes.
    query_scans = "SELECT * FROM scans WHERE COALESCE(scan_mode, 'active') != 'passive' AND (status = 'completed' OR (scan_mode = 'netexec' AND status != 'failed'))"
    params = []
    if org:
        query_scans += " AND UPPER(organization_name) = UPPER(?)"
        params.append(org)
    if location:
        query_scans += " AND UPPER(location) = UPPER(?)"
        params.append(location)
    if scan_id:
        query_scans += " AND id = ?"
        params.append(scan_id)

    scans = cursor.execute(query_scans, params).fetchall()
    all_data = []

    for scan in scans:
        scan_id = scan['id']
        scan_dict = dict(scan)
        scan_dict['hosts'] = []
        
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
                    'hostnames': _json_items_as_text(row['isolation_hostnames']),
                    'interfaces': _json_items_as_text(row['isolation_interfaces'] or row['global_interfaces']),
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
                    'extrainfo': row['extrainfo'] or '',
                    'cpe': row['cpe'] or '',
                    'reason': row['reason'] or '',
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
        
        all_data.append(scan_dict)
        
    conn.close()
    try: shutil.rmtree(temp_dir)
    except: pass
    return all_data

def _duration_seconds(started_at, completed_at) -> int:
    """Retorna la duración en segundos entre dos timestamps ISO, o 0 si no aplica."""
    if not started_at or not completed_at:
        return 0
    try:
        from datetime import datetime
        for fmt in ('%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S'):
            try:
                s = datetime.strptime(str(started_at)[:26], fmt)
                e = datetime.strptime(str(completed_at)[:26], fmt)
                return max(0, int((e - s).total_seconds()))
            except ValueError:
                continue
    except Exception:
        pass
    return 0


def compute_org_stats(all_scans: List[Dict]) -> Dict[str, Dict]:
    """
    Calcula estadísticas agregadas por organización a partir de los escaneos ya cargados.
    Devuelve Dict[org_name → props dict listo para Neo4j].
    """
    raw: Dict[str, Dict] = {}

    for scan in all_scans:
        org = scan['organization_name'].upper()
        if org not in raw:
            raw[org] = {
                'ips': set(),
                'services': 0,
                'vulns': 0,
                'screenshots': 0,
                'source_code': 0,
                'subnets': set(),
                'locations': set(),
                'num_scans': 0,
                'first_scan': None,
                'last_scan': None,
                'critical_ips': set(),
            }
        r = raw[org]
        r['num_scans'] += 1

        started = scan.get('started_at') or ''
        completed = scan.get('completed_at') or started
        if started:
            if not r['first_scan'] or started < r['first_scan']:
                r['first_scan'] = started
            if not r['last_scan'] or completed > r['last_scan']:
                r['last_scan'] = completed

        if scan.get('location'):
            r['locations'].add(scan['location'])

        for h in scan['hosts']:
            r['ips'].add(h['ip'])
            if h.get('network_range'):
                r['subnets'].add(h['network_range'])
            if h.get('is_critical'):
                r['critical_ips'].add(h['ip'])
            for svc in h.get('services', []):
                r['services'] += 1
                r['vulns'] += len(svc.get('vulnerabilities') or [])
                if svc.get('SCREENSHOT'):
                    r['screenshots'] += 1
                if svc.get('WEBSOURCE'):
                    r['source_code'] += 1

    result: Dict[str, Dict] = {}
    for org, r in raw.items():
        result[org] = {
            'TOTAL_HOSTS':              len(r['ips']),
            'TOTAL_SERVICIOS':          r['services'],
            'TOTAL_VULNERABILIDADES':   r['vulns'],
            'TOTAL_SCREENSHOTS':        r['screenshots'],
            'TOTAL_CODIGO_FUENTE':      r['source_code'],
            'TOTAL_SUBREDES':           len(r['subnets']),
            'TOTAL_UBICACIONES':        len(r['locations']),
            'NUM_ESCANEOS':             r['num_scans'],
            'PRIMER_ESCANEO':           str(r['first_scan'] or ''),
            'ULTIMO_ESCANEO':           str(r['last_scan'] or ''),
            'NUM_DISPOSITIVOS_CRITICOS': len(r['critical_ips']),
        }
    return result


def process_to_neo4j_v2(graph: Graph, all_scans: List[Dict]):
    """Procesa los datos e importa a Neo4j con correlación y metadatos mejorados (OPTIMIZADO)."""

    # Pre-computar estadísticas por organización a partir de todos los escaneos cargados
    org_stats = compute_org_stats(all_scans)

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
        is_netexec = scan_mode == 'netexec'

        # 1. Nodo ORGANIZACION — incluye estadísticas agregadas de toda la org
        org_props = {'name': org_name, **org_stats.get(org_name, {})}
        org_node = Node("ORGANIZACION", **org_props)
        graph.merge(org_node, "ORGANIZACION", "name")

        # 2. Nodo ORIGEN — metadatos del escaneo + contadores y duración
        myip = scan['myip'] or 'N/A'
        duration = _duration_seconds(scan.get('started_at'), scan.get('completed_at'))
        if is_netexec:
            origin_name = f"NetExec import #{scan['id']}"
        else:
            origin_name = f"Escaneo {scan['id']}"

        origin_props = {
            'NAME': origin_name,
            'ORGANIZACION': org_name,
            'MI_IP': myip,
            'SCAN_ID': scan['id'],
            'SCAN_TYPE': scan['scan_type'] or '',
            'SCAN_MODE': scan['scan_mode'] or '',
            'TARGET_RANGE': scan['target_range'] or '',
            'INTERFACE': scan['interface'] or '',
            'COMMAND': scan.get('nmap_command') or 'N/A',
            'STARTED_AT': scan['started_at'] or '',
            'COMPLETED_AT': scan['completed_at'] or '',
            'DURACION_SEG': duration,
            'STATUS': scan['status'] or '',
            'LOCATION': scan['location'] or '',
            'HOSTS_DESCUBIERTOS': scan.get('hosts_discovered') or 0,
            'PUERTOS_ENCONTRADOS': scan.get('ports_found') or 0,
        }

        origin_node = Node("ORIGEN", **origin_props)
        graph.merge(origin_node, "ORIGEN", ("ORGANIZACION", "SCAN_ID"))

        # Relación ORG -> ORIGEN
        rel_org_origin = Relationship(org_node, "HAS_SOURCE", origin_node)
        graph.merge(rel_org_origin)

        discovery_source = f"{scan['scan_mode']}:{scan['id']}"

        # 3. PREPARAR DATOS PARA BULK INSERT (UNWIND)
        hosts_data = []
        services_data = []

        for h in scan['hosts']:
            svcs = h.get('services', [])
            has_vulns = any(s.get('vulnerabilities') for s in svcs)
            has_screenshots = any(s.get('SCREENSHOT') for s in svcs)
            has_source = any(s.get('WEBSOURCE') for s in svcs)

            h_props = {
                'IP':               h['ip'],
                'HOSTNAME':         h['hostname'] or '',
                'ORGANIZACION':     h['organization'],
                'CRITICO':          "SÍ" if h['is_critical'] else "NO",
                'RAZON_CRITICO':    h.get('critical_reason') or '',
                'NOMBRE_CRITICO':   h.get('critical_name') or '',
                'SUBRED':           h.get('network_range') or 'Unknown',
                'NOMBRE_SUBRED':    h.get('network_name') or 'Unknown',
                'SISTEMA':          h.get('network_system') or 'N/A',
                'VENDOR':           h['vendor'] or '',
                'MAC':              h['mac'] or '',
                'OS':               h['os_info'] or '',
                'HOSTNAMES':        h.get('hostnames') or '',
                'INTERFACES':       h.get('interfaces') or '',
                'SCRIPTS_HOST':     h.get('scripts') or '',
                'TIMESTAMP':        h.get('timestamp') or '',
                'DISCOVERY_SOURCE': discovery_source,
                'NUM_PUERTOS':      len(svcs),
                'TIENE_VULNERABILIDADES': "SÍ" if has_vulns else "NO",
                'TIENE_SCREENSHOTS':     "SÍ" if has_screenshots else "NO",
                'TIENE_CODIGO_FUENTE':   "SÍ" if has_source else "NO",
            }
            hosts_data.append(h_props)

            # Recolectar Servicios
            for s in svcs:
                vulns_list = s.get('vulnerabilities') or []
                vuln_ids = [v.get('cve_id') or v.get('vulnerability_id') or '' for v in vulns_list]

                s_props = {
                    'host_ip':              h['ip'],
                    'id':                   f"{h['ip']}_{s['port']}_{s['protocol']}_{discovery_source}",
                    'port':                 s['port'],
                    'protocol':             s['protocol'] or '',
                    'name':                 s['name'] or 'unknown',
                    'product':              s['product'] or '',
                    'version':              s['version'] or '',
                    'extrainfo':            s.get('extrainfo') or '',
                    'cpe':                  s.get('cpe') or '',
                    'reason':               s.get('reason') or '',
                    'vulnerabilidades':     ", ".join(filter(None, vuln_ids)),
                    'num_vulnerabilidades': len(vulns_list),
                    'tiene_screenshot':     "SÍ" if s.get('SCREENSHOT') else "NO",
                    'tiene_codigo_fuente':  "SÍ" if s.get('WEBSOURCE') else "NO",
                }

                # Añadir enriquecimientos binarios (SCREENSHOT, WEBSOURCE, IOXID…)
                _skip = {'port', 'protocol', 'name', 'product', 'version', 'extrainfo',
                         'cpe', 'reason', 'scripts', 'vulnerabilities', 'host_ip', 'id'}
                for k, v in s.items():
                    if k not in _skip and k not in s_props:
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

        # Rellenar ip_nodes_map para el paso 7 (esto requiere otra query o matcheo)
        # Como es para correlación, podemos hacerlo más eficiente después.
        for h in scan['hosts']:
            if h['ip'] not in ip_nodes_map: ip_nodes_map[h['ip']] = []
            # Guardamos solo el source para correlacionar después
            ip_nodes_map[h['ip']].append(discovery_source)

def _load_netexec_data(db_path: str, scan_id: int) -> Dict:
    """Lee enrichments NETEXEC y credenciales asociadas a un escaneo."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    out = {'hosts': {}, 'credentials': []}
    try:
        rows = conn.execute("""
            SELECT h.ip_address AS ip, e.data
            FROM enrichments e
            JOIN scan_results sr ON sr.id = e.scan_result_id
            JOIN hosts h ON h.id = sr.host_id
            WHERE sr.scan_id = ? AND e.enrichment_type = 'NETEXEC'
        """, (scan_id,)).fetchall()
        for r in rows:
            try:
                payload = json.loads(r['data']) if r['data'] else {}
            except Exception:
                payload = {}
            out['hosts'][r['ip']] = payload
        cred_rows = conn.execute("""
            SELECT domain, username, password, credtype, source_protocol, source_host_ip
            FROM credentials WHERE scan_id = ?
        """, (scan_id,)).fetchall()
        out['credentials'] = [dict(r) for r in cred_rows]
    except Exception as e:
        print(f"⚠️  Error leyendo enriquecimientos NETEXEC: {e}")
    finally:
        conn.close()
    return out


def _push_netexec_to_neo4j(graph, org_name: str, discovery_source: str,
                            nxc_data: Dict):
    """Crea/actualiza nodos :CREDENCIAL y enriquece :HOST con metadatos NetExec."""
    # 1) Enriquecer hosts con propiedades nxc-específicas
    host_updates = []
    for ip, payload in (nxc_data.get('hosts') or {}).items():
        protocols = payload.get('protocols') or {}
        smb = protocols.get('smb') or {}
        ldap = protocols.get('ldap') or {}
        rdp = protocols.get('rdp') or {}
        host_updates.append({
            'IP': ip,
            'NXC_DOMAIN': payload.get('domain') or '',
            'NXC_OS': payload.get('os') or '',
            'NXC_SMB_SIGNING': str(smb.get('signing')) if smb else '',
            'NXC_SMBV1': str(smb.get('smbv1')) if smb else '',
            'NXC_SMB_DC': str(smb.get('dc')) if smb else '',
            'NXC_RDP_NLA': str(rdp.get('nla')) if rdp else '',
            'NXC_LDAP_SIGNING_REQUIRED': str(ldap.get('signing_required')) if ldap else '',
            'NXC_SHARES': ', '.join(s.get('name', '') for s in (payload.get('shares') or [])),
            'NXC_ADMIN_USERS': ', '.join(payload.get('admin_users') or []),
            'NXC_LOOT_FILES': str(len(payload.get('loot_files') or [])),
        })
    if host_updates:
        graph.run("""
            UNWIND $data AS row
            MATCH (h:HOST {ORGANIZACION: $org, IP: row.IP, DISCOVERY_SOURCE: $ds})
            SET h += row
        """, data=host_updates, org=org_name, ds=discovery_source)

    # 2) Crear nodos :CREDENCIAL y relaciones
    cred_rows = []
    for c in (nxc_data.get('credentials') or []):
        if not c.get('username'):
            continue
        domain = (c.get('domain') or '').strip()
        username = c['username']
        password = c.get('password') or ''
        credtype = c.get('credtype') or ''
        cred_rows.append({
            'ID': f"{org_name}|{domain}|{username}|{credtype}|{password[:32]}",
            'DOMINIO': domain,
            'USUARIO': username,
            'PASSWORD': password,
            'TIPO': credtype,
            'PROTOCOLO_ORIGEN': c.get('source_protocol') or '',
            'HOST_ORIGEN': c.get('source_host_ip') or '',
            'ORGANIZACION': org_name,
        })

    if cred_rows:
        graph.run("""
            UNWIND $data AS row
            MERGE (c:CREDENCIAL {ID: row.ID})
            SET c += row
            WITH c, row
            MATCH (org:ORGANIZACION {name: $org})
            MERGE (org)-[:HAS_CREDENTIAL]->(c)
        """, data=cred_rows, org=org_name)

        # Vincular credencial → host origen si aplica
        graph.run("""
            UNWIND $data AS row
            WITH row WHERE row.HOST_ORIGEN <> ''
            MATCH (c:CREDENCIAL {ID: row.ID})
            MATCH (h:HOST {ORGANIZACION: $org, IP: row.HOST_ORIGEN, DISCOVERY_SOURCE: $ds})
            MERGE (c)-[:PILLAGED_FROM]->(h)
        """, data=cred_rows, org=org_name, ds=discovery_source)

    return {
        'hosts_updated': len(host_updates),
        'credentials_pushed': len(cred_rows),
    }


def export_single_scan(scan_id: int) -> Dict:
    """Exporta un único escaneo a Neo4j. Pensado para invocarse desde el web API.

    Lee la conexión de Neo4j desde variables de entorno (NEO4J_HOST, NEO4J_USERNAME,
    NEO4J_PASSWORD).
    """
    db_path = os.getenv("ARSENAL_DB_PATH", "results/scans.db")
    if not Path(db_path).exists():
        return {'ok': False, 'error': f'BD no encontrada: {db_path}'}

    host = os.getenv("NEO4J_HOST", "127.0.0.1")
    user = os.getenv("NEO4J_USERNAME", "neo4j")
    password = os.getenv("NEO4J_PASSWORD", "change-this-neo4j-password")

    try:
        graph = connect_to_neo4j(host, user, password)
    except Exception as e:
        return {'ok': False, 'error': f'Neo4j: {e}'}

    scans_data = get_scans_data(db_path, scan_id=scan_id)
    if not scans_data:
        return {'ok': False, 'error': f'Scan {scan_id} no encontrado o no completado'}

    process_to_neo4j_v2(graph, scans_data)

    scan = scans_data[0]
    nxc = _load_netexec_data(db_path, scan_id)
    nxc_stats = _push_netexec_to_neo4j(
        graph,
        scan['organization_name'].upper(),
        f"{scan['scan_mode']}:{scan['id']}",
        nxc,
    )

    return {
        'ok': True,
        'scan_id': scan_id,
        'hosts_in_scan': len(scan['hosts']),
        **nxc_stats,
    }


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
