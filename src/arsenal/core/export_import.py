"""
Funciones de exportación e importación de datos de escaneos
"""

import sqlite3
import json
import zipfile
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, List
from arsenal.core.storage import ScanStorage


def export_data(storage: ScanStorage, organization: Optional[str] = None, 
               location: Optional[str] = None, 
               scan_id: Optional[int] = None) -> Path:
    """
    Exporta datos y archivos según los filtros proporcionados.
    
    Args:
        storage: Instancia de ScanStorage
        organization: Si se proporciona, exporta solo esta organización
        location: Si se proporciona junto con organization, exporta solo esta ubicación
        scan_id: Si se proporciona, exporta solo este escaneo
    
    Returns:
        Path al archivo ZIP generado
    """
    # Crear archivo temporal para el ZIP
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    if scan_id:
        zip_name = f"export_scan_{scan_id}_{timestamp}.zip"
    elif location and organization:
        zip_name = f"export_{organization}_{location}_{timestamp}.zip"
    elif organization:
        zip_name = f"export_{organization}_{timestamp}.zip"
    else:
        zip_name = f"export_all_{timestamp}.zip"
    
    zip_path = storage.results_root / zip_name
    
    # Crear ZIP
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        # 1. Exportar datos de la base de datos
        conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Determinar qué datos exportar
        if scan_id:
            # Exportar solo un escaneo
            scan = cursor.execute("""
                SELECT * FROM scans WHERE id = ?
            """, (scan_id,)).fetchone()
            if not scan:
                conn.close()
                raise ValueError(f"Escaneo {scan_id} no encontrado")
            
            export_data = {
                'type': 'scan',
                'scan_id': scan_id,
                'metadata': dict(scan),
                'scan_results': [],
                'hosts': [],
                'vulnerabilities': [],
                'enrichments': [],
                'networks': [],
                'critical_devices': []
            }
            
            # Obtener redes de la organización
            networks = cursor.execute("""
                SELECT * FROM networks WHERE organization_name = ?
            """, (scan['organization_name'],)).fetchall()
            export_data['networks'] = [dict(n) for n in networks]
            
            # Obtener dispositivos críticos
            critical_devs = cursor.execute("""
                SELECT * FROM critical_devices WHERE organization_name = ?
            """, (scan['organization_name'],)).fetchall()
            export_data['critical_devices'] = [dict(d) for d in critical_devs]
            
            # Obtener scan_results
            scan_results = cursor.execute("""
                SELECT * FROM scan_results WHERE scan_id = ?
            """, (scan_id,)).fetchall()
            export_data['scan_results'] = [dict(r) for r in scan_results]
            
            # Obtener hosts relacionados
            host_ids = [r['host_id'] for r in scan_results]
            if host_ids:
                placeholders = ','.join('?' * len(host_ids))
                hosts = cursor.execute(f"""
                    SELECT * FROM hosts WHERE id IN ({placeholders})
                """, host_ids).fetchall()
                export_data['hosts'] = [dict(h) for h in hosts]
            
            # Obtener vulnerabilidades
            scan_result_ids = [r['id'] for r in scan_results]
            if scan_result_ids:
                placeholders = ','.join('?' * len(scan_result_ids))
                vulns = cursor.execute(f"""
                    SELECT * FROM vulnerabilities WHERE scan_result_id IN ({placeholders})
                """, scan_result_ids).fetchall()
                export_data['vulnerabilities'] = [dict(v) for v in vulns]
                
                enrichments = cursor.execute(f"""
                    SELECT * FROM enrichments WHERE scan_result_id IN ({placeholders})
                """, scan_result_ids).fetchall()
                export_data['enrichments'] = [dict(e) for e in enrichments]
            
            # Guardar JSON en ZIP
            zipf.writestr('export_data.json', json.dumps(export_data, indent=2, default=str))
            
            # Exportar archivos del escaneo
            scan_dir = storage.get_scan_directory(
                scan['organization_name'],
                scan['location'],
                scan_id
            )
            if scan_dir.exists():
                _add_directory_to_zip(zipf, scan_dir, f"scans/{scan_dir.name}")
            
        elif location and organization:
            # Exportar organización + ubicación
            scans = cursor.execute("""
                SELECT * FROM scans 
                WHERE organization_name = ? AND location = ?
            """, (organization.upper(), location.upper())).fetchall()
            
            export_data = {
                'type': 'location',
                'organization': organization.upper(),
                'location': location.upper(),
                'scans': [dict(s) for s in scans],
                'scan_results': [],
                'hosts': [],
                'vulnerabilities': [],
                'enrichments': []
            }
            
            # Obtener redes de la organización
            networks = cursor.execute("""
                SELECT * FROM networks WHERE organization_name = ?
            """, (organization.upper(),)).fetchall()
            export_data['networks'] = [dict(n) for n in networks]
            
            # Obtener dispositivos críticos
            critical_devs = cursor.execute("""
                SELECT * FROM critical_devices WHERE organization_name = ?
            """, (organization.upper(),)).fetchall()
            export_data['critical_devices'] = [dict(d) for d in critical_devs]
            
            
            scan_ids = [s['id'] for s in scans]
            if scan_ids:
                placeholders = ','.join('?' * len(scan_ids))
                scan_results = cursor.execute(f"""
                    SELECT * FROM scan_results WHERE scan_id IN ({placeholders})
                """, scan_ids).fetchall()
                export_data['scan_results'] = [dict(r) for r in scan_results]
                
                host_ids = list(set([r['host_id'] for r in scan_results]))
                if host_ids:
                    placeholders = ','.join('?' * len(host_ids))
                    hosts = cursor.execute(f"""
                        SELECT * FROM hosts WHERE id IN ({placeholders})
                    """, host_ids).fetchall()
                    export_data['hosts'] = [dict(h) for h in hosts]
                
                scan_result_ids = [r['id'] for r in scan_results]
                if scan_result_ids:
                    placeholders = ','.join('?' * len(scan_result_ids))
                    vulns = cursor.execute(f"""
                        SELECT * FROM vulnerabilities WHERE scan_result_id IN ({placeholders})
                    """, scan_result_ids).fetchall()
                    export_data['vulnerabilities'] = [dict(v) for v in vulns]
                    
                    enrichments = cursor.execute(f"""
                        SELECT * FROM enrichments WHERE scan_result_id IN ({placeholders})
                    """, scan_result_ids).fetchall()
                    export_data['enrichments'] = [dict(e) for e in enrichments]
            
            zipf.writestr('export_data.json', json.dumps(export_data, indent=2, default=str))
            
            # Exportar directorio de la ubicación
            location_dir = storage.results_root / organization.upper() / location.upper()
            if location_dir.exists():
                _add_directory_to_zip(zipf, location_dir, f"{organization.upper()}/{location.upper()}")
            
        elif organization:
            # Exportar toda la organización
            org_data = cursor.execute("""
                SELECT * FROM organizations WHERE name = ?
            """, (organization.upper(),)).fetchone()
            
            scans = cursor.execute("""
                SELECT * FROM scans WHERE organization_name = ?
            """, (organization.upper(),)).fetchall()
            
            export_data = {
                'type': 'organization',
                'organization': dict(org_data) if org_data else None,
                'scans': [dict(s) for s in scans],
                'scan_results': [],
                'hosts': [],
                'vulnerabilities': [],
                'enrichments': []
            }
            
            # Obtener redes de la organización
            networks = cursor.execute("""
                SELECT * FROM networks WHERE organization_name = ?
            """, (organization.upper(),)).fetchall()
            export_data['networks'] = [dict(n) for n in networks]
            
            # Obtener dispositivos críticos
            critical_devs = cursor.execute("""
                SELECT * FROM critical_devices WHERE organization_name = ?
            """, (organization.upper(),)).fetchall()
            export_data['critical_devices'] = [dict(d) for d in critical_devs]
            
            
            scan_ids = [s['id'] for s in scans]
            if scan_ids:
                placeholders = ','.join('?' * len(scan_ids))
                scan_results = cursor.execute(f"""
                    SELECT * FROM scan_results WHERE scan_id IN ({placeholders})
                """, scan_ids).fetchall()
                export_data['scan_results'] = [dict(r) for r in scan_results]
                
                host_ids = list(set([r['host_id'] for r in scan_results]))
                if host_ids:
                    placeholders = ','.join('?' * len(host_ids))
                    hosts = cursor.execute(f"""
                        SELECT * FROM hosts WHERE id IN ({placeholders})
                    """, host_ids).fetchall()
                    export_data['hosts'] = [dict(h) for h in hosts]
                
                scan_result_ids = [r['id'] for r in scan_results]
                if scan_result_ids:
                    placeholders = ','.join('?' * len(scan_result_ids))
                    vulns = cursor.execute(f"""
                        SELECT * FROM vulnerabilities WHERE scan_result_id IN ({placeholders})
                    """, scan_result_ids).fetchall()
                    export_data['vulnerabilities'] = [dict(v) for v in vulns]
                    
                    enrichments = cursor.execute(f"""
                        SELECT * FROM enrichments WHERE scan_result_id IN ({placeholders})
                    """, scan_result_ids).fetchall()
                    export_data['enrichments'] = [dict(e) for e in enrichments]
            
            zipf.writestr('export_data.json', json.dumps(export_data, indent=2, default=str))
            
            # Exportar directorio completo de la organización
            org_dir = storage.results_root / organization.upper()
            if org_dir.exists():
                _add_directory_to_zip(zipf, org_dir, organization.upper())
            
        else:
            # Exportar todo
            organizations = cursor.execute("SELECT * FROM organizations").fetchall()
            scans = cursor.execute("SELECT * FROM scans").fetchall()
            scan_results = cursor.execute("SELECT * FROM scan_results").fetchall()
            hosts = cursor.execute("SELECT * FROM hosts").fetchall()
            vulnerabilities = cursor.execute("SELECT * FROM vulnerabilities").fetchall()
            enrichments = cursor.execute("SELECT * FROM enrichments").fetchall()
            
            export_data = {
                'type': 'all',
                'organizations': [dict(o) for o in organizations],
                'scans': [dict(s) for s in scans],
                'scan_results': [dict(r) for r in scan_results],
                'hosts': [dict(h) for h in hosts],
                'vulnerabilities': [dict(v) for v in vulnerabilities],
                'enrichments': [dict(e) for e in enrichments],
                'networks': [],
                'critical_devices': []
            }
            
            # Obtener todas las redes
            networks = cursor.execute("SELECT * FROM networks").fetchall()
            export_data['networks'] = [dict(n) for n in networks]
            
            # Obtener todos los dispositivos críticos
            critical_devs = cursor.execute("SELECT * FROM critical_devices").fetchall()
            export_data['critical_devices'] = [dict(d) for d in critical_devs]
            
            zipf.writestr('export_data.json', json.dumps(export_data, indent=2, default=str))
            
            # Exportar todo el directorio results (excepto scans.db y ZIPs)
            if storage.results_root.exists():
                for item in storage.results_root.iterdir():
                    if item.is_dir() and item.name != '__pycache__':
                        _add_directory_to_zip(zipf, item, item.name)
                    elif item.is_file() and item.suffix == '.zip':
                        continue  # No incluir otros ZIPs
        
        conn.close()
    
    return zip_path


def _add_directory_to_zip(zipf: zipfile.ZipFile, directory: Path, zip_path: str):
    """Añade un directorio completo al ZIP, manejando posibles errores de acceso."""
    import os
    for root, dirs, files in os.walk(directory):
        # Excluir archivos ZIP y la base de datos
        if 'scans.db' in root or root.endswith('.zip'):
            continue
        for file in files:
            if file.endswith('.zip'):
                continue
            file_path = Path(root) / file
            arcname = str(Path(zip_path) / file_path.relative_to(directory))
            try:
                zipf.write(file_path, arcname)
            except (PermissionError, OSError) as e:
                print(f"⚠️ Saltando archivo {file_path} por error de acceso: {e}")


def import_data(storage: ScanStorage, zip_path: Path) -> Dict:
    """
    Importa datos y archivos desde un archivo ZIP exportado.
    
    Args:
        storage: Instancia de ScanStorage
        zip_path: Path al archivo ZIP a importar
    
    Returns:
        Dict con información sobre lo importado
    """
    import os
    import_stats = {
        'organizations': 0,
        'scans': 0,
        'scan_results': 0,
        'hosts': 0,
        'vulnerabilities': 0,
        'enrichments': 0,
        'files_imported': 0
    }
    
    # Crear directorio temporal para extraer
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Extraer ZIP
        with zipfile.ZipFile(zip_path, 'r') as zipf:
            zipf.extractall(temp_path)
        
        # Leer datos exportados
        export_data_path = temp_path / 'export_data.json'
        if not export_data_path.exists():
            raise ValueError("Archivo export_data.json no encontrado en el ZIP")
        
        with open(export_data_path, 'r') as f:
            export_data = json.load(f)
        
        conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys = ON")
        cursor = conn.cursor()
        
        try:
            # Importar según el tipo
            if export_data['type'] == 'all':
                # Importar todo
                for org in export_data.get('organizations', []):
                    # Normalizar nombre
                    org_name = org['name'].strip().upper()
                    cursor.execute("""
                        INSERT OR REPLACE INTO organizations (name, description, created_at)
                        VALUES (?, ?, ?)
                    """, (org_name, org.get('description'), org.get('created_at')))
                    import_stats['organizations'] += 1
                
                _import_scan_data(cursor, export_data, import_stats)
                _import_org_metadata(cursor, export_data, import_stats)
                
                # Copiar archivos
                for item in temp_path.iterdir():
                    if item.is_dir() and item.name != '__pycache__':
                        dest_dir = storage.results_root / item.name
                        if dest_dir.exists():
                            shutil.rmtree(dest_dir)
                        shutil.copytree(item, dest_dir)
                        import_stats['files_imported'] += 1
            
            elif export_data['type'] == 'organization':
                org = export_data.get('organization')
                if org:
                    if isinstance(org, dict):
                        org_name_val = org.get('name', '').strip().upper()
                        org_desc = org.get('description')
                        org_created = org.get('created_at')
                    else:
                        org_name_val = str(org).strip().upper()
                        org_desc = None
                        org_created = datetime.now().isoformat()

                    cursor.execute("""
                        INSERT OR REPLACE INTO organizations (name, description, created_at)
                        VALUES (?, ?, ?)
                    """, (org_name_val, org_desc, org_created))
                    import_stats['organizations'] += 1
                
                _import_scan_data(cursor, export_data, import_stats)
                _import_org_metadata(cursor, export_data, import_stats)
                
                # Copiar archivos de la organización
                org_info = export_data.get('organization')
                if isinstance(org_info, dict):
                    org_name = org_info.get('name', '').strip().upper()
                else:
                    org_name = str(org_info).strip().upper() if org_info else None
                
                if org_name:
                    org_dir = temp_path / org_name.upper()
                    if org_dir.exists():
                        dest_dir = storage.results_root / org_name.upper()
                        if dest_dir.exists():
                            _merge_directory(org_dir, dest_dir)
                        else:
                            shutil.copytree(org_dir, dest_dir)
                        import_stats['files_imported'] += 1
            
            elif export_data['type'] == 'location':
                org_name = export_data.get('organization', '')
                if org_name:
                    org_name = org_name.strip().upper()
                    cursor.execute("""
                        INSERT OR IGNORE INTO organizations (name, description, created_at)
                        VALUES (?, ?, ?)
                    """, (org_name, None, datetime.now().isoformat()))
                    import_stats['organizations'] += 1
                
                _import_scan_data(cursor, export_data, import_stats)
                _import_org_metadata(cursor, export_data, import_stats)
                
                # Copiar archivos de la ubicación
                location = export_data.get('location')
                if org_name and location:
                    location_dir = temp_path / org_name.upper() / location.upper()
                    if location_dir.exists():
                        dest_dir = storage.results_root / org_name.upper() / location.upper()
                        dest_dir.parent.mkdir(parents=True, exist_ok=True)
                        if dest_dir.exists():
                            _merge_directory(location_dir, dest_dir)
                        else:
                            shutil.copytree(location_dir, dest_dir)
                        import_stats['files_imported'] += 1
            
            elif export_data['type'] == 'scan':
                scan_meta = export_data.get('metadata', {})
                org_name = scan_meta.get('organization_name', '')
                location = scan_meta.get('location', '')
                
                if org_name:
                    org_name = org_name.strip().upper()
                    cursor.execute("""
                        INSERT OR IGNORE INTO organizations (name, description, created_at)
                        VALUES (?, ?, ?)
                    """, (org_name, None, datetime.now().isoformat()))
                    import_stats['organizations'] += 1
                
                _import_scan_data(cursor, export_data, import_stats)
                _import_org_metadata(cursor, export_data, import_stats)
                
                # Copiar archivos del escaneo
                scans_dir = temp_path / 'scans'
                if scans_dir.exists():
                    for scan_dir in scans_dir.iterdir():
                        if scan_dir.is_dir():
                            dest_base = storage.results_root / org_name.upper() / location.upper() / 'scans'
                            dest_base.mkdir(parents=True, exist_ok=True)
                            dest_dir = dest_base / scan_dir.name
                            if dest_dir.exists():
                                shutil.rmtree(dest_dir)
                            shutil.copytree(scan_dir, dest_dir)
                            import_stats['files_imported'] += 1
            
            conn.commit()
            
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    return import_stats


def _import_scan_data(cursor, export_data: Dict, import_stats: Dict):
    """Helper para importar datos de escaneos."""
    # Importar hosts
    for host in export_data.get('hosts', []):
        cursor.execute("""
            INSERT INTO hosts 
            (id, ip_address, hostname, hostnames_json, mac_address, vendor,
             subnet, is_private, os_info_json, host_scripts_json,
             first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip_address) DO UPDATE SET
                hostname = COALESCE(excluded.hostname, hostname),
                hostnames_json = COALESCE(excluded.hostnames_json, hostnames_json),
                mac_address = COALESCE(excluded.mac_address, mac_address),
                vendor = COALESCE(excluded.vendor, vendor),
                subnet = COALESCE(excluded.subnet, subnet),
                os_info_json = COALESCE(excluded.os_info_json, os_info_json),
                host_scripts_json = COALESCE(excluded.host_scripts_json, host_scripts_json),
                last_seen = excluded.last_seen
        """, (
            host.get('id'), host['ip_address'], host.get('hostname'),
            host.get('hostnames_json'), host.get('mac_address'),
            host.get('vendor'), host.get('subnet'), host.get('is_private'),
            host.get('os_info_json'), host.get('host_scripts_json'),
            host.get('first_seen'), host.get('last_seen')
        ))
        import_stats['hosts'] += 1
    
    # Importar escaneos
    scans = export_data.get('scans', [])
    if not scans and export_data.get('metadata'):
        scans = [export_data['metadata']]
    
    for scan in scans:
        # Normalizar nombres
        org_name = scan['organization_name'].strip().upper()
        loc_name = scan['location'].strip().upper()
        
        cursor.execute("""
            INSERT OR REPLACE INTO scans 
            (id, organization_name, location, scan_type, target_range, interface,
             nmap_command, started_at, completed_at, status, hosts_discovered,
             ports_found, error_message, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan.get('id'), org_name, loc_name,
            scan['scan_type'], scan['target_range'], scan.get('interface'),
            scan.get('nmap_command'), scan.get('started_at'),
            scan.get('completed_at'), scan.get('status', 'completed'),
            scan.get('hosts_discovered'), scan.get('ports_found'),
            scan.get('error_message'), scan.get('created_by')
        ))
        import_stats['scans'] += 1
    
    # Importar scan_results
    for result in export_data.get('scan_results', []):
        cursor.execute("""
            INSERT OR REPLACE INTO scan_results
            (id, scan_id, host_id, port, protocol, state, service_name,
             product, version, extrainfo, cpe, reason, reason_ttl,
             confidence, scripts_json, discovered_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result.get('id'), result['scan_id'], result['host_id'],
            result.get('port'), result.get('protocol'), result['state'],
            result.get('service_name'), result.get('product'),
            result.get('version'), result.get('extrainfo'),
            result.get('cpe'), result.get('reason'),
            result.get('reason_ttl'), result.get('confidence'),
            result.get('scripts_json'), result.get('discovered_at')
        ))
        import_stats['scan_results'] += 1
    
    # Importar vulnerabilidades
    for vuln in export_data.get('vulnerabilities', []):
        cursor.execute("""
            INSERT OR REPLACE INTO vulnerabilities
            (id, scan_result_id, vulnerability_id, title, description,
             severity, cvss_score, references, discovered_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            vuln.get('id'), vuln['scan_result_id'],
            vuln['vulnerability_id'], vuln.get('title'),
            vuln.get('description'), vuln.get('severity'),
            vuln.get('cvss_score'), vuln.get('references'),
            vuln.get('discovered_at')
        ))
        import_stats['vulnerabilities'] += 1
    
    # Importar enrichments
    for enrich in export_data.get('enrichments', []):
        # Usar created_at si existe, si no usar discovered_at (compatibilidad), o datetime actual
        created_at = enrich.get('created_at') or enrich.get('discovered_at') or datetime.now().isoformat()
        cursor.execute("""
            INSERT OR REPLACE INTO enrichments
            (id, scan_result_id, enrichment_type, file_path, data, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            enrich.get('id'), enrich['scan_result_id'],
            enrich['enrichment_type'], enrich.get('file_path'),
            enrich.get('data'), created_at
        ))
        import_stats['enrichments'] += 1


def _merge_directory(source: Path, dest: Path):
    """Fusiona directorio fuente en destino, evitando sobrescribir y manejando errores."""
    for item in source.rglob('*'):
        if item.is_file():
            rel_path = item.relative_to(source)
            dest_file = dest / rel_path
            dest_file.parent.mkdir(parents=True, exist_ok=True)
            if not dest_file.exists():
                try:
                    shutil.copy2(item, dest_file)
                except (PermissionError, OSError) as e:
                    print(f"⚠️ No se pudo copiar {item} a {dest_file}: {e}")


def _import_org_metadata(cursor, export_data: Dict, import_stats: Dict):
    """Importa redes y dispositivos críticos."""
    # Importar redes
    for net in export_data.get('networks', []):
        # Normalizar nombre
        org_name = net['organization_name'].strip().upper()
        cursor.execute("""
            INSERT OR REPLACE INTO networks 
            (organization_name, system_name, network_name, network_range, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            org_name, net.get('system_name'),
            net['network_name'], net['network_range'],
            net.get('created_at', datetime.now().isoformat())
        ))
        if 'networks' not in import_stats:
            import_stats['networks'] = 0
        import_stats['networks'] += 1

    # Importar dispositivos críticos
    for dev in export_data.get('critical_devices', []):
        # Normalizar nombre
        org_name = dev['organization_name'].strip().upper()
        cursor.execute("""
            INSERT OR REPLACE INTO critical_devices
            (organization_name, name, ips, reason, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            org_name, dev['name'],
            dev['ips'], dev['reason'],
            dev.get('created_at', datetime.now().isoformat())
        ))
        if 'critical_devices' not in import_stats:
            import_stats['critical_devices'] = 0
        import_stats['critical_devices'] += 1

