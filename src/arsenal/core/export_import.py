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
            scan = cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
            if not scan:
                conn.close()
                raise ValueError(f"Escaneo {scan_id} no encontrado")

            scan_results = cursor.execute(
                "SELECT * FROM scan_results WHERE scan_id = ?", (scan_id,)
            ).fetchall()
            host_ids      = list(set(r['host_id'] for r in scan_results))
            sr_ids        = [r['id'] for r in scan_results]
            ph_h          = ','.join('?' * len(host_ids))  if host_ids else '0'
            ph_sr         = ','.join('?' * len(sr_ids))    if sr_ids   else '0'

            org_rec = cursor.execute("SELECT * FROM organizations WHERE name = ?", (scan['organization_name'],)).fetchone()
            pwndoc_rows = cursor.execute("SELECT * FROM pwndoc_audits WHERE UPPER(org_name) = UPPER(?)", (scan['organization_name'],)).fetchall()

            export_data = {
                'type': 'scan',
                'scan_id': scan_id,
                'metadata': dict(scan),
                'organization_record':  dict(org_rec) if org_rec else None,
                'scans': [dict(scan)],
                'scan_results':         [dict(r) for r in scan_results],
                'hosts':                [dict(h) for h in cursor.execute(f"SELECT * FROM hosts WHERE id IN ({ph_h})", host_ids).fetchall()] if host_ids else [],
                'host_scan_metadata':   [dict(h) for h in cursor.execute("SELECT * FROM host_scan_metadata WHERE scan_id = ?", (scan_id,)).fetchall()],
                'vulnerabilities':      [dict(v) for v in cursor.execute(f"SELECT * FROM vulnerabilities WHERE scan_result_id IN ({ph_sr})", sr_ids).fetchall()] if sr_ids else [],
                'enrichments':          [dict(e) for e in cursor.execute(f"SELECT * FROM enrichments WHERE scan_result_id IN ({ph_sr})", sr_ids).fetchall()] if sr_ids else [],
                'passive_conversations': [dict(p) for p in cursor.execute("SELECT * FROM passive_conversations WHERE scan_id = ?", (scan_id,)).fetchall()],
                'networks':             [dict(n) for n in cursor.execute("SELECT * FROM networks WHERE organization_name = ?", (scan['organization_name'],)).fetchall()],
                'critical_devices':     [dict(d) for d in cursor.execute("SELECT * FROM critical_devices WHERE organization_name = ?", (scan['organization_name'],)).fetchall()],
                'pwndoc_audits':        [dict(p) for p in pwndoc_rows],
            }

            zipf.writestr('export_data.json', json.dumps(export_data, indent=2, default=str))

            scan_dir = storage.get_scan_directory(scan['organization_name'], scan['location'], scan_id)
            if scan_dir.exists():
                _add_directory_to_zip(zipf, scan_dir, f"scans/{scan_dir.name}")

        elif location and organization:
            scans = cursor.execute(
                "SELECT * FROM scans WHERE organization_name = ? AND location = ?",
                (organization.upper(), location.upper())
            ).fetchall()
            scan_ids = [s['id'] for s in scans]
            ph_s     = ','.join('?' * len(scan_ids)) if scan_ids else '0'

            scan_results = cursor.execute(f"SELECT * FROM scan_results WHERE scan_id IN ({ph_s})", scan_ids).fetchall() if scan_ids else []
            host_ids     = list(set(r['host_id'] for r in scan_results))
            sr_ids       = [r['id'] for r in scan_results]
            ph_h         = ','.join('?' * len(host_ids)) if host_ids else '0'
            ph_sr        = ','.join('?' * len(sr_ids))   if sr_ids   else '0'

            org_rec = cursor.execute("SELECT * FROM organizations WHERE name = ?", (organization.upper(),)).fetchone()
            pwndoc_rows = cursor.execute("SELECT * FROM pwndoc_audits WHERE UPPER(org_name) = UPPER(?)", (organization.upper(),)).fetchall()

            export_data = {
                'type': 'location',
                'organization': organization.upper(),
                'organization_record':  dict(org_rec) if org_rec else None,
                'location': location.upper(),
                'scans':                [dict(s) for s in scans],
                'scan_results':         [dict(r) for r in scan_results],
                'hosts':                [dict(h) for h in cursor.execute(f"SELECT * FROM hosts WHERE id IN ({ph_h})", host_ids).fetchall()] if host_ids else [],
                'host_scan_metadata':   [dict(h) for h in cursor.execute(f"SELECT * FROM host_scan_metadata WHERE scan_id IN ({ph_s})", scan_ids).fetchall()] if scan_ids else [],
                'vulnerabilities':      [dict(v) for v in cursor.execute(f"SELECT * FROM vulnerabilities WHERE scan_result_id IN ({ph_sr})", sr_ids).fetchall()] if sr_ids else [],
                'enrichments':          [dict(e) for e in cursor.execute(f"SELECT * FROM enrichments WHERE scan_result_id IN ({ph_sr})", sr_ids).fetchall()] if sr_ids else [],
                'passive_conversations': [dict(p) for p in cursor.execute(f"SELECT * FROM passive_conversations WHERE scan_id IN ({ph_s})", scan_ids).fetchall()] if scan_ids else [],
                'networks':             [dict(n) for n in cursor.execute("SELECT * FROM networks WHERE organization_name = ?", (organization.upper(),)).fetchall()],
                'critical_devices':     [dict(d) for d in cursor.execute("SELECT * FROM critical_devices WHERE organization_name = ?", (organization.upper(),)).fetchall()],
                'pwndoc_audits':        [dict(p) for p in pwndoc_rows],
            }

            zipf.writestr('export_data.json', json.dumps(export_data, indent=2, default=str))

            location_dir = storage.results_root / organization.upper() / location.upper()
            if location_dir.exists():
                _add_directory_to_zip(zipf, location_dir, f"{organization.upper()}/{location.upper()}")

        elif organization:
            org_data = cursor.execute("SELECT * FROM organizations WHERE name = ?", (organization.upper(),)).fetchone()
            scans    = cursor.execute("SELECT * FROM scans WHERE organization_name = ?", (organization.upper(),)).fetchall()
            scan_ids = [s['id'] for s in scans]
            ph_s     = ','.join('?' * len(scan_ids)) if scan_ids else '0'

            scan_results = cursor.execute(f"SELECT * FROM scan_results WHERE scan_id IN ({ph_s})", scan_ids).fetchall() if scan_ids else []
            host_ids     = list(set(r['host_id'] for r in scan_results))
            sr_ids       = [r['id'] for r in scan_results]
            ph_h         = ','.join('?' * len(host_ids)) if host_ids else '0'
            ph_sr        = ','.join('?' * len(sr_ids))   if sr_ids   else '0'

            pwndoc_rows = cursor.execute("SELECT * FROM pwndoc_audits WHERE UPPER(org_name) = UPPER(?)", (organization.upper(),)).fetchall()

            export_data = {
                'type': 'organization',
                'organization':         dict(org_data) if org_data else None,
                'scans':                [dict(s) for s in scans],
                'scan_results':         [dict(r) for r in scan_results],
                'hosts':                [dict(h) for h in cursor.execute(f"SELECT * FROM hosts WHERE id IN ({ph_h})", host_ids).fetchall()] if host_ids else [],
                'host_scan_metadata':   [dict(h) for h in cursor.execute(f"SELECT * FROM host_scan_metadata WHERE scan_id IN ({ph_s})", scan_ids).fetchall()] if scan_ids else [],
                'vulnerabilities':      [dict(v) for v in cursor.execute(f"SELECT * FROM vulnerabilities WHERE scan_result_id IN ({ph_sr})", sr_ids).fetchall()] if sr_ids else [],
                'enrichments':          [dict(e) for e in cursor.execute(f"SELECT * FROM enrichments WHERE scan_result_id IN ({ph_sr})", sr_ids).fetchall()] if sr_ids else [],
                'passive_conversations': [dict(p) for p in cursor.execute(f"SELECT * FROM passive_conversations WHERE scan_id IN ({ph_s})", scan_ids).fetchall()] if scan_ids else [],
                'networks':             [dict(n) for n in cursor.execute("SELECT * FROM networks WHERE organization_name = ?", (organization.upper(),)).fetchall()],
                'critical_devices':     [dict(d) for d in cursor.execute("SELECT * FROM critical_devices WHERE organization_name = ?", (organization.upper(),)).fetchall()],
                'pwndoc_audits':        [dict(p) for p in pwndoc_rows],
            }

            zipf.writestr('export_data.json', json.dumps(export_data, indent=2, default=str))

            org_dir = storage.results_root / organization.upper()
            if org_dir.exists():
                _add_directory_to_zip(zipf, org_dir, organization.upper())

        else:
            # Exportar todo
            organizations = cursor.execute("SELECT * FROM organizations").fetchall()
            scans         = cursor.execute("SELECT * FROM scans").fetchall()
            scan_results  = cursor.execute("SELECT * FROM scan_results").fetchall()
            hosts         = cursor.execute("SELECT * FROM hosts").fetchall()
            sr_ids        = [r['id'] for r in scan_results]
            ph_sr         = ','.join('?' * len(sr_ids)) if sr_ids else '0'

            export_data = {
                'type': 'all',
                'organizations':        [dict(o) for o in organizations],
                'scans':                [dict(s) for s in scans],
                'scan_results':         [dict(r) for r in scan_results],
                'hosts':                [dict(h) for h in hosts],
                'host_scan_metadata':   [dict(h) for h in cursor.execute("SELECT * FROM host_scan_metadata").fetchall()],
                'vulnerabilities':      [dict(v) for v in cursor.execute(f"SELECT * FROM vulnerabilities WHERE scan_result_id IN ({ph_sr})", sr_ids).fetchall()] if sr_ids else [],
                'enrichments':          [dict(e) for e in cursor.execute(f"SELECT * FROM enrichments WHERE scan_result_id IN ({ph_sr})", sr_ids).fetchall()] if sr_ids else [],
                'passive_conversations': [dict(p) for p in cursor.execute("SELECT * FROM passive_conversations").fetchall()],
                'networks':             [dict(n) for n in cursor.execute("SELECT * FROM networks").fetchall()],
                'critical_devices':     [dict(d) for d in cursor.execute("SELECT * FROM critical_devices").fetchall()],
                'pwndoc_audits':        [dict(p) for p in cursor.execute("SELECT * FROM pwndoc_audits").fetchall()],
            }

            zipf.writestr('export_data.json', json.dumps(export_data, indent=2, default=str))

            if storage.results_root.exists():
                for item in storage.results_root.iterdir():
                    if item.is_dir() and item.name != '__pycache__':
                        _add_directory_to_zip(zipf, item, item.name)
                    elif item.is_file() and item.suffix == '.zip':
                        continue
        
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
                org_rec  = export_data.get('organization_record')
                if org_name:
                    org_name = org_name.strip().upper()
                    if isinstance(org_rec, dict):
                        cursor.execute("""
                            INSERT OR IGNORE INTO organizations (name, description, created_at)
                            VALUES (?, ?, ?)
                        """, (org_name, org_rec.get('description'), org_rec.get('created_at') or datetime.now().isoformat()))
                    else:
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
                org_rec  = export_data.get('organization_record')

                if org_name:
                    org_name = org_name.strip().upper()
                    if isinstance(org_rec, dict):
                        cursor.execute("""
                            INSERT OR IGNORE INTO organizations (name, description, created_at)
                            VALUES (?, ?, ?)
                        """, (org_name, org_rec.get('description'), org_rec.get('created_at') or datetime.now().isoformat()))
                    else:
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
    """
    Importa todos los datos de escaneo con remapping seguro de IDs.

    El remapping es necesario porque los IDs del origen pueden colisionar con
    los IDs ya existentes en el destino. Se construyen mapas:
        old_host_id   → new_host_id
        old_scan_id   → new_scan_id
        old_sr_id     → new_sr_id
    que se usan en las FKs de las tablas dependientes.
    """
    host_id_map: Dict[int, int] = {}   # old_host_id → new_host_id
    scan_id_map: Dict[int, int] = {}   # old_scan_id → new_scan_id
    sr_id_map:   Dict[int, int] = {}   # old_scan_result_id → new_scan_result_id

    # ------------------------------------------------------------------ #
    # 1. HOSTS — insertar sin ID explícito; resolver conflictos por IP    #
    # ------------------------------------------------------------------ #
    for host in export_data.get('hosts', []):
        old_id = host.get('id')
        ip     = host['ip_address']

        cursor.execute("""
            INSERT INTO hosts
                (ip_address, hostname, hostnames_json, mac_address, vendor,
                 subnet, is_private, os_info_json, host_scripts_json,
                 first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip_address) DO UPDATE SET
                hostname          = COALESCE(excluded.hostname,          hostname),
                hostnames_json    = COALESCE(excluded.hostnames_json,    hostnames_json),
                mac_address       = COALESCE(excluded.mac_address,       mac_address),
                vendor            = COALESCE(excluded.vendor,            vendor),
                subnet            = COALESCE(excluded.subnet,            subnet),
                os_info_json      = COALESCE(excluded.os_info_json,      os_info_json),
                host_scripts_json = COALESCE(excluded.host_scripts_json, host_scripts_json),
                last_seen         = excluded.last_seen
        """, (
            ip, host.get('hostname'), host.get('hostnames_json'),
            host.get('mac_address'), host.get('vendor'),
            host.get('subnet'), host.get('is_private'),
            host.get('os_info_json'), host.get('host_scripts_json'),
            host.get('first_seen'), host.get('last_seen')
        ))

        # Obtener el ID real en el destino (puede ser el existente o el recién creado)
        new_id = cursor.execute(
            "SELECT id FROM hosts WHERE ip_address = ?", (ip,)
        ).fetchone()[0]

        if old_id is not None:
            host_id_map[old_id] = new_id
        import_stats['hosts'] += 1

    # ------------------------------------------------------------------ #
    # 2. SCANS — insertar sin ID explícito; todos los campos              #
    # ------------------------------------------------------------------ #
    scans = export_data.get('scans', [])
    if not scans and export_data.get('metadata'):
        scans = [export_data['metadata']]

    for scan in scans:
        old_id   = scan.get('id')
        org_name = scan['organization_name'].strip().upper()
        loc_name = scan['location'].strip().upper()

        cursor.execute("""
            INSERT INTO scans
                (organization_name, location, scan_type, target_range, interface,
                 myip, nmap_command, started_at, completed_at, status,
                 hosts_discovered, ports_found, error_message, created_by,
                 scan_mode, pcap_file,
                 enable_version_detection, enable_vulnerability_scan,
                 enable_screenshots, enable_source_code)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            org_name, loc_name,
            scan.get('scan_type', 'mixed'), scan.get('target_range', ''),
            scan.get('interface'), scan.get('myip'),
            scan.get('nmap_command'), scan.get('started_at'),
            scan.get('completed_at'), scan.get('status', 'completed'),
            scan.get('hosts_discovered', 0), scan.get('ports_found', 0),
            scan.get('error_message'), scan.get('created_by'),
            scan.get('scan_mode', 'active'), scan.get('pcap_file'),
            scan.get('enable_version_detection', 0),
            scan.get('enable_vulnerability_scan', 0),
            scan.get('enable_screenshots', 0),
            scan.get('enable_source_code', 0),
        ))
        new_id = cursor.lastrowid
        if old_id is not None:
            scan_id_map[old_id] = new_id
        import_stats['scans'] += 1

    # ------------------------------------------------------------------ #
    # 3. SCAN_RESULTS — usar IDs remapeados de host y scan                #
    # ------------------------------------------------------------------ #
    for result in export_data.get('scan_results', []):
        old_id      = result.get('id')
        old_scan_id = result.get('scan_id')
        old_host_id = result.get('host_id')

        new_scan_id = scan_id_map.get(old_scan_id, old_scan_id)
        new_host_id = host_id_map.get(old_host_id, old_host_id)

        # Verificar que FK existe (evitar violaciones silenciosas)
        host_exists = cursor.execute(
            "SELECT 1 FROM hosts WHERE id = ?", (new_host_id,)
        ).fetchone()
        scan_exists = cursor.execute(
            "SELECT 1 FROM scans WHERE id = ?", (new_scan_id,)
        ).fetchone()
        if not host_exists or not scan_exists:
            print(f"⚠️ import scan_result: FK faltante host_id={new_host_id} scan_id={new_scan_id}, omitiendo")
            continue

        cursor.execute("""
            INSERT OR IGNORE INTO scan_results
                (scan_id, host_id, port, protocol, state, service_name,
                 product, version, extrainfo, cpe, reason, reason_ttl,
                 confidence, scripts_json, discovery_method, discovered_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            new_scan_id, new_host_id,
            result.get('port'), result.get('protocol'),
            result.get('state', 'up'),
            result.get('service_name'), result.get('product'),
            result.get('version'), result.get('extrainfo'),
            result.get('cpe'), result.get('reason'),
            result.get('reason_ttl'), result.get('confidence'),
            result.get('scripts_json'), result.get('discovery_method'),
            result.get('discovered_at', datetime.now().isoformat())
        ))

        new_id = cursor.lastrowid
        if old_id is not None and new_id:
            sr_id_map[old_id] = new_id
        elif old_id is not None:
            # La fila ya existía (INSERT OR IGNORE no hizo nada): recuperar ID real
            row = cursor.execute("""
                SELECT id FROM scan_results
                WHERE scan_id=? AND host_id=?
                  AND port IS ? AND protocol IS ?
            """, (new_scan_id, new_host_id,
                  result.get('port'), result.get('protocol'))).fetchone()
            if row:
                sr_id_map[old_id] = row[0]

        import_stats['scan_results'] += 1

    # ------------------------------------------------------------------ #
    # 4. VULNERABILIDADES — columnas correctas + remapping sr_id          #
    # ------------------------------------------------------------------ #
    for vuln in export_data.get('vulnerabilities', []):
        old_sr_id = vuln.get('scan_result_id')
        new_sr_id = sr_id_map.get(old_sr_id, old_sr_id)

        if not new_sr_id:
            continue

        cursor.execute("""
            INSERT OR IGNORE INTO vulnerabilities
                (scan_result_id, vulnerability_id, vulnerability_name, severity,
                 description, cve_id, cvss_score, script_source, script_output,
                 discovered_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            new_sr_id,
            vuln.get('vulnerability_id'),
            vuln.get('vulnerability_name') or vuln.get('title'),   # compatibilidad legada
            vuln.get('severity'),
            vuln.get('description'),
            vuln.get('cve_id') or vuln.get('references'),          # compatibilidad legada
            vuln.get('cvss_score'),
            vuln.get('script_source'),
            vuln.get('script_output'),
            vuln.get('discovered_at', datetime.now().isoformat())
        ))
        import_stats['vulnerabilities'] += 1

    # ------------------------------------------------------------------ #
    # 5. ENRICHMENTS — remapping sr_id                                    #
    # ------------------------------------------------------------------ #
    for enrich in export_data.get('enrichments', []):
        old_sr_id = enrich.get('scan_result_id')
        new_sr_id = sr_id_map.get(old_sr_id, old_sr_id)

        if not new_sr_id:
            continue

        created_at = enrich.get('created_at') or enrich.get('discovered_at') or datetime.now().isoformat()
        cursor.execute("""
            INSERT OR IGNORE INTO enrichments
                (scan_result_id, enrichment_type, data, file_path, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            new_sr_id,
            enrich.get('enrichment_type'),
            enrich.get('data'),
            enrich.get('file_path'),
            created_at
        ))
        import_stats['enrichments'] += 1

    # ------------------------------------------------------------------ #
    # 6. PASSIVE_CONVERSATIONS — remapping scan_id                        #
    # ------------------------------------------------------------------ #
    passive_count = 0
    for conv in export_data.get('passive_conversations', []):
        old_scan_id = conv.get('scan_id')
        new_scan_id = scan_id_map.get(old_scan_id, old_scan_id)

        if not new_scan_id:
            continue

        cursor.execute("""
            INSERT OR IGNORE INTO passive_conversations
                (scan_id, src_ip, src_mac, src_port,
                 dst_ip, dst_mac, dst_port, protocol, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            new_scan_id,
            conv.get('src_ip'), conv.get('src_mac'), conv.get('src_port'),
            conv.get('dst_ip'), conv.get('dst_mac'), conv.get('dst_port'),
            conv.get('protocol'), conv.get('last_seen')
        ))
        passive_count += 1

    if passive_count:
        import_stats['passive_conversations'] = passive_count

    # ------------------------------------------------------------------ #
    # 7. HOST_SCAN_METADATA — remapping scan_id y host_id                 #
    # ------------------------------------------------------------------ #
    for meta in export_data.get('host_scan_metadata', []):
        old_scan_id = meta.get('scan_id')
        old_host_id = meta.get('host_id')
        new_scan_id = scan_id_map.get(old_scan_id, old_scan_id)
        new_host_id = host_id_map.get(old_host_id, old_host_id)

        if not new_scan_id or not new_host_id:
            continue

        cursor.execute("""
            INSERT INTO host_scan_metadata
                (scan_id, host_id, hostname, hostnames_json, mac_address, vendor,
                 os_info_json, host_scripts_json, interfaces_json, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(scan_id, host_id) DO UPDATE SET
                hostname          = COALESCE(excluded.hostname,          hostname),
                hostnames_json    = COALESCE(excluded.hostnames_json,    hostnames_json),
                mac_address       = COALESCE(excluded.mac_address,       mac_address),
                vendor            = COALESCE(excluded.vendor,            vendor),
                os_info_json      = COALESCE(excluded.os_info_json,      os_info_json),
                host_scripts_json = COALESCE(excluded.host_scripts_json, host_scripts_json),
                interfaces_json   = COALESCE(excluded.interfaces_json,   interfaces_json),
                last_seen         = COALESCE(excluded.last_seen,         last_seen)
        """, (
            new_scan_id, new_host_id,
            meta.get('hostname'), meta.get('hostnames_json'),
            meta.get('mac_address'), meta.get('vendor'),
            meta.get('os_info_json'), meta.get('host_scripts_json'),
            meta.get('interfaces_json'), meta.get('last_seen')
        ))


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

    # Importar auditorías PwnDoc (mapping org → audit_id)
    for pw in export_data.get('pwndoc_audits', []):
        if not pw.get('org_name') or not pw.get('audit_id'):
            continue
        cursor.execute("""
            INSERT INTO pwndoc_audits (org_name, audit_id, created_at)
            VALUES (UPPER(?), ?, ?)
            ON CONFLICT(org_name) DO UPDATE SET audit_id = excluded.audit_id
        """, (
            pw['org_name'], pw['audit_id'],
            pw.get('created_at') or datetime.now().isoformat()
        ))
        if 'pwndoc_audits' not in import_stats:
            import_stats['pwndoc_audits'] = 0
        import_stats['pwndoc_audits'] += 1

