"""
Funciones de exportación e importación de datos de escaneos
"""

import sqlite3
import json
import zipfile
import shutil
import tempfile
import base64
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, List, Any
from arsenal.core.storage import ScanStorage


SCAN_EXPORT_COLUMNS = (
    "id",
    "organization_name",
    "location",
    "scan_type",
    "target_range",
    "interface",
    "myip",
    "nmap_command",
    "started_at",
    "completed_at",
    "status",
    "hosts_discovered",
    "ports_found",
    "error_message",
    "created_by",
    "enable_version_detection",
    "enable_vulnerability_scan",
    "enable_screenshots",
    "enable_source_code",
    "scan_mode",
)


def _fetch_rows(cursor, query: str, params: tuple = ()) -> List[Dict]:
    """Ejecuta una query opcional y devuelve filas como dict sin romper exports antiguos."""
    try:
        return [dict(row) for row in cursor.execute(query, params).fetchall()]
    except sqlite3.OperationalError:
        return []


def _export_scan_row(row) -> Dict:
    """Serializa un escaneo sin campos de capacidades retiradas."""
    scan = dict(row)
    return {
        key: scan.get(key)
        for key in SCAN_EXPORT_COLUMNS
        if key in scan
    }


def _collect_pwndoc_export(cursor, org_names: List[str]) -> Dict:
    """Crea una instantanea portable de auditorias PwnDoc para las organizaciones."""
    clean_orgs = sorted({(org or "").strip().upper() for org in org_names if org})
    if not clean_orgs:
        return {"audits": [], "errors": []}

    placeholders = ",".join("?" * len(clean_orgs))
    mappings = _fetch_rows(
        cursor,
        f"SELECT * FROM pwndoc_audits WHERE UPPER(org_name) IN ({placeholders})",
        tuple(clean_orgs),
    )
    markers = _fetch_rows(
        cursor,
        f"SELECT * FROM arsenalot_pwndoc_findings WHERE UPPER(org_name) IN ({placeholders})",
        tuple(clean_orgs),
    )
    marker_ids = {
        (row.get("org_name") or "").strip().upper(): set()
        for row in markers
    }
    for row in markers:
        marker_ids.setdefault((row.get("org_name") or "").strip().upper(), set()).add(str(row.get("finding_id")))

    snapshots = []
    errors = []
    try:
        from arsenal.core.pwndoc_client import PwnDocClient
        client = PwnDocClient()
        for mapping in mappings:
            org_name = (mapping.get("org_name") or "").strip().upper()
            audit_id = str(mapping.get("audit_id") or "")
            if not org_name or not audit_id:
                continue
            try:
                audit = client.get_audit(audit_id)
                if not audit:
                    errors.append(f"{org_name}: auditoria PwnDoc {audit_id} no encontrada")
                    continue
                findings = []
                for finding in audit.get("findings", []) or []:
                    source_id = str(finding.get("_id") or finding.get("id") or "")
                    findings.append({
                        "source_id": source_id,
                        "arsenalot_added": source_id in marker_ids.get(org_name, set()),
                        "title": finding.get("title") or "",
                        "description": finding.get("description") or "",
                        "observation": finding.get("observation") or "",
                        "remediation": finding.get("remediation") or "",
                        "cvssv3": finding.get("cvssv3") or "",
                        "vulnType": finding.get("vulnType") or "",
                        "category": finding.get("category") or "",
                        "references": finding.get("references") or [],
                        "poc": finding.get("poc") or "",
                        "status": finding.get("status", 0),
                    })
                snapshots.append({
                    "org_name": org_name,
                    "source_audit_id": audit_id,
                    "audit_name": audit.get("name") or org_name,
                    "audit_type": audit.get("auditType") or audit.get("audit_type") or "",
                    "language": audit.get("language") or "es",
                    "scope": _normalize_pwndoc_scope(audit.get("scope") or []),
                    "date_start": audit.get("date_start") or audit.get("dateStart") or "",
                    "date_end": audit.get("date_end") or audit.get("dateEnd") or "",
                    "findings": findings,
                })
            except Exception as exc:
                errors.append(f"{org_name}: {exc}")
    except Exception as exc:
        errors.append(f"PwnDoc no disponible durante exportacion: {exc}")

    return {"audits": snapshots, "errors": errors}


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
            if (scan['scan_mode'] or 'active') == 'passive':
                conn.close()
                raise ValueError(f"Escaneo {scan_id} no exportable")

            scan_results = cursor.execute(
                "SELECT * FROM scan_results WHERE scan_id = ?", (scan_id,)
            ).fetchall()
            host_ids      = list(set(r['host_id'] for r in scan_results))
            sr_ids        = [r['id'] for r in scan_results]
            ph_h          = ','.join('?' * len(host_ids))  if host_ids else '0'
            ph_sr         = ','.join('?' * len(sr_ids))    if sr_ids   else '0'

            org_rec = cursor.execute("SELECT * FROM organizations WHERE name = ?", (scan['organization_name'],)).fetchone()
            pwndoc_rows = cursor.execute("SELECT * FROM pwndoc_audits WHERE UPPER(org_name) = UPPER(?)", (scan['organization_name'],)).fetchall()
            arsenalot_pwndoc_rows = _fetch_rows(cursor, "SELECT * FROM arsenalot_pwndoc_findings WHERE UPPER(org_name) = UPPER(?)", (scan['organization_name'],))
            pwndoc_export = _collect_pwndoc_export(cursor, [scan['organization_name']])

            export_data = {
                'type': 'scan',
                'scan_id': scan_id,
                'metadata': _export_scan_row(scan),
                'organization_record':  dict(org_rec) if org_rec else None,
                'scans': [_export_scan_row(scan)],
                'scan_results':         [dict(r) for r in scan_results],
                'hosts':                [dict(h) for h in cursor.execute(f"SELECT * FROM hosts WHERE id IN ({ph_h})", host_ids).fetchall()] if host_ids else [],
                'host_scan_metadata':   [dict(h) for h in cursor.execute("SELECT * FROM host_scan_metadata WHERE scan_id = ?", (scan_id,)).fetchall()],
                'vulnerabilities':      [dict(v) for v in cursor.execute(f"SELECT * FROM vulnerabilities WHERE scan_result_id IN ({ph_sr})", sr_ids).fetchall()] if sr_ids else [],
                'enrichments':          [dict(e) for e in cursor.execute(f"SELECT * FROM enrichments WHERE scan_result_id IN ({ph_sr})", sr_ids).fetchall()] if sr_ids else [],
                'networks':             [dict(n) for n in cursor.execute("SELECT * FROM networks WHERE organization_name = ?", (scan['organization_name'],)).fetchall()],
                'critical_devices':     [dict(d) for d in cursor.execute("SELECT * FROM critical_devices WHERE organization_name = ?", (scan['organization_name'],)).fetchall()],
                'network_devices':      [dict(d) for d in cursor.execute("SELECT * FROM network_devices WHERE organization_name = ?", (scan['organization_name'],)).fetchall()],
                'pwndoc_audits':        [dict(p) for p in pwndoc_rows],
                'arsenalot_pwndoc_findings': arsenalot_pwndoc_rows,
                'pwndoc_export':         pwndoc_export,
            }

            zipf.writestr('export_data.json', json.dumps(export_data, indent=2, default=str))

            scan_dir = storage.get_scan_directory(scan['organization_name'], scan['location'], scan_id)
            if scan_dir.exists():
                _add_directory_to_zip(zipf, scan_dir, f"scans/{scan_dir.name}")
            _add_bitacora_org_to_zip(zipf, storage, scan['organization_name'])

        elif location and organization:
            scans = cursor.execute(
                """
                SELECT * FROM scans
                WHERE organization_name = ? AND location = ?
                  AND COALESCE(scan_mode, 'active') != 'passive'
                """,
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
            arsenalot_pwndoc_rows = _fetch_rows(cursor, "SELECT * FROM arsenalot_pwndoc_findings WHERE UPPER(org_name) = UPPER(?)", (organization.upper(),))
            pwndoc_export = _collect_pwndoc_export(cursor, [organization.upper()])

            export_data = {
                'type': 'location',
                'organization': organization.upper(),
                'organization_record':  dict(org_rec) if org_rec else None,
                'location': location.upper(),
                'scans':                [_export_scan_row(s) for s in scans],
                'scan_results':         [dict(r) for r in scan_results],
                'hosts':                [dict(h) for h in cursor.execute(f"SELECT * FROM hosts WHERE id IN ({ph_h})", host_ids).fetchall()] if host_ids else [],
                'host_scan_metadata':   [dict(h) for h in cursor.execute(f"SELECT * FROM host_scan_metadata WHERE scan_id IN ({ph_s})", scan_ids).fetchall()] if scan_ids else [],
                'vulnerabilities':      [dict(v) for v in cursor.execute(f"SELECT * FROM vulnerabilities WHERE scan_result_id IN ({ph_sr})", sr_ids).fetchall()] if sr_ids else [],
                'enrichments':          [dict(e) for e in cursor.execute(f"SELECT * FROM enrichments WHERE scan_result_id IN ({ph_sr})", sr_ids).fetchall()] if sr_ids else [],
                'networks':             [dict(n) for n in cursor.execute("SELECT * FROM networks WHERE organization_name = ?", (organization.upper(),)).fetchall()],
                'critical_devices':     [dict(d) for d in cursor.execute("SELECT * FROM critical_devices WHERE organization_name = ?", (organization.upper(),)).fetchall()],
                'network_devices':      [dict(d) for d in cursor.execute("SELECT * FROM network_devices WHERE organization_name = ?", (organization.upper(),)).fetchall()],
                'pwndoc_audits':        [dict(p) for p in pwndoc_rows],
                'arsenalot_pwndoc_findings': arsenalot_pwndoc_rows,
                'pwndoc_export':         pwndoc_export,
            }

            zipf.writestr('export_data.json', json.dumps(export_data, indent=2, default=str))

            location_dir = storage.results_root / organization.upper() / location.upper()
            if location_dir.exists():
                _add_directory_to_zip(zipf, location_dir, f"{organization.upper()}/{location.upper()}")
            _add_bitacora_org_to_zip(zipf, storage, organization.upper())

        elif organization:
            org_data = cursor.execute("SELECT * FROM organizations WHERE name = ?", (organization.upper(),)).fetchone()
            scans    = cursor.execute(
                """
                SELECT * FROM scans
                WHERE organization_name = ?
                  AND COALESCE(scan_mode, 'active') != 'passive'
                """,
                (organization.upper(),)
            ).fetchall()
            scan_ids = [s['id'] for s in scans]
            ph_s     = ','.join('?' * len(scan_ids)) if scan_ids else '0'

            scan_results = cursor.execute(f"SELECT * FROM scan_results WHERE scan_id IN ({ph_s})", scan_ids).fetchall() if scan_ids else []
            host_ids     = list(set(r['host_id'] for r in scan_results))
            sr_ids       = [r['id'] for r in scan_results]
            ph_h         = ','.join('?' * len(host_ids)) if host_ids else '0'
            ph_sr        = ','.join('?' * len(sr_ids))   if sr_ids   else '0'

            pwndoc_rows = cursor.execute("SELECT * FROM pwndoc_audits WHERE UPPER(org_name) = UPPER(?)", (organization.upper(),)).fetchall()
            arsenalot_pwndoc_rows = _fetch_rows(cursor, "SELECT * FROM arsenalot_pwndoc_findings WHERE UPPER(org_name) = UPPER(?)", (organization.upper(),))
            pwndoc_export = _collect_pwndoc_export(cursor, [organization.upper()])

            export_data = {
                'type': 'organization',
                'organization':         dict(org_data) if org_data else None,
                'scans':                [_export_scan_row(s) for s in scans],
                'scan_results':         [dict(r) for r in scan_results],
                'hosts':                [dict(h) for h in cursor.execute(f"SELECT * FROM hosts WHERE id IN ({ph_h})", host_ids).fetchall()] if host_ids else [],
                'host_scan_metadata':   [dict(h) for h in cursor.execute(f"SELECT * FROM host_scan_metadata WHERE scan_id IN ({ph_s})", scan_ids).fetchall()] if scan_ids else [],
                'vulnerabilities':      [dict(v) for v in cursor.execute(f"SELECT * FROM vulnerabilities WHERE scan_result_id IN ({ph_sr})", sr_ids).fetchall()] if sr_ids else [],
                'enrichments':          [dict(e) for e in cursor.execute(f"SELECT * FROM enrichments WHERE scan_result_id IN ({ph_sr})", sr_ids).fetchall()] if sr_ids else [],
                'networks':             [dict(n) for n in cursor.execute("SELECT * FROM networks WHERE organization_name = ?", (organization.upper(),)).fetchall()],
                'critical_devices':     [dict(d) for d in cursor.execute("SELECT * FROM critical_devices WHERE organization_name = ?", (organization.upper(),)).fetchall()],
                'network_devices':      [dict(d) for d in cursor.execute("SELECT * FROM network_devices WHERE organization_name = ?", (organization.upper(),)).fetchall()],
                'pwndoc_audits':        [dict(p) for p in pwndoc_rows],
                'arsenalot_pwndoc_findings': arsenalot_pwndoc_rows,
                'pwndoc_export':         pwndoc_export,
            }

            zipf.writestr('export_data.json', json.dumps(export_data, indent=2, default=str))

            org_dir = storage.results_root / organization.upper()
            if org_dir.exists():
                _add_directory_to_zip(zipf, org_dir, organization.upper())
            _add_bitacora_org_to_zip(zipf, storage, organization.upper())

        else:
            # Exportar todo
            organizations = cursor.execute("SELECT * FROM organizations").fetchall()
            organization_names = [o['name'] for o in organizations]
            scans         = cursor.execute("SELECT * FROM scans WHERE COALESCE(scan_mode, 'active') != 'passive'").fetchall()
            scan_ids      = [s['id'] for s in scans]
            ph_s          = ','.join('?' * len(scan_ids)) if scan_ids else '0'
            scan_results  = cursor.execute(f"SELECT * FROM scan_results WHERE scan_id IN ({ph_s})", scan_ids).fetchall() if scan_ids else []
            host_ids      = list(set(r['host_id'] for r in scan_results))
            ph_h          = ','.join('?' * len(host_ids)) if host_ids else '0'
            sr_ids        = [r['id'] for r in scan_results]
            ph_sr         = ','.join('?' * len(sr_ids)) if sr_ids else '0'

            export_data = {
                'type': 'all',
                'organizations':        [dict(o) for o in organizations],
                'scans':                [_export_scan_row(s) for s in scans],
                'scan_results':         [dict(r) for r in scan_results],
                'hosts':                [dict(h) for h in cursor.execute(f"SELECT * FROM hosts WHERE id IN ({ph_h})", host_ids).fetchall()] if host_ids else [],
                'host_scan_metadata':   [dict(h) for h in cursor.execute(f"SELECT * FROM host_scan_metadata WHERE scan_id IN ({ph_s})", scan_ids).fetchall()] if scan_ids else [],
                'vulnerabilities':      [dict(v) for v in cursor.execute(f"SELECT * FROM vulnerabilities WHERE scan_result_id IN ({ph_sr})", sr_ids).fetchall()] if sr_ids else [],
                'enrichments':          [dict(e) for e in cursor.execute(f"SELECT * FROM enrichments WHERE scan_result_id IN ({ph_sr})", sr_ids).fetchall()] if sr_ids else [],
                'networks':             [dict(n) for n in cursor.execute("SELECT * FROM networks").fetchall()],
                'critical_devices':     [dict(d) for d in cursor.execute("SELECT * FROM critical_devices").fetchall()],
                'network_devices':      [dict(d) for d in cursor.execute("SELECT * FROM network_devices").fetchall()],
                'pwndoc_audits':        [dict(p) for p in cursor.execute("SELECT * FROM pwndoc_audits").fetchall()],
                'arsenalot_pwndoc_findings': _fetch_rows(cursor, "SELECT * FROM arsenalot_pwndoc_findings"),
                'pwndoc_export':         _collect_pwndoc_export(cursor, organization_names),
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


def _normalize_org_name(org_name: Optional[str]) -> Optional[str]:
    normalized = (org_name or "").strip().upper()
    return normalized or None


def _is_missing(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str) and not value.strip():
        return True
    return False


def _sql_value_matches(column: str) -> str:
    return f"(({column} IS NULL AND ? IS NULL) OR {column} = ?)"


def _update_missing_fields(cursor, table: str, id_value: int,
                           data: Dict, fields: List[str],
                           id_column: str = "id") -> int:
    """Rellena columnas vacias de una fila existente sin pisar datos locales."""
    if not fields:
        return 0

    row = cursor.execute(
        f"SELECT {', '.join(fields)} FROM {table} WHERE {id_column} = ?",
        (id_value,)
    ).fetchone()
    if not row:
        return 0

    updates = []
    params = []
    for field in fields:
        current = row[field] if hasattr(row, "keys") else row[fields.index(field)]
        incoming = data.get(field)
        if _is_missing(current) and not _is_missing(incoming):
            updates.append(f"{field} = ?")
            params.append(incoming)

    if not updates:
        return 0

    params.append(id_value)
    cursor.execute(
        f"UPDATE {table} SET {', '.join(updates)} WHERE {id_column} = ?",
        tuple(params)
    )
    return cursor.rowcount


def _merge_unique_list(existing: List[Any], incoming: List[Any]) -> List[Any]:
    merged = []
    seen = set()
    for value in list(existing or []) + list(incoming or []):
        if value is None:
            continue
        key = str(value).strip()
        if not key or key in seen:
            continue
        seen.add(key)
        merged.append(value)
    return merged


def _json_list(value: Any) -> List[Any]:
    if _is_missing(value):
        return []
    if isinstance(value, list):
        return value
    try:
        decoded = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return []
    return decoded if isinstance(decoded, list) else [decoded]


def _csv_list(value: Any) -> List[str]:
    if _is_missing(value):
        return []
    return [item.strip() for item in str(value).split(",") if item.strip()]


def _merge_csv(existing: Any, incoming: Any) -> Optional[str]:
    merged = _merge_unique_list(_csv_list(existing), _csv_list(incoming))
    return ", ".join(merged) if merged else None


def _merge_json_lists(existing: Any, incoming: Any) -> Optional[str]:
    merged = _merge_unique_list(_json_list(existing), _json_list(incoming))
    return json.dumps(merged) if merged else None


def _ensure_organization_incremental(cursor, org_name: Optional[str],
                                     description: Optional[str] = None,
                                     created_at: Optional[str] = None) -> bool:
    """Crea la organizacion si falta; si existe solo rellena campos vacios."""
    normalized = _normalize_org_name(org_name)
    if not normalized:
        return False

    cursor.execute("""
        INSERT OR IGNORE INTO organizations (name, description, created_at)
        VALUES (?, ?, ?)
    """, (normalized, description, created_at or datetime.now().isoformat()))
    inserted = cursor.rowcount > 0
    if not inserted:
        _update_missing_fields(cursor, "organizations", normalized, {
            "description": description,
            "created_at": created_at,
        }, ["description", "created_at"], id_column="name")
    return True


def _scan_identity(scan: Dict) -> Dict[str, Any]:
    return {
        "organization_name": _normalize_org_name(scan.get("organization_name")) or "",
        "location": (scan.get("location") or "").strip().upper(),
        "scan_type": scan.get("scan_type") or "mixed",
        "target_range": scan.get("target_range") or "",
        "started_at": scan.get("started_at"),
        "scan_mode": scan.get("scan_mode") or "active",
    }


def _find_existing_scan(cursor, scan: Dict) -> Optional[int]:
    identity = _scan_identity(scan)
    if not identity["organization_name"] or not identity["location"] or _is_missing(identity["started_at"]):
        return None

    row = cursor.execute("""
        SELECT id FROM scans
        WHERE organization_name = ?
          AND location = ?
          AND scan_type = ?
          AND target_range = ?
          AND started_at = ?
          AND COALESCE(scan_mode, 'active') = COALESCE(?, 'active')
        ORDER BY id
        LIMIT 1
    """, (
        identity["organization_name"],
        identity["location"],
        identity["scan_type"],
        identity["target_range"],
        identity["started_at"],
        identity["scan_mode"],
    )).fetchone()
    return row["id"] if row else None


def _update_existing_scan_missing(cursor, scan_id: int, scan: Dict) -> int:
    updated = _update_missing_fields(cursor, "scans", scan_id, scan, [
        "interface", "myip", "nmap_command", "completed_at", "error_message",
        "created_by", "scan_mode",
    ])

    row = cursor.execute("""
        SELECT hosts_discovered, ports_found, enable_version_detection,
               enable_vulnerability_scan, enable_screenshots, enable_source_code
        FROM scans WHERE id = ?
    """, (scan_id,)).fetchone()
    if not row:
        return updated

    updates = []
    params = []
    for field in ("hosts_discovered", "ports_found"):
        incoming = scan.get(field)
        if incoming not in (None, "") and int(row[field] or 0) == 0 and int(incoming or 0) > 0:
            updates.append(f"{field} = ?")
            params.append(incoming)
    for field in ("enable_version_detection", "enable_vulnerability_scan",
                  "enable_screenshots", "enable_source_code"):
        incoming = scan.get(field)
        if incoming in (1, True, "1", "true", "True") and not row[field]:
            updates.append(f"{field} = ?")
            params.append(incoming)

    if updates:
        params.append(scan_id)
        cursor.execute(f"UPDATE scans SET {', '.join(updates)} WHERE id = ?", tuple(params))
        updated += cursor.rowcount
    return updated


def _find_scan_result_id(cursor, scan_id: int, host_id: int,
                         port: Any, protocol: Any) -> Optional[int]:
    row = cursor.execute(f"""
        SELECT id FROM scan_results
        WHERE scan_id = ?
          AND host_id = ?
          AND {_sql_value_matches('port')}
          AND {_sql_value_matches('protocol')}
        ORDER BY id
        LIMIT 1
    """, (scan_id, host_id, port, port, protocol, protocol)).fetchone()
    return row["id"] if row else None


def _find_vulnerability_id(cursor, scan_result_id: int, vuln: Dict) -> Optional[int]:
    row = cursor.execute("""
        SELECT id FROM vulnerabilities
        WHERE scan_result_id = ?
          AND COALESCE(vulnerability_id, '') = COALESCE(?, '')
          AND COALESCE(vulnerability_name, '') = COALESCE(?, '')
          AND COALESCE(cve_id, '') = COALESCE(?, '')
          AND COALESCE(script_source, '') = COALESCE(?, '')
          AND COALESCE(script_output, '') = COALESCE(?, '')
        ORDER BY id
        LIMIT 1
    """, (
        scan_result_id,
        vuln.get("vulnerability_id"),
        vuln.get("vulnerability_name") or vuln.get("title"),
        vuln.get("cve_id") or vuln.get("references"),
        vuln.get("script_source"),
        vuln.get("script_output"),
    )).fetchone()
    return row["id"] if row else None


def _find_enrichment_id(cursor, scan_result_id: int, enrich: Dict) -> Optional[int]:
    enrichment_type = enrich.get("enrichment_type")
    data = enrich.get("data")
    if not _is_missing(data):
        row = cursor.execute("""
            SELECT id FROM enrichments
            WHERE scan_result_id = ?
              AND COALESCE(enrichment_type, '') = COALESCE(?, '')
              AND COALESCE(data, '') = COALESCE(?, '')
            ORDER BY id
            LIMIT 1
        """, (scan_result_id, enrichment_type, data)).fetchone()
        if row:
            return row["id"]

    file_path = enrich.get("file_path")
    file_name = Path(file_path).name if file_path else None
    if file_name:
        row = cursor.execute("""
            SELECT id FROM enrichments
            WHERE scan_result_id = ?
              AND COALESCE(enrichment_type, '') = COALESCE(?, '')
              AND file_path LIKE ?
            ORDER BY id
            LIMIT 1
        """, (scan_result_id, enrichment_type, f"%{file_name}")).fetchone()
        if row:
            return row["id"]

    row = cursor.execute("""
        SELECT id FROM enrichments
        WHERE scan_result_id = ?
          AND COALESCE(enrichment_type, '') = COALESCE(?, '')
        ORDER BY id
        LIMIT 1
    """, (scan_result_id, enrichment_type)).fetchone()
    return row["id"] if row else None


def _add_bitacora_org_to_zip(zipf: zipfile.ZipFile, storage: ScanStorage, org_name: Optional[str]):
    """Incluye la bitacora Obsidian de la organizacion en exports filtrados."""
    normalized = _normalize_org_name(org_name)
    if not normalized:
        return

    bitacora_dir = storage.results_root / "bitacora" / "Organizaciones" / normalized
    if bitacora_dir.exists():
        _add_directory_to_zip(zipf, bitacora_dir, f"bitacora/Organizaciones/{normalized}")


def _get_export_org_names(export_data: Dict) -> List[str]:
    export_type = export_data.get("type")
    org_names = []

    if export_type == "all":
        for org in export_data.get("organizations", []):
            org_names.append(org.get("name"))
    elif export_type == "organization":
        org = export_data.get("organization")
        org_names.append(org.get("name") if isinstance(org, dict) else org)
    elif export_type == "location":
        org_names.append(export_data.get("organization"))
    elif export_type == "scan":
        metadata = export_data.get("metadata") or {}
        org_names.append(metadata.get("organization_name"))

    normalized = []
    for org_name in org_names:
        org = _normalize_org_name(org_name)
        if org and org not in normalized:
            normalized.append(org)
    return normalized


def _import_bitacora_org_files(storage: ScanStorage, temp_path: Path,
                               export_data: Dict, import_stats: Dict):
    """Restaura la bitacora Obsidian incluida en el ZIP, si existe."""
    for org_name in _get_export_org_names(export_data):
        source_dir = temp_path / "bitacora" / "Organizaciones" / org_name
        if not source_dir.exists():
            continue

        dest_dir = storage.results_root / "bitacora" / "Organizaciones" / org_name
        dest_dir.parent.mkdir(parents=True, exist_ok=True)
        if dest_dir.exists():
            _merge_directory(source_dir, dest_dir, merge_text=True)
        else:
            shutil.copytree(source_dir, dest_dir)
        import_stats["bitacora_files_imported"] = import_stats.get("bitacora_files_imported", 0) + 1


def _scan_dir_id(scan_dir_name: str) -> Optional[int]:
    if not scan_dir_name.startswith("scan_"):
        return None
    parts = scan_dir_name.split("_", 2)
    if len(parts) < 2 or not parts[1].isdigit():
        return None
    return int(parts[1])


def _build_exported_scan_dir_index(temp_path: Path) -> Dict[int, List[Path]]:
    index: Dict[int, List[Path]] = {}
    for scan_dir in temp_path.rglob("scan_*"):
        if not scan_dir.is_dir():
            continue
        scan_id = _scan_dir_id(scan_dir.name)
        if scan_id is None:
            continue
        index.setdefault(scan_id, []).append(scan_dir)
    return index


def _evidence_subdir(enrichment_type: Optional[str]) -> Optional[str]:
    etype = (enrichment_type or "").strip().lower()
    if etype == "screenshot":
        return "img"
    if etype in ("websource", "source", "source_code"):
        return "source"
    return None


def _scan_relative_tail(file_path: Optional[str], old_scan_id: Optional[int]) -> Optional[Path]:
    if not file_path:
        return None

    path = Path(file_path)
    parts = list(path.parts)
    old_prefix = f"scan_{old_scan_id:06d}" if old_scan_id is not None else None

    for idx, part in enumerate(parts):
        if part.startswith("scan_") and (old_prefix is None or part.startswith(old_prefix)):
            tail_parts = parts[idx + 1:]
            return Path(*tail_parts) if tail_parts else None

    if "evidence" in parts:
        idx = parts.index("evidence")
        return Path(*parts[idx:])

    return None


def _scan_timestamp_suffix(scan: Dict, old_scan_dir: Optional[Path],
                           old_scan_id: int) -> str:
    old_prefix = f"scan_{old_scan_id:06d}"
    if old_scan_dir and old_scan_dir.name.startswith(old_prefix):
        suffix = old_scan_dir.name[len(old_prefix):]
        if suffix:
            return suffix

    raw_timestamp = scan.get("started_at") or scan.get("created_at")
    if raw_timestamp:
        try:
            parsed = datetime.fromisoformat(str(raw_timestamp).replace("Z", "+00:00"))
            return f"_{parsed.strftime('%Y%m%d_%H%M%S')}"
        except ValueError:
            pass

    return f"_{datetime.now().strftime('%Y%m%d_%H%M%S')}"


def _new_scan_dir(storage: ScanStorage, scan: Dict, old_scan_dir: Optional[Path],
                  old_scan_id: int, new_scan_id: int) -> Path:
    org_name = _normalize_org_name(scan.get("organization_name")) or "UNKNOWN"
    location = (scan.get("location") or "UNKNOWN").strip().upper()
    suffix = _scan_timestamp_suffix(scan, old_scan_dir, old_scan_id)
    return storage.results_root / org_name / location / "scans" / f"scan_{new_scan_id:06d}{suffix}"


def _find_source_evidence_file(temp_path: Path, scan_dirs: List[Path],
                               old_scan_id: Optional[int], file_path: Optional[str],
                               enrichment_type: Optional[str]) -> tuple[Optional[Path], Optional[Path], Optional[Path]]:
    if not file_path:
        return None, None, None

    tail = _scan_relative_tail(file_path, old_scan_id)
    file_name = Path(file_path).name
    subdir = _evidence_subdir(enrichment_type)

    for scan_dir in scan_dirs:
        candidates = []
        if tail:
            candidates.append(scan_dir / tail)
        if subdir and file_name:
            candidates.append(scan_dir / "evidence" / subdir / file_name)
        for candidate in candidates:
            if candidate.exists() and candidate.is_file():
                return candidate, scan_dir, candidate.relative_to(scan_dir)

    raw_path = Path(file_path)
    if not raw_path.is_absolute():
        direct_candidate = temp_path / raw_path
        if direct_candidate.exists() and direct_candidate.is_file():
            scan_dir = next((parent for parent in direct_candidate.parents
                             if _scan_dir_id(parent.name) == old_scan_id), None)
            rel_tail = direct_candidate.relative_to(scan_dir) if scan_dir else tail
            return direct_candidate, scan_dir, rel_tail

    if file_name:
        for candidate in temp_path.rglob(file_name):
            if not candidate.is_file():
                continue
            scan_dir = next((parent for parent in candidate.parents
                             if _scan_dir_id(parent.name) == old_scan_id), None)
            if scan_dir or not scan_dirs:
                rel_tail = candidate.relative_to(scan_dir) if scan_dir else tail
                return candidate, scan_dir, rel_tail

    return None, None, tail


def _write_enrichment_data_file(enrich: Dict, dest_file: Path) -> bool:
    data = enrich.get("data")
    if not data:
        return False

    dest_file.parent.mkdir(parents=True, exist_ok=True)
    etype = (enrich.get("enrichment_type") or "").strip().lower()
    try:
        if etype == "screenshot":
            raw_data = str(data)
            if "," in raw_data and raw_data.lower().startswith("data:"):
                raw_data = raw_data.split(",", 1)[1]
            dest_file.write_bytes(base64.b64decode(raw_data))
        else:
            dest_file.write_text(str(data), encoding="utf-8")
        return True
    except Exception as exc:
        print(f"⚠️ No se pudo reconstruir evidencia {dest_file}: {exc}")
        return False


def _restore_imported_evidence_files(storage: ScanStorage, temp_path: Path,
                                     export_data: Dict, cursor,
                                     import_stats: Dict):
    """
    Restaura evidencias bajo los nuevos IDs de escaneo y actualiza
    enrichments.file_path para que resultados y bitacora apunten al destino real.
    """
    scan_id_map = import_stats.get("_scan_id_map_int", {})
    sr_id_map = import_stats.get("_sr_id_map_int", {})
    if not scan_id_map or not sr_id_map:
        return

    scans = export_data.get("scans", [])
    if not scans and export_data.get("metadata"):
        scans = [export_data["metadata"]]
    scans_by_old_id = {scan.get("id"): scan for scan in scans if scan.get("id") is not None}
    scan_results_by_old_id = {
        result.get("id"): result
        for result in export_data.get("scan_results", [])
        if result.get("id") is not None
    }
    exported_scan_dirs = _build_exported_scan_dir_index(temp_path)
    copied_scan_dirs = set()

    for enrich in export_data.get("enrichments", []):
        old_sr_id = enrich.get("scan_result_id")
        old_result = scan_results_by_old_id.get(old_sr_id)
        new_sr_id = sr_id_map.get(old_sr_id)
        if not old_result or not new_sr_id:
            continue

        old_scan_id = old_result.get("scan_id")
        new_scan_id = scan_id_map.get(old_scan_id)
        scan = scans_by_old_id.get(old_scan_id)
        if not old_scan_id or not new_scan_id or not scan:
            continue

        file_path = enrich.get("file_path")
        subdir = _evidence_subdir(enrich.get("enrichment_type"))
        if not file_path or not subdir:
            continue

        scan_dirs = exported_scan_dirs.get(old_scan_id, [])
        src_file, old_scan_dir, rel_tail = _find_source_evidence_file(
            temp_path, scan_dirs, old_scan_id, file_path, enrich.get("enrichment_type")
        )
        dest_scan_dir = _new_scan_dir(storage, scan, old_scan_dir, old_scan_id, new_scan_id)

        if old_scan_dir and old_scan_dir.exists() and dest_scan_dir not in copied_scan_dirs:
            dest_scan_dir.parent.mkdir(parents=True, exist_ok=True)
            if dest_scan_dir.exists():
                _merge_directory(old_scan_dir, dest_scan_dir)
            else:
                shutil.copytree(old_scan_dir, dest_scan_dir)
            copied_scan_dirs.add(dest_scan_dir)
            import_stats["evidence_scan_dirs_copied"] = import_stats.get("evidence_scan_dirs_copied", 0) + 1

        if not rel_tail:
            rel_tail = Path("evidence") / subdir / Path(file_path).name

        dest_file = dest_scan_dir / rel_tail
        if src_file and src_file.exists() and not dest_file.exists():
            dest_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_file, dest_file)

        if not dest_file.exists() and not _write_enrichment_data_file(enrich, dest_file):
            continue

        new_file_path = str(dest_file)
        cursor.execute("""
            UPDATE enrichments
            SET file_path = ?
            WHERE scan_result_id = ?
              AND enrichment_type = ?
              AND COALESCE(file_path, '') = COALESCE(?, '')
        """, (
            new_file_path,
            new_sr_id,
            enrich.get("enrichment_type"),
            file_path,
        ))
        if cursor.rowcount == 0:
            cursor.execute("""
                UPDATE enrichments
                SET file_path = ?
                WHERE scan_result_id = ?
                  AND enrichment_type = ?
                  AND (file_path IS NULL OR TRIM(file_path) = '')
            """, (new_file_path, new_sr_id, enrich.get("enrichment_type")))

        import_stats["evidence_files_relinked"] = import_stats.get("evidence_files_relinked", 0) + 1


def _refresh_imported_bitacoras(storage: ScanStorage, export_data: Dict, import_stats: Dict):
    """Regenera bloques gestionados de bitacora para que las evidencias importadas aparezcan."""
    org_names = _get_export_org_names(export_data)
    if not org_names:
        return

    try:
        from arsenal.core.bitacora_manager import BitacoraManager
        manager = BitacoraManager(storage.results_root)
    except Exception as exc:
        import_stats.setdefault("bitacora_errors", []).append(f"Bitacora no disponible: {exc}")
        return

    for org_name in org_names:
        try:
            result = manager.fill_from_scans(org_name, storage.db_path)
            import_stats["bitacora_refreshed"] = import_stats.get("bitacora_refreshed", 0) + 1
            import_stats["bitacora_evidence_copied"] = (
                import_stats.get("bitacora_evidence_copied", 0)
                + int(result.get("evidence_copied", 0) or 0)
            )
            for error in result.get("errors", []) or []:
                import_stats.setdefault("bitacora_errors", []).append(f"{org_name}: {error}")
        except Exception as exc:
            import_stats.setdefault("bitacora_errors", []).append(f"{org_name}: {exc}")


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
        'files_imported': 0,
        'pwndoc_audits': 0,
        'pwndoc_findings': 0,
        'pwndoc_findings_skipped': 0,
        'pwndoc_errors': [],
        'network_devices': 0,
        'imported_scan_ids': [],
        'scan_id_map': {},
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
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys = ON")
        cursor = conn.cursor()
        
        try:
            # Importar según el tipo
            if export_data['type'] == 'all':
                # Importar todo
                for org in export_data.get('organizations', []):
                    if _ensure_organization_incremental(
                        cursor,
                        org.get('name'),
                        org.get('description'),
                        org.get('created_at'),
                    ):
                        import_stats['organizations'] += 1
                
                _import_scan_data(cursor, export_data, import_stats)
                _import_org_metadata(cursor, export_data, import_stats)
                
                # Copiar archivos
                for item in temp_path.iterdir():
                    if item.is_dir() and item.name != '__pycache__':
                        dest_dir = storage.results_root / item.name
                        if dest_dir.exists():
                            _merge_directory(item, dest_dir)
                        else:
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

                    if _ensure_organization_incremental(cursor, org_name_val, org_desc, org_created):
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
                        _ensure_organization_incremental(
                            cursor,
                            org_name,
                            org_rec.get('description'),
                            org_rec.get('created_at') or datetime.now().isoformat(),
                        )
                    else:
                        _ensure_organization_incremental(cursor, org_name, None, datetime.now().isoformat())
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
                        _ensure_organization_incremental(
                            cursor,
                            org_name,
                            org_rec.get('description'),
                            org_rec.get('created_at') or datetime.now().isoformat(),
                        )
                    else:
                        _ensure_organization_incremental(cursor, org_name, None, datetime.now().isoformat())
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
                                _merge_directory(scan_dir, dest_dir)
                            else:
                                shutil.copytree(scan_dir, dest_dir)
                            import_stats['files_imported'] += 1
            
            _import_bitacora_org_files(storage, temp_path, export_data, import_stats)
            _restore_imported_evidence_files(storage, temp_path, export_data, cursor, import_stats)

            conn.commit()
            
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()

        _refresh_imported_bitacoras(storage, export_data, import_stats)
    
    for key in list(import_stats.keys()):
        if key.startswith("_"):
            import_stats.pop(key, None)

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
    skipped_scan_ids = set()

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
                hostname          = COALESCE(NULLIF(hostname, ''),          excluded.hostname),
                hostnames_json    = COALESCE(NULLIF(hostnames_json, ''),    excluded.hostnames_json),
                mac_address       = COALESCE(NULLIF(mac_address, ''),       excluded.mac_address),
                vendor            = COALESCE(NULLIF(vendor, ''),            excluded.vendor),
                subnet            = COALESCE(NULLIF(subnet, ''),            excluded.subnet),
                os_info_json      = COALESCE(NULLIF(os_info_json, ''),      excluded.os_info_json),
                host_scripts_json = COALESCE(NULLIF(host_scripts_json, ''), excluded.host_scripts_json),
                last_seen         = COALESCE(NULLIF(last_seen, ''),         excluded.last_seen)
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
        if (scan.get('scan_mode') or 'active') == 'passive':
            if old_id is not None:
                skipped_scan_ids.add(old_id)
            import_stats['passive_scans_skipped'] = import_stats.get('passive_scans_skipped', 0) + 1
            continue
        org_name = scan['organization_name'].strip().upper()
        loc_name = scan['location'].strip().upper()

        existing_scan_id = _find_existing_scan(cursor, scan)
        if existing_scan_id:
            new_id = existing_scan_id
            _update_existing_scan_missing(cursor, new_id, scan)
            import_stats['existing_scans_reused'] = import_stats.get('existing_scans_reused', 0) + 1
        else:
            cursor.execute("""
                INSERT INTO scans
                    (organization_name, location, scan_type, target_range, interface,
                     myip, nmap_command, started_at, completed_at, status,
                     hosts_discovered, ports_found, error_message, created_by,
                     scan_mode,
                     enable_version_detection, enable_vulnerability_scan,
                     enable_screenshots, enable_source_code)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                org_name, loc_name,
                scan.get('scan_type', 'mixed'), scan.get('target_range') or '',
                scan.get('interface'), scan.get('myip'),
                scan.get('nmap_command'), scan.get('started_at'),
                scan.get('completed_at'), scan.get('status', 'completed'),
                scan.get('hosts_discovered', 0), scan.get('ports_found', 0),
                scan.get('error_message'), scan.get('created_by'),
                scan.get('scan_mode', 'active'),
                scan.get('enable_version_detection', 0),
                scan.get('enable_vulnerability_scan', 0),
                scan.get('enable_screenshots', 0),
                scan.get('enable_source_code', 0),
            ))
            new_id = cursor.lastrowid
            import_stats['scans'] += 1
        if old_id is not None:
            scan_id_map[old_id] = new_id
            import_stats['scan_id_map'][str(old_id)] = new_id
        if new_id not in import_stats['imported_scan_ids']:
            import_stats['imported_scan_ids'].append(new_id)

    # ------------------------------------------------------------------ #
    # 3. SCAN_RESULTS — usar IDs remapeados de host y scan                #
    # ------------------------------------------------------------------ #
    for result in export_data.get('scan_results', []):
        old_id      = result.get('id')
        old_scan_id = result.get('scan_id')
        old_host_id = result.get('host_id')
        if old_scan_id in skipped_scan_ids:
            continue

        new_scan_id = scan_id_map.get(old_scan_id)
        new_host_id = host_id_map.get(old_host_id, old_host_id)
        if not new_scan_id:
            continue

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

        existing_result_id = _find_scan_result_id(
            cursor,
            new_scan_id,
            new_host_id,
            result.get('port'),
            result.get('protocol'),
        )
        if existing_result_id:
            new_id = existing_result_id
            _update_missing_fields(cursor, "scan_results", new_id, {
                "state": result.get('state', 'up'),
                "service_name": result.get('service_name'),
                "product": result.get('product'),
                "version": result.get('version'),
                "extrainfo": result.get('extrainfo'),
                "cpe": result.get('cpe'),
                "reason": result.get('reason'),
                "reason_ttl": result.get('reason_ttl'),
                "confidence": result.get('confidence'),
                "scripts_json": result.get('scripts_json'),
                "discovery_method": result.get('discovery_method'),
                "discovered_at": result.get('discovered_at'),
            }, [
                "state", "service_name", "product", "version", "extrainfo",
                "cpe", "reason", "reason_ttl", "confidence", "scripts_json",
                "discovery_method", "discovered_at",
            ])
            import_stats['existing_scan_results_reused'] = import_stats.get('existing_scan_results_reused', 0) + 1
        else:
            cursor.execute("""
                INSERT INTO scan_results
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
            import_stats['scan_results'] += 1

        if old_id is not None and new_id:
            sr_id_map[old_id] = new_id

    # ------------------------------------------------------------------ #
    # 4. VULNERABILIDADES — columnas correctas + remapping sr_id          #
    # ------------------------------------------------------------------ #
    for vuln in export_data.get('vulnerabilities', []):
        old_sr_id = vuln.get('scan_result_id')
        new_sr_id = sr_id_map.get(old_sr_id)

        if not new_sr_id:
            continue

        vuln_data = {
            'vulnerability_id': vuln.get('vulnerability_id'),
            'vulnerability_name': vuln.get('vulnerability_name') or vuln.get('title'),
            'severity': vuln.get('severity'),
            'description': vuln.get('description'),
            'cve_id': vuln.get('cve_id') or vuln.get('references'),
            'cvss_score': vuln.get('cvss_score'),
            'script_source': vuln.get('script_source'),
            'script_output': vuln.get('script_output'),
            'discovered_at': vuln.get('discovered_at', datetime.now().isoformat()),
        }
        existing_vuln_id = _find_vulnerability_id(cursor, new_sr_id, vuln_data)
        if existing_vuln_id:
            _update_missing_fields(cursor, "vulnerabilities", existing_vuln_id, vuln_data, [
                "vulnerability_id", "vulnerability_name", "severity", "description",
                "cve_id", "cvss_score", "script_source", "script_output", "discovered_at",
            ])
            import_stats['existing_vulnerabilities_reused'] = import_stats.get('existing_vulnerabilities_reused', 0) + 1
        else:
            cursor.execute("""
                INSERT INTO vulnerabilities
                    (scan_result_id, vulnerability_id, vulnerability_name, severity,
                     description, cve_id, cvss_score, script_source, script_output,
                     discovered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                new_sr_id,
                vuln_data['vulnerability_id'],
                vuln_data['vulnerability_name'],
                vuln_data['severity'],
                vuln_data['description'],
                vuln_data['cve_id'],
                vuln_data['cvss_score'],
                vuln_data['script_source'],
                vuln_data['script_output'],
                vuln_data['discovered_at']
            ))
            import_stats['vulnerabilities'] += 1

    # ------------------------------------------------------------------ #
    # 5. ENRICHMENTS — remapping sr_id                                    #
    # ------------------------------------------------------------------ #
    for enrich in export_data.get('enrichments', []):
        old_sr_id = enrich.get('scan_result_id')
        new_sr_id = sr_id_map.get(old_sr_id)

        if not new_sr_id:
            continue

        created_at = enrich.get('created_at') or enrich.get('discovered_at') or datetime.now().isoformat()
        enrich_data = {
            'enrichment_type': enrich.get('enrichment_type'),
            'data': enrich.get('data'),
            'file_path': enrich.get('file_path'),
            'created_at': created_at,
        }
        existing_enrichment_id = _find_enrichment_id(cursor, new_sr_id, enrich_data)
        if existing_enrichment_id:
            _update_missing_fields(cursor, "enrichments", existing_enrichment_id, enrich_data, [
                "enrichment_type", "data", "file_path", "created_at",
            ])
            import_stats['existing_enrichments_reused'] = import_stats.get('existing_enrichments_reused', 0) + 1
        else:
            cursor.execute("""
                INSERT INTO enrichments
                    (scan_result_id, enrichment_type, data, file_path, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (
                new_sr_id,
                enrich_data['enrichment_type'],
                enrich_data['data'],
                enrich_data['file_path'],
                enrich_data['created_at']
            ))
            import_stats['enrichments'] += 1

    # ------------------------------------------------------------------ #
    # 6. HOST_SCAN_METADATA — remapping scan_id y host_id                 #
    # ------------------------------------------------------------------ #
    for meta in export_data.get('host_scan_metadata', []):
        old_scan_id = meta.get('scan_id')
        old_host_id = meta.get('host_id')
        if old_scan_id in skipped_scan_ids:
            continue
        new_scan_id = scan_id_map.get(old_scan_id)
        new_host_id = host_id_map.get(old_host_id, old_host_id)

        if not new_scan_id or not new_host_id:
            continue

        cursor.execute("""
            INSERT INTO host_scan_metadata
                (scan_id, host_id, hostname, hostnames_json, mac_address, vendor,
                 os_info_json, host_scripts_json, interfaces_json, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(scan_id, host_id) DO UPDATE SET
                hostname          = COALESCE(NULLIF(hostname, ''),          excluded.hostname),
                hostnames_json    = COALESCE(NULLIF(hostnames_json, ''),    excluded.hostnames_json),
                mac_address       = COALESCE(NULLIF(mac_address, ''),       excluded.mac_address),
                vendor            = COALESCE(NULLIF(vendor, ''),            excluded.vendor),
                os_info_json      = COALESCE(NULLIF(os_info_json, ''),      excluded.os_info_json),
                host_scripts_json = COALESCE(NULLIF(host_scripts_json, ''), excluded.host_scripts_json),
                interfaces_json   = COALESCE(NULLIF(interfaces_json, ''),   excluded.interfaces_json),
                last_seen         = COALESCE(NULLIF(last_seen, ''),         excluded.last_seen)
        """, (
            new_scan_id, new_host_id,
            meta.get('hostname'), meta.get('hostnames_json'),
            meta.get('mac_address'), meta.get('vendor'),
            meta.get('os_info_json'), meta.get('host_scripts_json'),
            meta.get('interfaces_json'), meta.get('last_seen')
        ))

    import_stats['_scan_id_map_int'] = scan_id_map
    import_stats['_sr_id_map_int'] = sr_id_map
    import_stats['_host_id_map_int'] = host_id_map


_ARSENAL_MANAGED_BLOCK_RE = (
    r"<!-- ARSENAL:[A-Z0-9_-]+ -->.*?<!-- /ARSENAL:[A-Z0-9_-]+ -->"
)


def _merge_text_file_missing_content(source_file: Path, dest_file: Path) -> bool:
    """Añade lineas de texto importadas que no existan sin sobrescribir la nota local."""
    try:
        source_text = source_file.read_text(encoding="utf-8", errors="replace")
        dest_text = dest_file.read_text(encoding="utf-8", errors="replace")
    except UnicodeError:
        return False

    if source_text == dest_text:
        return False

    import re
    source_text = re.sub(_ARSENAL_MANAGED_BLOCK_RE, "", source_text, flags=re.DOTALL)
    dest_lines = {line.strip() for line in dest_text.splitlines() if line.strip()}
    missing_lines = [
        line.rstrip()
        for line in source_text.splitlines()
        if line.strip() and line.strip() not in dest_lines
    ]
    if not missing_lines:
        return False

    imported_block = (
        "\n\n<!-- ARSENAL:IMPORT-MERGE -->\n"
        "## Contenido importado pendiente de revisar\n\n"
        + "\n".join(missing_lines)
        + "\n<!-- /ARSENAL:IMPORT-MERGE -->\n"
    )
    dest_file.write_text(dest_text.rstrip() + imported_block, encoding="utf-8")
    return True


def _merge_directory(source: Path, dest: Path, merge_text: bool = False):
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
            elif merge_text and item.suffix.lower() in {".md", ".txt"}:
                try:
                    _merge_text_file_missing_content(item, dest_file)
                except (PermissionError, OSError) as e:
                    print(f"⚠️ No se pudo fusionar {item} con {dest_file}: {e}")


def _import_org_metadata(cursor, export_data: Dict, import_stats: Dict):
    """Importa redes y dispositivos críticos."""
    network_id_map: Dict[int, int] = {}

    def _find_network_id(net: Dict) -> Optional[int]:
        row = cursor.execute("""
            SELECT id FROM networks
            WHERE UPPER(organization_name) = UPPER(?)
              AND network_name = ?
              AND network_range = ?
            ORDER BY id
            LIMIT 1
        """, (
            net['organization_name'].strip().upper(),
            net['network_name'],
            net['network_range'],
        )).fetchone()
        return row["id"] if row else None

    def _find_critical_device_id(dev: Dict) -> Optional[int]:
        org_name = dev['organization_name'].strip().upper()
        system_name = dev.get('system_name')
        row = cursor.execute(f"""
            SELECT id FROM critical_devices
            WHERE UPPER(organization_name) = UPPER(?)
              AND {_sql_value_matches('system_name')}
              AND name = ?
            ORDER BY id
            LIMIT 1
        """, (org_name, system_name, system_name, dev['name'])).fetchone()
        return row["id"] if row else None

    def _find_network_device_id(dev: Dict) -> Optional[int]:
        org_name = dev['organization_name'].strip().upper()
        system_name = dev.get('system_name')
        row = cursor.execute(f"""
            SELECT id FROM network_devices
            WHERE UPPER(organization_name) = UPPER(?)
              AND {_sql_value_matches('system_name')}
              AND name = ?
            ORDER BY id
            LIMIT 1
        """, (org_name, system_name, system_name, dev['name'])).fetchone()
        return row["id"] if row else None

    def _remap_json_ids(raw_value, id_map: Dict[int, int]) -> str:
        try:
            values = json.loads(raw_value or "[]")
        except (TypeError, json.JSONDecodeError):
            values = []
        if not isinstance(values, list):
            values = [values]
        remapped = []
        for value in values:
            try:
                old_id = int(value)
            except (TypeError, ValueError):
                continue
            new_id = id_map.get(old_id, old_id)
            if new_id not in remapped:
                remapped.append(new_id)
        return json.dumps(remapped)

    # Importar redes
    for net in export_data.get('networks', []):
        # Normalizar nombre
        old_id = net.get('id')
        org_name = net['organization_name'].strip().upper()
        existing_network_id = _find_network_id(net)
        if existing_network_id:
            new_network_id = existing_network_id
            _update_missing_fields(cursor, "networks", new_network_id, {
                "system_name": net.get('system_name'),
                "purdue_level": net.get('purdue_level'),
                "created_at": net.get('created_at'),
            }, ["system_name", "purdue_level", "created_at"])
            import_stats['existing_networks_reused'] = import_stats.get('existing_networks_reused', 0) + 1
        else:
            cursor.execute("""
                INSERT INTO networks
                (organization_name, system_name, network_name, network_range, purdue_level, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                org_name, net.get('system_name'),
                net['network_name'], net['network_range'], net.get('purdue_level'),
                net.get('created_at', datetime.now().isoformat())
            ))
            new_network_id = cursor.lastrowid
            if 'networks' not in import_stats:
                import_stats['networks'] = 0
            import_stats['networks'] += 1
        if old_id is not None:
            network_id_map[int(old_id)] = new_network_id

    # Importar dispositivos críticos
    for dev in export_data.get('critical_devices', []):
        # Normalizar nombre
        org_name = dev['organization_name'].strip().upper()
        existing_critical_id = _find_critical_device_id(dev)
        if existing_critical_id:
            row = cursor.execute("""
                SELECT ips, reason, created_at FROM critical_devices WHERE id = ?
            """, (existing_critical_id,)).fetchone()
            merged_ips = _merge_csv(row["ips"], dev.get('ips'))
            updates = []
            params = []
            if merged_ips and merged_ips != row["ips"]:
                updates.append("ips = ?")
                params.append(merged_ips)
            if _is_missing(row["reason"]) and not _is_missing(dev.get('reason')):
                updates.append("reason = ?")
                params.append(dev.get('reason'))
            if _is_missing(row["created_at"]) and not _is_missing(dev.get('created_at')):
                updates.append("created_at = ?")
                params.append(dev.get('created_at'))
            if updates:
                params.append(existing_critical_id)
                cursor.execute(
                    f"UPDATE critical_devices SET {', '.join(updates)} WHERE id = ?",
                    tuple(params)
                )
            import_stats['existing_critical_devices_reused'] = (
                import_stats.get('existing_critical_devices_reused', 0) + 1
            )
        else:
            cursor.execute("""
                INSERT INTO critical_devices
                (organization_name, system_name, name, ips, reason, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                org_name, dev.get('system_name'), dev['name'],
                dev['ips'], dev['reason'],
                dev.get('created_at', datetime.now().isoformat())
            ))
            if 'critical_devices' not in import_stats:
                import_stats['critical_devices'] = 0
            import_stats['critical_devices'] += 1

    # Importar electrónica de red. Se remapean IDs de redes y dispositivos
    # porque el importador general crea nuevos IDs al restaurar en destino.
    network_device_id_map: Dict[int, int] = {}
    pending_connections = []
    for dev in export_data.get('network_devices', []):
        old_id = dev.get('id')
        org_name = dev['organization_name'].strip().upper()
        accessible_networks = _remap_json_ids(dev.get('accessible_network_ids_json'), network_id_map)
        existing_device_id = _find_network_device_id(dev)
        if existing_device_id:
            new_id = existing_device_id
            _update_missing_fields(cursor, "network_devices", new_id, {
                "system_name": dev.get('system_name'),
                "device_type": dev.get('device_type'),
                "management_ip": dev.get('management_ip'),
                "notes": dev.get('notes'),
                "created_at": dev.get('created_at'),
            }, ["system_name", "device_type", "management_ip", "notes", "created_at"])

            row = cursor.execute("""
                SELECT accessible_network_ids_json, origin_locations_json
                FROM network_devices WHERE id = ?
            """, (new_id,)).fetchone()
            merged_accessible = _merge_json_lists(row["accessible_network_ids_json"], accessible_networks)
            merged_origins = _merge_json_lists(row["origin_locations_json"], dev.get('origin_locations_json'))
            updates = []
            params = []
            if merged_accessible and merged_accessible != row["accessible_network_ids_json"]:
                updates.append("accessible_network_ids_json = ?")
                params.append(merged_accessible)
            if merged_origins and merged_origins != row["origin_locations_json"]:
                updates.append("origin_locations_json = ?")
                params.append(merged_origins)
            if updates:
                params.append(new_id)
                cursor.execute(
                    f"UPDATE network_devices SET {', '.join(updates)} WHERE id = ?",
                    tuple(params)
                )
            import_stats['existing_network_devices_reused'] = (
                import_stats.get('existing_network_devices_reused', 0) + 1
            )
        else:
            cursor.execute("""
                INSERT INTO network_devices
                (organization_name, system_name, name, device_type, management_ip,
                 accessible_network_ids_json, origin_locations_json,
                 connected_device_ids_json, notes, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                org_name,
                dev.get('system_name'),
                dev['name'],
                dev['device_type'],
                dev.get('management_ip'),
                accessible_networks,
                dev.get('origin_locations_json'),
                json.dumps([]),
                dev.get('notes'),
                dev.get('created_at', datetime.now().isoformat()),
            ))
            new_id = cursor.lastrowid
            import_stats['network_devices'] = import_stats.get('network_devices', 0) + 1
        if old_id is not None:
            network_device_id_map[int(old_id)] = new_id
        pending_connections.append((new_id, dev.get('connected_device_ids_json')))

    for new_id, connected_json in pending_connections:
        row = cursor.execute("""
            SELECT connected_device_ids_json FROM network_devices WHERE id = ?
        """, (new_id,)).fetchone()
        if not row:
            continue
        remapped_connections = _remap_json_ids(connected_json, network_device_id_map)
        merged_connections = _merge_json_lists(row["connected_device_ids_json"], remapped_connections)
        if merged_connections and merged_connections != row["connected_device_ids_json"]:
            cursor.execute("""
                UPDATE network_devices
                SET connected_device_ids_json = ?
                WHERE id = ?
            """, (merged_connections, new_id))

    # Importar auditorías PwnDoc (mapping org → audit_id)
    _restore_pwndoc_exports(cursor, export_data, import_stats)

    if not (export_data.get('pwndoc_export') or {}).get('audits'):
        for pw in export_data.get('pwndoc_audits', []):
            if not pw.get('org_name') or not pw.get('audit_id'):
                continue
            cursor.execute("""
                INSERT INTO pwndoc_audits (org_name, audit_id, created_at)
                VALUES (UPPER(?), ?, ?)
                ON CONFLICT(org_name) DO NOTHING
            """, (
                pw['org_name'], pw['audit_id'],
                pw.get('created_at') or datetime.now().isoformat()
            ))
            if cursor.rowcount:
                import_stats['pwndoc_audits'] += 1


def _restore_pwndoc_exports(cursor, export_data: Dict, import_stats: Dict):
    """Recrea auditorias PwnDoc exportadas en el PwnDoc local del equipo destino."""
    export_block = export_data.get('pwndoc_export') or {}
    snapshots = export_block.get('audits') or []
    for error in export_block.get('errors') or []:
        import_stats.setdefault('pwndoc_errors', []).append(f"Export origen: {error}")
    if not snapshots:
        return

    try:
        from arsenal.core.pwndoc_client import PwnDocClient
        client = PwnDocClient()
        client.authenticate()
    except Exception as exc:
        import_stats.setdefault('pwndoc_errors', []).append(f"PwnDoc no disponible en destino: {exc}")
        return

    for snapshot in snapshots:
        org_name = (snapshot.get('org_name') or '').strip().upper()
        if not org_name:
            continue
        audit_name = (snapshot.get('audit_name') or org_name).strip() or org_name
        language = snapshot.get('language') or 'es'
        audit_type = _resolve_import_audit_type(client, snapshot.get('audit_type'))
        try:
            existing_audit = cursor.execute("""
                SELECT audit_id FROM pwndoc_audits WHERE UPPER(org_name) = UPPER(?)
            """, (org_name,)).fetchone()
            if existing_audit and existing_audit["audit_id"]:
                audit_id = existing_audit["audit_id"]
            else:
                audit_id = client.ensure_audit(
                    audit_name,
                    language=language,
                    audit_type=audit_type,
                    scope=_normalize_pwndoc_scope(snapshot.get('scope') or []),
                    date_start=snapshot.get('date_start') or '',
                    date_end=snapshot.get('date_end') or '',
                )
                cursor.execute("""
                    INSERT INTO pwndoc_audits (org_name, audit_id, created_at)
                    VALUES (UPPER(?), ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(org_name) DO NOTHING
                """, (org_name, audit_id))
                if cursor.rowcount:
                    import_stats['pwndoc_audits'] += 1

            existing_keys = {_finding_key(finding) for finding in client.get_findings(audit_id)}
            for finding in snapshot.get('findings') or []:
                key = _finding_key(finding)
                if key in existing_keys:
                    import_stats['pwndoc_findings_skipped'] += 1
                    continue
                restored = client.add_finding(
                    audit_id=audit_id,
                    title=finding.get('title') or 'Sin titulo',
                    description=finding.get('description') or '',
                    observation=finding.get('observation') or '',
                    remediation=finding.get('remediation') or '',
                    cvssv3=finding.get('cvssv3') or '',
                    vuln_type_id=finding.get('vulnType') or None,
                    category=finding.get('category') or 'Manual',
                    references=finding.get('references') or [],
                    poc=finding.get('poc') or '',
                    status=int(finding.get('status') or 0),
                )
                restored_id = str(restored.get('_id') or restored.get('id') or '')
                if restored_id:
                    cursor.execute("""
                        INSERT INTO arsenalot_pwndoc_findings
                            (org_name, audit_id, finding_id, title, created_at, updated_at)
                        VALUES (UPPER(?), ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                        ON CONFLICT(org_name, finding_id) DO NOTHING
                    """, (org_name, audit_id, restored_id, finding.get('title') or 'Sin titulo'))
                existing_keys.add(key)
                import_stats['pwndoc_findings'] += 1
        except Exception as exc:
            import_stats.setdefault('pwndoc_errors', []).append(f"{org_name}: {exc}")


def _resolve_import_audit_type(client, desired: Optional[str]) -> str:
    """Usa el audit type exportado si puede crearse/encontrarse; si no, usa el default."""
    desired = (desired or '').strip()
    try:
        audit_types = client.list_audit_types()
        names = {item.get('name') for item in audit_types if item.get('name')}
        if desired and desired in names:
            return desired
        if desired:
            client.create_audit_type(desired)
            return desired
        return client.ensure_default_audit_type()
    except Exception:
        return client.ensure_default_audit_type()


def _finding_key(finding: Dict) -> tuple:
    """Clave estable para evitar duplicar findings al reimportar."""
    return (
        (finding.get('title') or '').strip().lower(),
        (finding.get('description') or '').strip(),
        (finding.get('category') or '').strip().lower(),
    )


def _normalize_pwndoc_scope(scope) -> List[str]:
    """Convierte el scope de PwnDoc a lista de textos portable entre instancias."""
    normalized = []
    for item in scope or []:
        if isinstance(item, str):
            value = item.strip()
        elif isinstance(item, dict):
            raw = item.get('name') or item.get('label') or item.get('value') or ''
            if isinstance(raw, dict):
                raw = raw.get('name') or raw.get('label') or raw.get('value') or ''
            value = str(raw).strip()
        else:
            value = str(item).strip()
        if value:
            normalized.append(value)
    return normalized
