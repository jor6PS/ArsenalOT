import csv
import base64
import html
import io
import ipaddress
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional, List
from urllib.parse import quote
from fastapi import APIRouter, HTTPException, UploadFile, File
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response, StreamingResponse

from arsenal.core.demo_seed import seed_demo_organization
from arsenal.web.core.models import (
    NetworkCreateRequest,
    NetworkUpdateRequest,
    CriticalDeviceRequest,
    CriticalDeviceUpdateRequest,
    NetworkDeviceRequest,
    NetworkDeviceUpdateRequest,
)
from arsenal.web.core.deps import storage

router = APIRouter()


def _success_response(message: str, **extra):
    return {"status": "success", **extra, "message": message}


def _not_found_unless(found: bool, detail: str):
    if not found:
        raise HTTPException(status_code=404, detail=detail)

@router.get("/api/stats")
async def get_stats(
    organization: Optional[str] = None,
    location: Optional[str] = None,
    scan_id: Optional[int] = None
):
    """Obtiene estadísticas generales o filtradas."""
    conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
    conn.execute("PRAGMA journal_mode=WAL")
    cursor = conn.cursor()
    
    scan_filter = "WHERE 1=1"
    scan_params = []
    
    if organization:
        scan_filter += " AND UPPER(s.organization_name) = UPPER(?)"
        scan_params.append(organization)

    if location:
        scan_filter += " AND UPPER(s.location) = UPPER(?)"
        scan_params.append(location)
        
    if scan_id:
        scan_filter += " AND s.id = ?"
        scan_params.append(scan_id)

    scan_filter += " AND COALESCE(s.scan_mode, 'active') != 'passive'"
    active_result_filter = " AND COALESCE(sr.discovery_method, 'unknown') != 'passive_capture'"
    
    # Organizaciones
    if organization:
        orgs_count = 1
    elif scan_id:
        org_query = """
            SELECT COUNT(DISTINCT s.organization_name)
            FROM scans s
            WHERE s.id = ?
        """
        orgs_count = cursor.execute(org_query, [scan_id]).fetchone()[0]
    else:
        orgs_count = cursor.execute("SELECT COUNT(DISTINCT name) FROM organizations").fetchone()[0]
    
    # Escaneos (una sola query con CASE en lugar de tres COUNT separados)
    scans_row = cursor.execute(
        f"""SELECT
            COUNT(*),
            SUM(CASE WHEN s.status = 'completed' THEN 1 ELSE 0 END),
            SUM(CASE WHEN s.status = 'running'   THEN 1 ELSE 0 END)
        FROM scans s {scan_filter}""",
        scan_params
    ).fetchone()
    total_scans       = scans_row[0] or 0
    completed_scans   = scans_row[1] or 0
    running_scans_count = scans_row[2] or 0
    
    # Hosts
    hosts_query = f"""
        SELECT COUNT(DISTINCT h.id)
        FROM hosts h
        JOIN scan_results sr ON sr.host_id = h.id
        JOIN scans s ON s.id = sr.scan_id
        {scan_filter}
        {active_result_filter}
    """
    hosts_count = cursor.execute(hosts_query, scan_params).fetchone()[0]
    
    # Puertos
    ports_query = f"""
        SELECT COUNT(*)
        FROM scan_results sr
        JOIN scans s ON s.id = sr.scan_id
        {scan_filter}
        {active_result_filter}
    """
    ports_count = cursor.execute(ports_query, scan_params).fetchone()[0]
    
    # Vulnerabilidades (Solo activas por ahora)
    vulns_query = f"""
        SELECT COUNT(*) 
        FROM vulnerabilities v
        JOIN scan_results sr ON sr.id = v.scan_result_id
        JOIN scans s ON s.id = sr.scan_id
        {scan_filter}
        {active_result_filter}
    """
    vulns_count = cursor.execute(vulns_query, scan_params).fetchone()[0]
    
    # Screenshots
    screenshots_query = f"""
        SELECT COUNT(*) 
        FROM enrichments e
        JOIN scan_results sr ON sr.id = e.scan_result_id
        JOIN scans s ON s.id = sr.scan_id
        {scan_filter}
        {active_result_filter}
        AND e.enrichment_type = 'Screenshot'
    """
    screenshots_count = cursor.execute(screenshots_query, scan_params).fetchone()[0]
    
    # Source codes
    sources_query = f"""
        SELECT COUNT(*) 
        FROM enrichments e
        JOIN scan_results sr ON sr.id = e.scan_result_id
        JOIN scans s ON s.id = sr.scan_id
        {scan_filter}
        {active_result_filter}
        AND e.enrichment_type = 'Websource'
    """
    sources_count = cursor.execute(sources_query, scan_params).fetchone()[0]
    
    conn.close()
    
    return {
        "organizations": orgs_count,
        "scans": {
            "total": total_scans,
            "completed": completed_scans,
            "running": running_scans_count
        },
        "hosts": hosts_count,
        "ports": ports_count,
        "vulnerabilities": vulns_count,
        "screenshots": screenshots_count,
        "sources": sources_count
    }

@router.get("/api/interfaces")
async def get_interfaces():
    """Obtiene la lista de interfaces de red disponibles en el sistema."""
    # 1. Intentar con psutil (más completo)
    try:
        import psutil
        interfaces = sorted(list(psutil.net_if_addrs().keys()))
        # Filtrar interfaces 'lo' y otras virtuales no deseadas
        return [i for i in interfaces if i != 'lo' and not i.startswith('veth') and i != 'docker0']
    except (ImportError, Exception):
        # psutil no está o falló, intentar fallback
        pass

    # 2. Intentar fallback con socket (estándar en Python)
    try:
        import socket
        if hasattr(socket, 'if_nameindex'):
            return [i[1] for i in socket.if_nameindex() if i[1] != 'lo']
    except Exception:
        pass

    # 3. Fallback final
    return ["eth0", "wlan0"]

@router.get("/api/organizations")
async def get_organizations():
    """Obtiene lista de organizaciones."""
    conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    orgs = cursor.execute("SELECT name, description, created_at FROM organizations ORDER BY name").fetchall()
    conn.close()

    return [{"name": org["name"], "description": org["description"], "created_at": org["created_at"]} for org in orgs]


class CreateOrgRequest(BaseModel):
    name: str
    description: str = ""
    create_pwndoc_audit: bool = True
    pwndoc_audit_name: Optional[str] = None
    pwndoc_audit_type: Optional[str] = None
    pwndoc_language: str = "es"
    pwndoc_scope: List[str] = []
    pwndoc_date_start: str = ""
    pwndoc_date_end: str = ""


class CreateLocationRequest(BaseModel):
    organization: str
    location: str


@router.post("/api/organizations")
async def create_organization(body: CreateOrgRequest):
    """Crea una organización, su bitácora y opcionalmente su auditoría PwnDoc."""
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="El nombre no puede estar vacío.")
    pwndoc_result = None
    if body.create_pwndoc_audit:
        try:
            from arsenal.core.pwndoc_client import PwnDocClient
            client = PwnDocClient()
            audit_type = body.pwndoc_audit_type or client.ensure_default_audit_type()
            audit_name = (body.pwndoc_audit_name or name).strip() or name
            audit_id = client.ensure_audit(
                audit_name,
                language=(body.pwndoc_language or "es"),
                audit_type=audit_type,
                scope=[s.strip() for s in (body.pwndoc_scope or []) if s and s.strip()],
                date_start=body.pwndoc_date_start,
                date_end=body.pwndoc_date_end,
            )
            pwndoc_result = {
                "ok": True,
                "audit_id": audit_id,
                "audit_name": audit_name,
                "audit_type": audit_type,
            }
        except Exception as e:
            raise HTTPException(
                status_code=502,
                detail=f"No se pudo crear la auditoría en PwnDoc: {e}"
            )

    storage.create_organization(name, body.description)
    if pwndoc_result:
        storage.save_pwndoc_audit_id(name.upper(), pwndoc_result["audit_id"])

    return {"ok": True, "name": name.upper(), "pwndoc": pwndoc_result}


@router.post("/api/organizations/demo/load")
async def load_demo_organization():
    """Carga una organización demo completa para probar y enseñar la aplicación."""
    try:
        result = seed_demo_organization(storage, reset=True)
        return _success_response(
            "Organización demo cargada correctamente",
            **result,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"No se pudo cargar la demo: {exc}")


def _resolve_evidence_file(file_path: Optional[str], organization: str, location: str,
                           scan_id: int, evidence_kind: str) -> Optional[Path]:
    if not file_path:
        return None

    path = Path(file_path)
    if path.is_absolute():
        return path if path.exists() else None

    candidates = [
        Path.cwd() / path,
        storage.get_scan_directory(organization, location, scan_id) / evidence_kind / path.name,
        storage.get_scan_directory(organization, location, scan_id) / path,
    ]
    return next((candidate for candidate in candidates if candidate.exists()), None)


def _fetch_evidence(scan_id: int, ip: str, port: int, enrichment_type: str):
    conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    row = cursor.execute("""
        SELECT s.organization_name, s.location, e.file_path, e.data
        FROM enrichments e
        JOIN scan_results sr ON sr.id = e.scan_result_id
        JOIN hosts h ON h.id = sr.host_id
        JOIN scans s ON s.id = sr.scan_id
        WHERE s.id = ?
          AND h.ip_address = ?
          AND sr.port = ?
          AND e.enrichment_type = ?
        ORDER BY e.created_at DESC
        LIMIT 1
    """, (scan_id, ip, port, enrichment_type)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail=f"Evidencia {enrichment_type} no encontrada")
    return row


@router.get("/api/evidence/screenshot/{scan_id}/{ip}/{port}")
async def get_evidence_screenshot(scan_id: int, ip: str, port: int):
    """Sirve capturas desde el router API principal para el Overview y detalle."""
    evidence = _fetch_evidence(scan_id, ip, port, "Screenshot")
    file_path = _resolve_evidence_file(
        evidence["file_path"],
        evidence["organization_name"],
        evidence["location"],
        scan_id,
        "evidence/img",
    )
    if file_path:
        return FileResponse(str(file_path), media_type="image/png", filename=file_path.name)

    if evidence["data"]:
        try:
            return Response(content=base64.b64decode(evidence["data"]), media_type="image/png")
        except Exception:
            pass
    raise HTTPException(status_code=404, detail="Archivo de screenshot no disponible")


@router.get("/api/evidence/source/{scan_id}/{ip}/{port}")
async def get_evidence_source(scan_id: int, ip: str, port: int):
    """Sirve código fuente web desde archivo o desde el contenido guardado."""
    evidence = _fetch_evidence(scan_id, ip, port, "Websource")
    file_path = _resolve_evidence_file(
        evidence["file_path"],
        evidence["organization_name"],
        evidence["location"],
        scan_id,
        "evidence/source",
    )
    if file_path:
        return FileResponse(str(file_path), media_type="text/plain; charset=utf-8", filename=file_path.name)

    if evidence["data"]:
        return JSONResponse(content={"content": evidence["data"]})
    raise HTTPException(status_code=404, detail="Código fuente no disponible")


@router.get("/api/scan/{scan_id}/screenshots")
async def get_scan_screenshots(scan_id: int):
    """Lista capturas de un escaneo para la pantalla de detalle/overview."""
    conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT DISTINCT h.ip_address, sr.port
        FROM enrichments e
        JOIN scan_results sr ON sr.id = e.scan_result_id
        JOIN hosts h ON h.id = sr.host_id
        WHERE sr.scan_id = ? AND e.enrichment_type = 'Screenshot'
        ORDER BY h.ip_address, sr.port
    """, (scan_id,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]


@router.get("/api/scan/{scan_id}/sources")
async def get_scan_sources(scan_id: int):
    """Lista fuentes web de un escaneo para la pantalla de detalle/overview."""
    conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT DISTINCT h.ip_address, sr.port
        FROM enrichments e
        JOIN scan_results sr ON sr.id = e.scan_result_id
        JOIN hosts h ON h.id = sr.host_id
        WHERE sr.scan_id = ? AND e.enrichment_type = 'Websource'
        ORDER BY h.ip_address, sr.port
    """, (scan_id,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]

@router.get("/api/locations")
async def get_locations(organization: Optional[str] = None):
    """Obtiene lista de ubicaciones, opcionalmente filtradas por organización."""
    return [{"location": loc} for loc in storage.get_scan_origins(organization)]


@router.post("/api/locations")
async def create_location(request: CreateLocationRequest):
    """Crea un origen reutilizable para nuevos escaneos."""
    try:
        location = storage.add_scan_origin(request.organization, request.location)
        return _success_response("Origen creado correctamente", location=location)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/api/targets/suggestions")
async def get_target_suggestions(organization: str, location: Optional[str] = None):
    """Sugiere objetivos para escaneos específicos basándose en resultados previos."""
    conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    params = [organization]
    loc_filter = ""
    if location:
        loc_filter = " AND UPPER(s.location) = UPPER(?)"
        params.append(location)
        
    # 1. Sugerencias Web (para Screenshots/Source Code)
    web_query = f"""
        SELECT DISTINCT h.ip_address, sr.port, sr.service_name
        FROM scan_results sr
        JOIN hosts h ON h.id = sr.host_id
        JOIN scans s ON s.id = sr.scan_id
        WHERE UPPER(s.organization_name) = UPPER(?) {loc_filter}
        AND (
            sr.port IN (80, 443, 8080, 8443, 8888, 9090)
            OR sr.service_name LIKE '%http%'
            OR sr.service_name LIKE '%ssl/http%'
            OR sr.service_name LIKE '%https%'
        )
        ORDER BY h.ip_address, sr.port
    """
    web_rows = cursor.execute(web_query, params).fetchall()
    web_targets = [dict(r) for r in web_rows]
    
    # 2. Sugerencias Windows (para IOXIDResolver)
    win_query = f"""
        SELECT DISTINCT h.ip_address, h.os_info_json
        FROM hosts h
        JOIN scan_results sr ON h.id = sr.host_id
        JOIN scans s ON s.id = sr.scan_id
        WHERE UPPER(s.organization_name) = UPPER(?) {loc_filter}
        AND (
            h.os_info_json LIKE '%Windows%'
            OR h.os_info_json LIKE '%Microsoft%'
            OR sr.port IN (135, 139, 445)
        )
        ORDER BY h.ip_address
    """
    win_rows = cursor.execute(win_query, params).fetchall()
    win_targets = []
    for r in win_rows:
        target = dict(r)
        # Intentar extraer nombre de OS legible si existe
        if target['os_info_json']:
            try:
                os_data = json.loads(target['os_info_json'])
                if os_data.get('matches'):
                    target['os_name'] = os_data['matches'][0]['name']
            except: pass
        win_targets.append(target)
        
    conn.close()
    return {
        "web": web_targets,
        "windows": win_targets
    }

@router.get("/api/networks")
async def get_networks(organization: str):
    """Obtiene lista de redes vinculadas a una organización."""
    try:
        networks = getattr(storage, 'get_networks', lambda org: [])(organization)
        return [dict(n) for n in networks]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error obteniendo redes: {str(e)}")

@router.get("/api/networks/export", response_class=PlainTextResponse)
async def export_networks(organization: str):
    """Exporta las redes de una organización en un archivo TXT formateado."""
    try:
        networks = getattr(storage, 'get_networks', lambda org: [])(organization)
        if not networks:
            return "No hay redes registradas para esta organización."
            
        # Agrupar por system_name
        grouped = {}
        for net in networks:
            sys = net.get("system_name") or "Sin Sistema Asociado"
            if sys not in grouped:
                grouped[sys] = []
            grouped[sys].append(net)
            
        lines = [f"=== Redes de {organization.upper()} ===", ""]
        
        # Asegurarnos de que "Sin Sistema Asociado" quede al final si lo hay
        sorted_systems = sorted(grouped.keys(), key=lambda x: (x == "Sin Sistema Asociado", x))
        
        for sys in sorted_systems:
            lines.append(f"[{sys}]")
            for net in grouped[sys]:
                purdue = net.get('purdue_level')
                purdue_text = f" · Purdue L{purdue}" if purdue is not None else ""
                lines.append(f"  - {net['network_name']}: {net['network_range']}{purdue_text}")
            lines.append("")
            
        content = "\n".join(lines)
        headers = {
            "Content-Disposition": f"attachment; filename=redes_{organization.lower()}.txt"
        }
        return PlainTextResponse(content=content, headers=headers)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error exportando redes: {str(e)}")

@router.post("/api/networks")
async def create_network(request: NetworkCreateRequest):
    """Añade una nueva red a una organización."""
    try:
        conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
        conn.execute("INSERT OR IGNORE INTO organizations (name, description) VALUES (?, '')", (request.organization.upper(),))
        conn.commit()
        conn.close()

        if hasattr(storage, 'add_network'):
            storage.add_network(
                organization=request.organization.upper(),
                network_name=request.network_name,
                network_range=request.network_range,
                system_name=request.system_name,
                purdue_level=request.purdue_level,
            )
        return _success_response("Red añadida correctamente")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error añadiendo red: {str(e)}")

@router.delete("/api/networks/{network_id}")
async def delete_network(network_id: int):
    """Elimina una red por su ID."""
    try:
        if hasattr(storage, 'delete_network'):
            deleted = storage.delete_network(network_id)
        else:
            deleted = False
            
        _not_found_unless(deleted, "Red no encontrada")
        return _success_response("Red eliminada correctamente")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error eliminando red: {str(e)}")

@router.put("/api/networks/{network_id}")
async def update_network(network_id: int, request: NetworkUpdateRequest):
    """Actualiza una red por su ID."""
    try:
        if hasattr(storage, 'update_network'):
            updated = storage.update_network(
                network_id=network_id,
                network_name=request.network_name,
                network_range=request.network_range,
                system_name=request.system_name,
                purdue_level=request.purdue_level,
            )
            _not_found_unless(updated, "Red no encontrada")
            return _success_response("Red actualizada correctamente")
        else:
            raise HTTPException(status_code=501, detail="update_network no implementado en storage")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error actualizando red: {str(e)}")


# ------------------------------------------------------------------ #
#  DISPOSITIVOS CRÍTICOS                                              #
# ------------------------------------------------------------------ #

@router.get("/api/critical-devices")
async def get_critical_devices(organization: str):
    """Obtiene los dispositivos críticos de una organización."""
    try:
        devices = storage.get_critical_devices(organization)
        return devices
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/critical-devices")
async def create_critical_device(req: CriticalDeviceRequest):
    """Añade un dispositivo crítico."""
    try:
        new_id = storage.add_critical_device(
            organization=req.organization,
            name=req.name,
            ips=req.ips,
            reason=req.reason,
            system_name=req.system_name,
        )
        return _success_response("Dispositivo crítico añadido", id=new_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/api/critical-devices/{device_id}")
async def update_critical_device(device_id: int, req: CriticalDeviceUpdateRequest):
    """Actualiza un dispositivo crítico."""
    try:
        updated = storage.update_critical_device(
            device_id=device_id,
            name=req.name,
            ips=req.ips,
            reason=req.reason,
            system_name=req.system_name,
        )
        _not_found_unless(updated, "Dispositivo no encontrado")
        return _success_response("Dispositivo crítico actualizado")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ------------------------------------------------------------------ #
#  ELECTRÓNICA DE RED                                                 #
# ------------------------------------------------------------------ #

@router.get("/api/network-devices")
async def get_network_devices(organization: str):
    """Obtiene firewalls, routers y switches declarados para una organización."""
    try:
        return storage.get_network_devices(organization)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/network-devices")
async def create_network_device(req: NetworkDeviceRequest):
    """Añade un activo de electrónica de red."""
    try:
        new_id = storage.add_network_device(
            organization=req.organization,
            system_name=req.system_name,
            name=req.name,
            device_type=req.device_type,
            management_ip=req.management_ip,
            accessible_network_ids=req.accessible_network_ids,
            origin_locations=req.origin_locations,
            connected_device_ids=req.connected_device_ids,
            notes=req.notes,
        )
        return _success_response("Activo de red añadido", id=new_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/api/network-devices/{device_id}")
async def update_network_device(device_id: int, req: NetworkDeviceUpdateRequest):
    """Actualiza un activo de electrónica de red."""
    try:
        updated = storage.update_network_device(
            device_id=device_id,
            system_name=req.system_name,
            name=req.name,
            device_type=req.device_type,
            management_ip=req.management_ip,
            accessible_network_ids=req.accessible_network_ids,
            origin_locations=req.origin_locations,
            connected_device_ids=req.connected_device_ids,
            notes=req.notes,
        )
        _not_found_unless(updated, "Activo de red no encontrado")
        return _success_response("Activo de red actualizado")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/api/network-devices/{device_id}")
async def delete_network_device(device_id: int):
    """Elimina un activo de electrónica de red por ID."""
    try:
        deleted = storage.delete_network_device(device_id)
        _not_found_unless(deleted, "Activo de red no encontrado")
        return _success_response("Activo de red eliminado")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/api/critical-devices/{device_id}")
async def delete_critical_device(device_id: int):
    """Elimina un dispositivo crítico por ID."""
    try:
        deleted = storage.delete_critical_device(device_id)
        _not_found_unless(deleted, "Dispositivo no encontrado")
        return _success_response("Dispositivo crítico eliminado")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ------------------------------------------------------------------ #
#  IMPORT / EXPORT DASHBOARD RECONOCIMIENTO                           #
# ------------------------------------------------------------------ #

def _system_value(raw) -> Optional[str]:
    value = str(raw or "").strip()
    return value or None


def _network_label(network: dict) -> str:
    return f"{network['network_name']} ({network['network_range']})"


def _split_ips(value) -> str:
    if isinstance(value, list):
        return ", ".join(str(item).strip() for item in value if str(item).strip())
    return str(value or "").strip()


def _coerce_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _dashboard_systems(payload: dict) -> list:
    return payload.get("systems") or []


def _dashboard_system_name(system: dict) -> Optional[str]:
    return _system_value(system.get("system_name") or system.get("name"))


def _find_existing_network(networks: List[dict], system_name: Optional[str],
                           name: str, network_range: str) -> Optional[dict]:
    try:
        normalized_range = str(ipaddress.ip_network(network_range, strict=False))
    except ValueError:
        normalized_range = network_range
    for network in networks:
        if (network.get("system_name") or None) != system_name:
            continue
        if network.get("network_name", "").strip().lower() != name.strip().lower():
            continue
        if network.get("network_range") == normalized_range:
            return network
    return None


def _register_network_lookup(network_lookup: dict, network: dict):
    network_id = network["id"]
    network_lookup[network["network_name"].strip().lower()] = network_id
    network_lookup[_network_label(network).strip().lower()] = network_id


def _network_lookup(networks: List[dict]) -> dict:
    lookup = {}
    for network in networks:
        _register_network_lookup(lookup, network)
    return lookup


def _resolve_lookup_refs(refs, lookup: dict) -> list:
    resolved_ids = []
    for ref in _coerce_list(refs):
        if isinstance(ref, int):
            resolved_ids.append(ref)
            continue
        resolved = lookup.get(str(ref).strip().lower())
        if resolved:
            resolved_ids.append(resolved)
    return resolved_ids


def _device_lookup_key(system_key: str, name: str) -> tuple:
    return (system_key or "", name.strip().lower())


def _register_device_lookup(device_lookup: dict, device_id: int,
                            system_key: str, name: str):
    device_lookup[_device_lookup_key(system_key, name)] = device_id
    device_lookup[_device_lookup_key("", name)] = device_id


def _device_lookup(devices: List[dict]) -> dict:
    lookup = {}
    for device in devices:
        _register_device_lookup(
            lookup,
            device["id"],
            device.get("system_name") or "",
            device["name"],
        )
    return lookup


def _diagram_unique_append(items: list, value):
    if value in (None, ""):
        return
    if value not in items:
        items.append(value)


def _diagram_system_slug(system_name: str = "", is_unknown: bool = False) -> str:
    if is_unknown:
        return "__unknown__"
    cleaned = str(system_name or "").strip()
    return cleaned if cleaned else "__none__"


def _diagram_system_label(system_name: str = "", is_unknown: bool = False) -> str:
    if is_unknown:
        return "Unknown"
    cleaned = str(system_name or "").strip()
    return cleaned if cleaned else "Sin sistema"


def _diagram_network_display_name(names: list, range_value: str, is_unknown: bool = False) -> str:
    if is_unknown:
        return str(range_value or "Unknown").strip() or "Unknown"
    unique_names = []
    for name in names or []:
        cleaned = str(name or "").strip()
        if cleaned and cleaned not in unique_names:
            unique_names.append(cleaned)
    if unique_names:
        return " / ".join(unique_names)
    return str(range_value or "Sin rango").strip() or "Sin rango"


def _diagram_network_sort_key(item: dict):
    parsed = item.get("_parsed_network")
    if parsed is not None:
        return (0, parsed.version, int(parsed.network_address), parsed.prefixlen)
    return (1, str(item.get("range") or ""), str(item.get("display_name") or "").lower())


def _diagram_ip_sort_key(value: str):
    try:
        ip_obj = ipaddress.ip_address(str(value or "").strip())
        return (0, ip_obj.version, int(ip_obj))
    except ValueError:
        return (1, str(value or "").strip())


_DIAGRAM_LAYER_META = {
    "l2": {
        "id": "l2",
        "label": "Capa 2 · ARP",
        "description": "Descubrimiento en el mismo dominio de broadcast.",
        "sort_order": 0,
    },
    "l3": {
        "id": "l3",
        "label": "Capa 3 · Ping / Puertos",
        "description": "Visibilidad enrutada por ICMP, Nmap o importes equivalentes.",
        "sort_order": 1,
    },
    "l7": {
        "id": "l7",
        "label": "Capa 7 · Específico / IOXID",
        "description": "Alcance confirmado por técnicas de aplicación.",
        "sort_order": 2,
    },
}


def _diagram_discovery_method_to_layer_key(discovery_method: str, has_mac: bool = False,
                                           has_port: bool = False) -> Optional[str]:
    method = str(discovery_method or "").strip().lower()
    if method == "arp_discovery":
        return "l2"
    if method == "host_discovery":
        return "l2" if has_mac else "l3"
    if method in {"icmp_discovery", "nmap_ping", "nmap_ports", "nmap_import"}:
        return "l3"
    if method in {"ioxid", "specific_capture", "netexec"}:
        return "l7"
    return None


def _html_title(title: str, rows: list) -> str:
    body = "".join(
        f"<div><b>{html.escape(str(label))}</b>: {html.escape(str(value))}</div>"
        for label, value in rows
        if value not in (None, "")
    )
    return f"<div class='global-map-tooltip'><strong>{html.escape(title)}</strong>{body}</div>"


@router.get("/api/visibility-diagram")
def _get_visibility_diagram_sync(organization: str):
    """Devuelve un diagrama de visibilidad basado en resultados reales de escaneo."""
    try:
        org = organization.upper()
        declared_networks = storage.get_networks(org)
        critical_devices = storage.get_critical_devices(org)

        network_groups = {}
        unknown_groups = {}
        critical_hosts_map = {}
        layer_usage = {}

        def ensure_network_group(system_name: str, network_range: str, network_name: str = None,
                                 purdue_level: float = None, is_unknown: bool = False,
                                 parsed_network=None):
            normalized_range = str(network_range or "").strip() or "Unknown"
            system_slug = _diagram_system_slug(system_name, is_unknown=is_unknown)
            key = (system_slug, normalized_range)
            group = network_groups.get(key)
            if group is None:
                system_label = _diagram_system_label(system_name, is_unknown=is_unknown)
                group = {
                    "id": f"network:{system_slug}:{normalized_range}",
                    "system_id": f"system:{system_slug}",
                    "system_name": system_label,
                    "raw_system_name": (str(system_name or "").strip() or None) if not is_unknown else None,
                    "range": normalized_range,
                    "network_names": [],
                    "display_name": normalized_range if is_unknown else normalized_range,
                    "purdue_levels": [],
                    "is_unknown": bool(is_unknown),
                    "origin_ids": set(),
                    "incoming_origin_ids": set(),
                    "_critical_host_ids": set(),
                    "_known_target_ips": set(),
                    "_parsed_network": parsed_network,
                }
                network_groups[key] = group
            if network_name:
                _diagram_unique_append(group["network_names"], str(network_name).strip())
            if purdue_level is not None:
                _diagram_unique_append(group["purdue_levels"], purdue_level)
            if parsed_network is not None:
                group["_parsed_network"] = parsed_network
            group["display_name"] = _diagram_network_display_name(
                group["network_names"],
                group["range"],
                is_unknown=group["is_unknown"],
            )
            return group

        for network in declared_networks:
            try:
                parsed_network = ipaddress.ip_network(network["network_range"], strict=False)
                normalized_range = str(parsed_network)
            except ValueError:
                parsed_network = None
                normalized_range = str(network["network_range"] or "").strip()
            ensure_network_group(
                network.get("system_name") or "",
                normalized_range,
                network_name=network.get("network_name"),
                purdue_level=network.get("purdue_level"),
                parsed_network=parsed_network,
            )

        known_groups = list(network_groups.values())

        def ensure_unknown_group(ip_str: str):
            ip_obj = ipaddress.ip_address(str(ip_str).strip())
            if ip_obj.version == 4:
                bucket = ipaddress.ip_network(f"{ip_obj}/24", strict=False)
            else:
                bucket = ipaddress.ip_network(f"{ip_obj}/64", strict=False)
            bucket_label = str(bucket)
            group = unknown_groups.get(bucket_label)
            if group is None:
                group = ensure_network_group(
                    "Unknown",
                    bucket_label,
                    network_name=bucket_label,
                    is_unknown=True,
                    parsed_network=bucket,
                )
                unknown_groups[bucket_label] = group
            return group

        def match_ip_to_network_groups(ip_str: str) -> list:
            try:
                ip_obj = ipaddress.ip_address(str(ip_str or "").strip())
            except ValueError:
                return []

            matches = []
            for group in known_groups:
                parsed_network = group.get("_parsed_network")
                if parsed_network is None or parsed_network.version != ip_obj.version:
                    continue
                if ip_obj in parsed_network:
                    matches.append(group)

            if matches:
                most_specific = max(item["_parsed_network"].prefixlen for item in matches)
                return [item for item in matches if item["_parsed_network"].prefixlen == most_specific]

            return [ensure_unknown_group(str(ip_obj))]

        conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        scans = conn.execute("""
            SELECT id, location, myip, scan_type, started_at
            FROM scans
            WHERE UPPER(organization_name) = UPPER(?)
              AND COALESCE(scan_mode, 'active') != 'passive'
              AND COALESCE(status, '') = 'completed'
              AND COALESCE(TRIM(myip), '') != ''
            ORDER BY started_at DESC
        """, (org,)).fetchall()
        scan_results = conn.execute("""
            SELECT DISTINCT
                   s.id AS scan_id,
                   s.myip AS origin_ip,
                   h.ip_address AS target_ip,
                   COALESCE(sr.discovery_method, '') AS discovery_method,
                   CASE WHEN sr.port IS NULL THEN 0 ELSE 1 END AS has_port,
                   COALESCE(hsm.mac_address, h.mac_address, '') AS mac_address
            FROM scan_results sr
            JOIN scans s ON s.id = sr.scan_id
            JOIN hosts h ON h.id = sr.host_id
            LEFT JOIN host_scan_metadata hsm
                   ON hsm.scan_id = sr.scan_id
                  AND hsm.host_id = sr.host_id
            WHERE UPPER(s.organization_name) = UPPER(?)
              AND COALESCE(s.scan_mode, 'active') != 'passive'
              AND COALESCE(s.status, '') = 'completed'
              AND COALESCE(TRIM(s.myip), '') != ''
        """, (org,)).fetchall()
        conn.close()

        origins = {}
        for scan in scans:
            origin_ip = str(scan["myip"] or "").strip()
            if not origin_ip:
                continue
            source_groups = match_ip_to_network_groups(origin_ip)
            entry = origins.setdefault(origin_ip, {
                "id": f"origin:{origin_ip}",
                "ip": origin_ip,
                "name": origin_ip,
                "scan_ids": [],
                "scan_types": [],
                "locations": [],
                "source_network_ids": [],
                "source_network_labels": [],
                "_source_network_id_set": set(),
                "_all_visible_hosts": set(),
                "_local_visible_hosts": set(),
            })
            _diagram_unique_append(entry["scan_ids"], scan["id"])
            _diagram_unique_append(entry["scan_types"], scan["scan_type"])
            _diagram_unique_append(entry["locations"], scan["location"])

            for group in source_groups:
                group["origin_ids"].add(entry["id"])
                if group["id"] in entry["_source_network_id_set"]:
                    continue
                entry["_source_network_id_set"].add(group["id"])
                entry["source_network_ids"].append(group["id"])
                entry["source_network_labels"].append(
                    f"{group['system_name']} / {group['display_name']} ({group['range']})"
                )

        relations = {}
        for row in scan_results:
            origin_ip = str(row["origin_ip"] or "").strip()
            target_ip = str(row["target_ip"] or "").strip()
            if not origin_ip or not target_ip or origin_ip not in origins:
                continue

            layer_key = _diagram_discovery_method_to_layer_key(
                row["discovery_method"],
                has_mac=bool(str(row["mac_address"] or "").strip()),
                has_port=bool(row["has_port"]),
            )
            if not layer_key:
                continue

            origin_entry = origins[origin_ip]
            origin_entry["_all_visible_hosts"].add(target_ip)
            source_network_ids = set(origin_entry["source_network_ids"])
            layer_entry = layer_usage.setdefault(layer_key, {
                "scan_ids": set(),
                "target_ips": set(),
                "relation_ids": set(),
            })
            layer_entry["scan_ids"].add(row["scan_id"])
            layer_entry["target_ips"].add(target_ip)

            for target_group in match_ip_to_network_groups(target_ip):
                if target_group["id"] in source_network_ids:
                    origin_entry["_local_visible_hosts"].add(target_ip)
                    continue

                relation_key = (origin_entry["id"], target_group["id"])
                relation = relations.setdefault(relation_key, {
                    "id": f"relation:{origin_entry['id']}->{target_group['id']}",
                    "source_origin_id": origin_entry["id"],
                    "source_network_ids": list(origin_entry["source_network_ids"]),
                    "target_network_id": target_group["id"],
                    "_scan_ids": set(),
                    "_target_ips": set(),
                    "_layer_keys": set(),
                    "_layer_scan_ids": {},
                    "_layer_target_ips": {},
                })
                relation["_scan_ids"].add(row["scan_id"])
                relation["_target_ips"].add(target_ip)
                relation["_layer_keys"].add(layer_key)
                relation["_layer_scan_ids"].setdefault(layer_key, set()).add(row["scan_id"])
                relation["_layer_target_ips"].setdefault(layer_key, set()).add(target_ip)
                target_group["_known_target_ips"].add(target_ip)
                target_group["incoming_origin_ids"].add(origin_entry["id"])
                layer_entry["relation_ids"].add(relation["id"])

        for device in critical_devices:
            device_name = str(device.get("name") or "").strip() or "Host crítico"
            device_reason = str(device.get("reason") or "").strip()
            device_system = str(device.get("system_name") or "").strip() or None

            for raw_ip in str(device.get("ips") or "").split(","):
                critical_ip = str(raw_ip or "").strip()
                if not critical_ip:
                    continue

                host_id = f"critical:{critical_ip}"
                critical_host = critical_hosts_map.setdefault(host_id, {
                    "id": host_id,
                    "ip": critical_ip,
                    "device_name": device_name,
                    "system_name": device_system,
                    "reason": device_reason,
                    "network_ids": [],
                    "network_labels": [],
                })

                for group in match_ip_to_network_groups(critical_ip):
                    if group["id"] not in critical_host["network_ids"]:
                        critical_host["network_ids"].append(group["id"])
                        critical_host["network_labels"].append(
                            f"{group['system_name']} / {group['display_name']} ({group['range']})"
                        )
                    group["_critical_host_ids"].add(host_id)

        for group in network_groups.values():
            group["display_name"] = _diagram_network_display_name(
                group["network_names"],
                group["range"],
                is_unknown=group["is_unknown"],
            )

        systems_map = {}
        for group in network_groups.values():
            system_entry = systems_map.setdefault(group["system_id"], {
                "id": group["system_id"],
                "name": group["system_name"],
                "raw_name": group["raw_system_name"],
                "is_unknown": group["is_unknown"],
                "network_ids": [],
                "_origin_ids": set(),
            })
            system_entry["network_ids"].append(group["id"])
            system_entry["_origin_ids"].update(group["origin_ids"])

        networks_payload = []
        for group in sorted(network_groups.values(), key=lambda item: (
            item["is_unknown"],
            _diagram_network_sort_key(item),
        )):
            networks_payload.append({
                "id": group["id"],
                "system_id": group["system_id"],
                "system_name": group["system_name"],
                "raw_system_name": group["raw_system_name"],
                "display_name": group["display_name"],
                "network_names": list(group["network_names"]),
                "range": group["range"],
                "purdue_levels": sorted(group["purdue_levels"], reverse=True),
                "is_unknown": group["is_unknown"],
                "origin_ids": sorted(group["origin_ids"], key=lambda value: _diagram_ip_sort_key(value.split("origin:", 1)[-1])),
                "incoming_origin_ids": sorted(group["incoming_origin_ids"], key=lambda value: _diagram_ip_sort_key(value.split("origin:", 1)[-1])),
                "critical_hosts": [
                    {
                        "id": critical_hosts_map[host_id]["id"],
                        "ip": critical_hosts_map[host_id]["ip"],
                        "device_name": critical_hosts_map[host_id]["device_name"],
                    }
                    for host_id in sorted(group["_critical_host_ids"], key=lambda value: _diagram_ip_sort_key(value.split("critical:", 1)[-1]))
                    if host_id in critical_hosts_map
                ],
                "known_host_count": len(group["_known_target_ips"]),
            })

        systems_payload = []
        for system in sorted(systems_map.values(), key=lambda item: (item["is_unknown"], item["name"].lower())):
            systems_payload.append({
                "id": system["id"],
                "name": system["name"],
                "raw_name": system["raw_name"],
                "is_unknown": system["is_unknown"],
                "network_ids": sorted(system["network_ids"]),
                "network_count": len(system["network_ids"]),
                "origin_count": len(system["_origin_ids"]),
            })

        origins_payload = []
        for origin in sorted(origins.values(), key=lambda item: (
            item["source_network_labels"][0] if item["source_network_labels"] else "",
            _diagram_ip_sort_key(item["ip"]),
        )):
            visible_network_ids = sorted({
                relation["target_network_id"]
                for relation in relations.values()
                if relation["source_origin_id"] == origin["id"]
            })
            origins_payload.append({
                "id": origin["id"],
                "ip": origin["ip"],
                "name": origin["name"],
                "scan_ids": sorted(origin["scan_ids"]),
                "scan_types": list(origin["scan_types"]),
                "locations": list(origin["locations"]),
                "scan_count": len(origin["scan_ids"]),
                "source_network_ids": list(origin["source_network_ids"]),
                "source_network_labels": list(origin["source_network_labels"]),
                "visible_network_count": len(visible_network_ids),
                "visible_host_count": len(origin["_all_visible_hosts"]),
                "local_visible_host_count": len(origin["_local_visible_hosts"]),
            })

        relations_payload = []
        for relation in sorted(relations.values(), key=lambda item: (
            _diagram_ip_sort_key(item["source_origin_id"].split("origin:", 1)[-1]),
            item["target_network_id"],
        )):
            layer_keys = sorted(
                relation["_layer_keys"],
                key=lambda value: _DIAGRAM_LAYER_META.get(value, {}).get("sort_order", 999),
            )
            relations_payload.append({
                "id": relation["id"],
                "source_origin_id": relation["source_origin_id"],
                "source_network_ids": relation["source_network_ids"],
                "target_network_id": relation["target_network_id"],
                "scan_ids": sorted(relation["_scan_ids"]),
                "target_ips": sorted(relation["_target_ips"], key=_diagram_ip_sort_key),
                "layer_keys": layer_keys,
                "layers": {
                    layer_key: {
                        "scan_ids": sorted(relation["_layer_scan_ids"].get(layer_key, set())),
                        "target_ips": sorted(relation["_layer_target_ips"].get(layer_key, set()), key=_diagram_ip_sort_key),
                    }
                    for layer_key in layer_keys
                },
                "scan_count": len(relation["_scan_ids"]),
                "visible_host_count": len(relation["_target_ips"]),
            })

        layers_payload = []
        for layer_key in sorted(layer_usage.keys(), key=lambda value: _DIAGRAM_LAYER_META.get(value, {}).get("sort_order", 999)):
            meta = _DIAGRAM_LAYER_META.get(layer_key, {
                "id": layer_key,
                "label": layer_key.upper(),
                "description": "",
                "sort_order": 999,
            })
            usage = layer_usage[layer_key]
            layers_payload.append({
                "id": meta["id"],
                "label": meta["label"],
                "description": meta["description"],
                "sort_order": meta["sort_order"],
                "scan_count": len(usage["scan_ids"]),
                "visible_host_count": len(usage["target_ips"]),
                "relation_count": len(usage["relation_ids"]),
            })

        critical_hosts_payload = []
        for critical_host in sorted(critical_hosts_map.values(), key=lambda item: (
            str(item.get("device_name") or "").lower(),
            _diagram_ip_sort_key(item["ip"]),
        )):
            critical_hosts_payload.append({
                "id": critical_host["id"],
                "ip": critical_host["ip"],
                "device_name": critical_host["device_name"],
                "system_name": critical_host["system_name"],
                "reason": critical_host["reason"],
                "network_ids": list(critical_host["network_ids"]),
                "network_labels": list(critical_host["network_labels"]),
            })

        return {
            "organization": org,
            "stats": {
                "system_count": len(systems_payload),
                "network_count": len(networks_payload),
                "origin_count": len(origins_payload),
                "relation_count": len(relations_payload),
                "critical_host_count": len(critical_hosts_payload),
            },
            "systems": systems_payload,
            "networks": networks_payload,
            "origins": origins_payload,
            "layers": layers_payload,
            "critical_hosts": critical_hosts_payload,
            "relations": relations_payload,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generando diagrama de visibilidad: {e}")


async def get_visibility_diagram(organization: str):
    return await run_in_threadpool(_get_visibility_diagram_sync, organization)


@router.get("/api/global-map")
def _get_global_map_sync(organization: str):
    """Devuelve el mapa global desde SQLite: organizaciÃ³n -> sistemas -> redes -> assets -> servicios."""
    org = organization.upper()

    def parse_network(value: str):
        try:
            return ipaddress.ip_network(str(value or "").strip(), strict=False)
        except ValueError:
            return None

    conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    try:
        org_row = conn.execute("""
            SELECT o.name, o.description, o.created_at,
                   COUNT(DISTINCT s.id) AS scan_count,
                   COUNT(DISTINCT CASE WHEN COALESCE(s.status, '') = 'completed' THEN s.id END) AS completed_scan_count,
                   COUNT(DISTINCT sr.host_id) AS asset_count,
                   COUNT(DISTINCT CASE WHEN sr.port IS NOT NULL THEN sr.id END) AS service_count,
                   MIN(s.started_at) AS first_scan_at,
                   MAX(COALESCE(s.completed_at, s.started_at)) AS last_scan_at
            FROM organizations o
            LEFT JOIN scans s ON UPPER(s.organization_name) = UPPER(o.name)
            LEFT JOIN scan_results sr ON sr.scan_id = s.id
                 AND COALESCE(s.scan_mode, 'active') != 'passive'
                 AND COALESCE(sr.discovery_method, 'unknown') != 'passive_capture'
            WHERE UPPER(o.name) = UPPER(?)
            GROUP BY o.name, o.description, o.created_at
        """, (org,)).fetchone()

        declared_rows = conn.execute("""
            SELECT system_name, network_name, network_range, purdue_level
            FROM networks
            WHERE UPPER(organization_name) = UPPER(?)
        """, (org,)).fetchall()

        asset_rows = conn.execute("""
            SELECT h.id AS host_id,
                   h.ip_address,
                   COALESCE(NULLIF(TRIM(hsm.hostname), ''), NULLIF(TRIM(h.hostname), '')) AS hostname,
                   COALESCE(NULLIF(TRIM(hsm.mac_address), ''), NULLIF(TRIM(h.mac_address), '')) AS mac_address,
                   COALESCE(NULLIF(TRIM(hsm.vendor), ''), NULLIF(TRIM(h.vendor), '')) AS vendor,
                   COUNT(DISTINCT sr.scan_id) AS scan_count,
                   COUNT(DISTINCT CASE WHEN sr.port IS NOT NULL THEN sr.id END) AS service_count,
                   MIN(sr.discovered_at) AS first_seen,
                   MAX(COALESCE(hsm.last_seen, sr.discovered_at)) AS last_seen,
                   GROUP_CONCAT(DISTINCT s.location) AS locations,
                   GROUP_CONCAT(DISTINCT s.scan_type) AS scan_types
            FROM scan_results sr
            JOIN scans s ON s.id = sr.scan_id
            JOIN hosts h ON h.id = sr.host_id
            LEFT JOIN host_scan_metadata hsm
                   ON hsm.scan_id = sr.scan_id
                  AND hsm.host_id = sr.host_id
            WHERE UPPER(s.organization_name) = UPPER(?)
              AND COALESCE(s.scan_mode, 'active') != 'passive'
              AND COALESCE(s.status, '') = 'completed'
              AND COALESCE(sr.discovery_method, 'unknown') != 'passive_capture'
              AND COALESCE(TRIM(h.ip_address), '') != ''
            GROUP BY h.id, h.ip_address
        """, (org,)).fetchall()

        service_rows = conn.execute("""
            SELECT h.ip_address,
                   sr.port,
                   COALESCE(sr.protocol, 'tcp') AS protocol,
                   COALESCE(NULLIF(TRIM(sr.service_name), ''), 'unknown') AS service_name,
                   NULLIF(TRIM(sr.product), '') AS product,
                   NULLIF(TRIM(sr.version), '') AS version,
                   COUNT(DISTINCT sr.scan_id) AS scan_count,
                   MIN(sr.discovered_at) AS first_seen,
                   MAX(sr.discovered_at) AS last_seen
            FROM scan_results sr
            JOIN scans s ON s.id = sr.scan_id
            JOIN hosts h ON h.id = sr.host_id
            WHERE UPPER(s.organization_name) = UPPER(?)
              AND COALESCE(s.scan_mode, 'active') != 'passive'
              AND COALESCE(s.status, '') = 'completed'
              AND sr.port IS NOT NULL
              AND COALESCE(sr.discovery_method, 'unknown') != 'passive_capture'
            GROUP BY h.ip_address, sr.port, COALESCE(sr.protocol, 'tcp'), COALESCE(NULLIF(TRIM(sr.service_name), ''), 'unknown'), NULLIF(TRIM(sr.product), ''), NULLIF(TRIM(sr.version), '')
        """, (org,)).fetchall()
    finally:
        conn.close()

    org_data = dict(org_row) if org_row else {
        "name": org, "description": "", "created_at": "", "scan_count": 0,
        "completed_scan_count": 0, "asset_count": 0, "service_count": 0,
        "first_scan_at": "", "last_scan_at": "",
    }
    nodes = [{
        "id": f"org:{org}",
        "type": "organization",
        "label": org,
        "title": _html_title("OrganizaciÃ³n", [
            ("Escaneos", org_data["scan_count"]),
            ("Escaneos completados", org_data["completed_scan_count"]),
            ("Activos descubiertos", org_data["asset_count"]),
            ("Servicios", org_data["service_count"]),
            ("Primer escaneo", org_data["first_scan_at"]),
            ("Ãšltimo escaneo", org_data["last_scan_at"]),
        ]),
    }]
    edges = []
    systems = {}
    networks = {}
    unknown_networks = {}

    def unique_append(values: list, value):
        if value not in (None, "") and value not in values:
            values.append(value)

    def ensure_system(name: str):
        label = str(name or "").strip() or "Sin sistema"
        system = systems.setdefault(label, {"id": f"system:{label}", "name": label, "networks": set(), "assets": set()})
        return system

    def ensure_network(system_name: str, network_range: str, network_name: str = None, purdue_level=None, parsed=None, unknown=False):
        system = ensure_system("Unknown" if unknown else system_name)
        normalized = str(parsed) if parsed else (str(network_range or "").strip() or "Unknown")
        key = (system["name"], normalized)
        network = networks.setdefault(key, {
            "id": f"network:{system['name']}:{normalized}",
            "system_id": system["id"],
            "system_name": system["name"],
            "range": normalized,
            "names": [],
            "purdue_levels": [],
            "assets": set(),
            "parsed": parsed,
            "unknown": unknown,
        })
        unique_append(network["names"], network_name)
        unique_append(network["purdue_levels"], purdue_level)
        system["networks"].add(network["id"])
        return network

    for row in declared_rows:
        ensure_network(row["system_name"], row["network_range"], row["network_name"], row["purdue_level"], parse_network(row["network_range"]))

    known_networks = list(networks.values())

    def network_for_ip(ip_value: str):
        try:
            ip_obj = ipaddress.ip_address(str(ip_value or "").strip())
        except ValueError:
            return ensure_network("Unknown", "Unknown", "Unknown", unknown=True)

        matches = [
            network for network in known_networks
            if network["parsed"] and network["parsed"].version == ip_obj.version and ip_obj in network["parsed"]
        ]
        if matches:
            return max(matches, key=lambda network: network["parsed"].prefixlen)
        bucket = ipaddress.ip_network(f"{ip_obj}/24" if ip_obj.version == 4 else f"{ip_obj}/64", strict=False)
        return unknown_networks.setdefault(str(bucket), ensure_network("Unknown", str(bucket), str(bucket), parsed=bucket, unknown=True))

    assets = {}
    for row in asset_rows:
        network = network_for_ip(row["ip_address"])
        asset_id = f"asset:{row['ip_address']}"
        assets[asset_id] = {"id": asset_id, "network_id": network["id"], "ip": row["ip_address"], "hostname": row["hostname"] or "", "services": set(), "row": dict(row)}
        network["assets"].add(asset_id)
        for system in systems.values():
            if system["id"] == network["system_id"]:
                system["assets"].add(asset_id)
                break

    for row in service_rows:
        asset_id = f"asset:{row['ip_address']}"
        if asset_id not in assets:
            continue
        service_id = f"service:{row['ip_address']}:{row['protocol']}:{row['port']}:{row['service_name']}:{row['product'] or ''}:{row['version'] or ''}"
        assets[asset_id]["services"].add(service_id)
        nodes.append({
            "id": service_id,
            "type": "service",
            "label": f"{row['port']}/{row['protocol']} {row['service_name']}",
            "title": _html_title("Servicio", [
                ("Asset", row["ip_address"]),
                ("Puerto", f"{row['port']}/{row['protocol']}"),
                ("Servicio", row["service_name"]),
                ("Producto", row["product"]),
                ("VersiÃ³n", row["version"]),
                ("Escaneos", row["scan_count"]),
                ("Primera detecciÃ³n", row["first_seen"]),
                ("Ãšltima detecciÃ³n", row["last_seen"]),
            ]),
        })
        edges.append({"from": asset_id, "to": service_id, "type": "asset-service", "label": "expone"})

    for system in sorted(systems.values(), key=lambda item: item["name"].lower()):
        nodes.append({
            "id": system["id"],
            "type": "system",
            "label": system["name"],
            "title": _html_title("Sistema", [("Redes", len(system["networks"])), ("Assets", len(system["assets"]))]),
        })
        edges.append({"from": f"org:{org}", "to": system["id"], "type": "org-system", "label": "contiene"})

    for network in sorted(networks.values(), key=lambda item: (item["unknown"], str(item["range"]))):
        display_name = " / ".join(network["names"]) if network["names"] else network["range"]
        nodes.append({
            "id": network["id"],
            "type": "network",
            "label": f"{display_name}\n{network['range']}",
            "title": _html_title("Red", [
                ("Sistema", network["system_name"]),
                ("Nombre", display_name),
                ("Rango", network["range"]),
                ("Purdue", ", ".join(map(str, network["purdue_levels"]))),
                ("Assets", len(network["assets"])),
                ("Tipo", "Descubierta" if network["unknown"] else "Declarada"),
            ]),
        })
        edges.append({"from": network["system_id"], "to": network["id"], "type": "system-network", "label": "agrupa"})

    for asset in sorted(assets.values(), key=lambda item: _diagram_ip_sort_key(item["ip"])):
        row = asset["row"]
        nodes.append({
            "id": asset["id"],
            "type": "asset",
            "label": f"{asset['ip']}\n{asset['hostname']}" if asset["hostname"] else asset["ip"],
            "title": _html_title("Asset", [
                ("IP", asset["ip"]),
                ("Hostname", asset["hostname"]),
                ("MAC", row["mac_address"]),
                ("Fabricante", row["vendor"]),
                ("Servicios", len(asset["services"])),
                ("Escaneos", row["scan_count"]),
                ("Ubicaciones", row["locations"]),
                ("Tipos de escaneo", row["scan_types"]),
                ("Primera detecciÃ³n", row["first_seen"]),
                ("Ãšltima detecciÃ³n", row["last_seen"]),
            ]),
        })
        edges.append({"from": asset["network_id"], "to": asset["id"], "type": "network-asset", "label": "descubre"})

    return {
        "organization": org,
        "nodes": nodes,
        "edges": edges,
        "stats": {
            "systems": len(systems),
            "networks": len(networks),
            "assets": len(assets),
            "services": len([node for node in nodes if node["type"] == "service"]),
        },
    }


async def get_global_map(organization: str):
    return await run_in_threadpool(_get_global_map_sync, organization)


def _asset_hostname_lookup(org: str) -> dict:
    conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute("""
            SELECT DISTINCT h.ip_address, COALESCE(h.hostname, '') AS hostname
            FROM hosts h
            JOIN scan_results sr ON sr.host_id = h.id
            JOIN scans s ON s.id = sr.scan_id
            WHERE UPPER(s.organization_name) = UPPER(?)
              AND COALESCE(s.scan_mode, 'active') != 'passive'
              AND COALESCE(s.status, '') = 'completed'
              AND COALESCE(TRIM(h.ip_address), '') != ''
        """, (org,)).fetchall()
        return {row["ip_address"]: row["hostname"] for row in rows if row["ip_address"]}
    finally:
        conn.close()


def _attack_path_asset_options(diagram: dict, org: str) -> list:
    hostnames = _asset_hostname_lookup(org)
    asset_ips = set(hostnames.keys())
    for relation in diagram.get("relations", []):
        asset_ips.update(ip for ip in relation.get("target_ips", []) if ip)
    for origin in diagram.get("origins", []):
        if origin.get("ip"):
            asset_ips.add(origin["ip"])
    for critical in diagram.get("critical_hosts", []):
        if critical.get("ip"):
            asset_ips.add(critical["ip"])

    critical_by_ip = {
        critical["ip"]: critical
        for critical in diagram.get("critical_hosts", [])
        if critical.get("ip")
    }
    options = []
    for ip in sorted(asset_ips, key=_diagram_ip_sort_key):
        critical = critical_by_ip.get(ip)
        label_parts = [ip]
        if hostnames.get(ip):
            label_parts.append(hostnames[ip])
        if critical:
            label_parts.append(f"crítico: {critical.get('device_name') or 'activo crítico'}")
        options.append({
            "ip": ip,
            "label": " · ".join(label_parts),
            "hostname": hostnames.get(ip) or None,
            "is_critical": bool(critical),
            "critical_name": critical.get("device_name") if critical else None,
        })
    return options


def _network_for_asset_ip(target_ip: str, networks: list) -> Optional[dict]:
    try:
        ip_obj = ipaddress.ip_address(str(target_ip or "").strip())
    except ValueError:
        return None

    matches = []
    for network in networks:
        try:
            parsed = ipaddress.ip_network(str(network.get("range") or ""), strict=False)
        except ValueError:
            continue
        if parsed.version == ip_obj.version and ip_obj in parsed:
            matches.append((parsed.prefixlen, network))
    if not matches:
        return None
    matches.sort(key=lambda item: item[0], reverse=True)
    return matches[0][1]


def _normalize_attack_path_layers(layer_values: Optional[str], available_layers: list) -> Optional[set]:
    available_ids = {
        str(layer.get("id"))
        for layer in available_layers
        if layer.get("id")
    }
    if not layer_values:
        return {
            layer_id for layer_id in available_ids
            if _DIAGRAM_LAYER_META.get(layer_id, {}).get("sort_order", 999) >= 1
        } or available_ids

    raw_values = {
        str(value or "").strip().lower()
        for value in str(layer_values).split(",")
        if str(value or "").strip()
    }
    if not raw_values or "all" in raw_values or "*" in raw_values:
        return None

    selected = {layer_id for layer_id in raw_values if layer_id in available_ids}
    return selected or set()


def _filter_attack_path_relation_layers(relation: dict, selected_layers: Optional[set]) -> Optional[dict]:
    if selected_layers is None:
        return relation

    matched_layers = [
        layer_key for layer_key in relation.get("layer_keys") or []
        if layer_key in selected_layers
    ]
    if not matched_layers:
        return None

    target_ips = set()
    scan_ids = set()
    layers = relation.get("layers") or {}
    for layer_key in matched_layers:
        layer_entry = layers.get(layer_key) or {}
        target_ips.update(layer_entry.get("target_ips") or [])
        scan_ids.update(layer_entry.get("scan_ids") or [])

    if not target_ips:
        return None

    filtered = dict(relation)
    filtered["layer_keys"] = matched_layers
    filtered["target_ips"] = sorted(target_ips, key=_diagram_ip_sort_key)
    filtered["scan_ids"] = sorted(scan_ids)
    filtered["visible_host_count"] = len(target_ips)
    filtered["scan_count"] = len(scan_ids)
    return filtered


def _origin_graph_for_attack_path(diagram: dict, target_ip: str, target_network: dict,
                                  selected_layers: Optional[set] = None) -> dict:
    origins = {origin["id"]: origin for origin in diagram.get("origins", [])}
    origin_by_ip = {
        origin["ip"]: origin
        for origin in origins.values()
        if origin.get("ip")
    }
    target_network_id = target_network.get("id") if target_network else None
    direct_relations = {}
    origin_edges = {}

    for raw_relation in diagram.get("relations", []):
        relation = _filter_attack_path_relation_layers(raw_relation, selected_layers)
        if not relation:
            continue
        source_id = relation.get("source_origin_id")
        target_ips = set(relation.get("target_ips") or [])
        if not source_id or source_id not in origins:
            continue

        if target_ip in target_ips or (
            relation.get("target_network_id") == target_network_id and target_ip in target_ips
        ):
            direct_relations.setdefault(source_id, relation)

        for visible_ip in target_ips:
            target_origin = origin_by_ip.get(visible_ip)
            if not target_origin:
                continue
            target_origin_id = target_origin["id"]
            if target_origin_id == source_id:
                continue
            origin_edges.setdefault(source_id, {})[target_origin_id] = relation

    incoming = {}
    for source_id, targets in origin_edges.items():
        for target_origin_id, relation in targets.items():
            incoming.setdefault(target_origin_id, []).append((source_id, relation))

    hop_count = {}
    next_hop = {}
    next_relation = {}
    queue = []
    for origin_id in sorted(direct_relations.keys()):
        hop_count[origin_id] = 1
        next_hop[origin_id] = "__target__"
        next_relation[origin_id] = direct_relations[origin_id]
        queue.append(origin_id)

    cursor = 0
    while cursor < len(queue):
        current_id = queue[cursor]
        cursor += 1
        for source_id, relation in incoming.get(current_id, []):
            if source_id in hop_count:
                continue
            hop_count[source_id] = hop_count[current_id] + 1
            next_hop[source_id] = current_id
            next_relation[source_id] = relation
            queue.append(source_id)

    max_hops = max(hop_count.values()) if hop_count else 0
    origin_payload = []
    for origin in origins.values():
        origin_id = origin["id"]
        hops = hop_count.get(origin_id)
        source_network_ids = origin.get("source_network_ids") or []
        source_network = None
        if source_network_ids:
            source_network = next(
                (network for network in diagram.get("networks", [])
                 if network.get("id") == source_network_ids[0]),
                None,
            )
        origin_payload.append({
            "id": origin_id,
            "ip": origin.get("ip"),
            "locations": origin.get("locations") or [],
            "source_network_labels": origin.get("source_network_labels") or [],
            "source_network": source_network,
            "reachable": hops is not None,
            "hop_count": hops,
            "column": 0 if hops is None else max_hops - hops + 1,
            "next_hop_origin_id": None if next_hop.get(origin_id) == "__target__" else next_hop.get(origin_id),
        })

    edges = []
    for origin in origin_payload:
        if not origin["reachable"]:
            continue
        relation = next_relation.get(origin["id"]) or {}
        if origin["next_hop_origin_id"]:
            edges.append({
                "source_origin_id": origin["id"],
                "target_origin_id": origin["next_hop_origin_id"],
                "style": "dashed",
                "kind": "pivot",
                "visible_host_count": relation.get("visible_host_count", 0),
                "layer_keys": relation.get("layer_keys") or [],
            })
        else:
            edges.append({
                "source_origin_id": origin["id"],
                "target_network_id": target_network_id,
                "style": "solid",
                "kind": "direct",
                "visible_host_count": relation.get("visible_host_count", 0),
                "layer_keys": relation.get("layer_keys") or [],
            })

    columns = [{
        "index": 0,
        "label": "Sin camino",
        "description": "Orígenes sin ruta conocida hacia el objetivo",
        "origin_ids": sorted(
            [origin["id"] for origin in origin_payload if not origin["reachable"]],
            key=lambda origin_id: _diagram_ip_sort_key(origins[origin_id].get("ip")),
        ),
    }]
    for hops in range(max_hops, 0, -1):
        column_index = max_hops - hops + 1
        columns.append({
            "index": column_index,
            "label": f"{hops} salto{'s' if hops != 1 else ''}",
            "description": "Ruta indirecta" if hops > 1 else "Visibilidad directa",
            "origin_ids": sorted(
                [origin["id"] for origin in origin_payload if origin["hop_count"] == hops],
                key=lambda origin_id: _diagram_ip_sort_key(origins[origin_id].get("ip")),
            ),
        })

    return {
        "origins": sorted(
            origin_payload,
            key=lambda item: (
                item["column"],
                _diagram_ip_sort_key(item.get("ip")),
            ),
        ),
        "edges": edges,
        "columns": columns,
        "max_hops": max_hops,
        "reachable_count": len([origin for origin in origin_payload if origin["reachable"]]),
        "direct_count": len([origin for origin in origin_payload if origin["hop_count"] == 1]),
        "indirect_count": len([origin for origin in origin_payload if (origin["hop_count"] or 0) > 1]),
        "unreachable_count": len([origin for origin in origin_payload if not origin["reachable"]]),
    }


@router.get("/api/attack-path")
def _get_attack_path_sync(organization: str, target_ip: Optional[str] = None, layers: Optional[str] = None):
    """Devuelve el grafo de caminos de ataque hacia un asset objetivo."""
    try:
        org = organization.upper()
        diagram = _get_visibility_diagram_sync(org)
        selected_layers = _normalize_attack_path_layers(layers, diagram.get("layers", []))
        asset_options = _attack_path_asset_options(diagram, org)
        layers_payload = []
        for layer in diagram.get("layers", []):
            layer_id = layer.get("id")
            item = dict(layer)
            item["selected"] = selected_layers is None or layer_id in selected_layers
            item["default_selected"] = _DIAGRAM_LAYER_META.get(layer_id, {}).get("sort_order", 999) >= 1
            layers_payload.append(item)
        selected_ip = str(target_ip or "").strip()
        if not selected_ip:
            return {
                "organization": org,
                "asset_options": asset_options,
                "layers": layers_payload,
                "target": None,
                "target_network": None,
                "columns": [],
                "origins": [],
                "edges": [],
                "stats": {
                    "origin_count": len(diagram.get("origins", [])),
                    "reachable_count": 0,
                    "direct_count": 0,
                    "indirect_count": 0,
                    "unreachable_count": len(diagram.get("origins", [])),
                },
            }

        try:
            ipaddress.ip_address(selected_ip)
        except ValueError:
            raise HTTPException(status_code=400, detail="La IP objetivo no es válida")

        target_network = _network_for_asset_ip(selected_ip, diagram.get("networks", []))
        selected_option = next((option for option in asset_options if option["ip"] == selected_ip), None)
        if not target_network:
            return {
                "organization": org,
                "asset_options": asset_options,
                "layers": layers_payload,
                "target": {
                    "ip": selected_ip,
                    "label": selected_option["label"] if selected_option else selected_ip,
                    "found": selected_option is not None,
                },
                "target_network": None,
                "columns": [],
                "origins": [],
                "edges": [],
                "stats": {
                    "origin_count": len(diagram.get("origins", [])),
                    "reachable_count": 0,
                    "direct_count": 0,
                    "indirect_count": 0,
                    "unreachable_count": len(diagram.get("origins", [])),
                },
                "message": "No se ha encontrado una red asociada a la IP objetivo.",
            }

        graph = _origin_graph_for_attack_path(diagram, selected_ip, target_network, selected_layers)
        return {
            "organization": org,
            "asset_options": asset_options,
            "layers": layers_payload,
            "target": {
                "ip": selected_ip,
                "label": selected_option["label"] if selected_option else selected_ip,
                "found": selected_option is not None,
            },
            "target_network": target_network,
            "columns": graph["columns"],
            "origins": graph["origins"],
            "edges": graph["edges"],
            "stats": {
                "origin_count": len(graph["origins"]),
                "reachable_count": graph["reachable_count"],
                "direct_count": graph["direct_count"],
                "indirect_count": graph["indirect_count"],
                "unreachable_count": graph["unreachable_count"],
                "max_hops": graph["max_hops"],
            },
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generando attack path: {e}")


@router.get("/api/attack-path/candidates")
def _get_attack_path_candidates_sync(organization: str, min_hops: int = 2, limit: int = 50,
                                     layers: Optional[str] = None):
    """Devuelve assets que generan attack paths con al menos min_hops saltos."""
    try:
        org = organization.upper()
        min_hops = max(2, int(min_hops or 2))
        limit = max(1, min(200, int(limit or 50)))
        base = _get_attack_path_sync(org, layers=layers)
        candidates = []
        for asset in base.get("asset_options", []):
            data = _get_attack_path_sync(org, asset["ip"], layers=layers)
            stats = data.get("stats") or {}
            if (stats.get("max_hops") or 0) >= min_hops:
                candidates.append({
                    "ip": asset["ip"],
                    "label": asset.get("label") or asset["ip"],
                    "target_network": data.get("target_network"),
                    "stats": stats,
                })
            if len(candidates) >= limit:
                break

        candidates.sort(
            key=lambda item: (
                -(item["stats"].get("max_hops") or 0),
                -(item["stats"].get("indirect_count") or 0),
                _diagram_ip_sort_key(item["ip"]),
            )
        )
        return {
            "organization": org,
            "min_hops": min_hops,
            "count": len(candidates),
            "candidates": candidates,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error buscando attack paths: {e}")


async def get_attack_path(organization: str, target_ip: Optional[str] = None, layers: Optional[str] = None):
    return await run_in_threadpool(_get_attack_path_sync, organization, target_ip, layers)


async def get_attack_path_candidates(organization: str, min_hops: int = 2, limit: int = 50,
                                     layers: Optional[str] = None):
    return await run_in_threadpool(_get_attack_path_candidates_sync, organization, min_hops, limit, layers)


_FINDING_SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

_FINDING_SEVERITY_LABEL = {
    "critical": "Crítica",
    "high": "Alta",
    "medium": "Media",
    "low": "Baja",
    "info": "Info",
}

_FINDING_OT_PORTS = (
    102, 502, 789, 1089, 1090, 1091, 1911, 1962, 2222, 2223, 2404, 4000,
    4840, 4843, 4911, 5901, 7890, 9600, 10000, 12320, 12321, 18245, 18246,
    19999, 20000, 20547, 34962, 34963, 34964, 34980, 44818, 46823, 46824,
    47808, 47809, 47810, 47820, 55000, 55001, 55002, 55003, 55555, 55556,
    55900, 55901, 55902, 55903, 61408, 62351, 62352, 62353, 62354, 62355,
)

_FINDING_CANDIDATE_RULES = [
    {
        "id": "purdue-cross-level",
        "name": "Cruce Purdue IT/DMZ hacia OT",
        "category": "Segmentación",
        "description": "Detecta visibilidad desde zonas IT/DMZ (L5/L4) hacia OT (L3 o inferior) y desde Plant DMZ (L3.5) hacia celdas/control (L2 o inferior).",
        "data_sources": ["visibility_diagram", "networks", "scan_results", "scans"],
        "evidence_policy": "Solo usa relaciones calculadas desde resultados de escaneo y redes declaradas en SQLite.",
    },
    {
        "id": "critical-reachable",
        "name": "Activo crítico alcanzable",
        "category": "Activos críticos",
        "description": "Detecta IPs declaradas como críticas que aparecen como destino en una relación de visibilidad.",
        "data_sources": ["visibility_diagram", "critical_devices", "scan_results"],
        "evidence_policy": "No infiere criticidad: la IP debe estar en la tabla de dispositivos críticos.",
    },
    {
        "id": "shadow-network",
        "name": "Red no inventariada o de proveedor",
        "category": "Inventario",
        "description": "Detecta redes desconocidas por correlación de IPs fuera de rangos declarados o redes cuyo nombre/sistema indica proveedor, shadow o no inventariada.",
        "data_sources": ["visibility_diagram", "networks", "scan_results"],
        "evidence_policy": "La red debe existir como red declarada o como bucket desconocido generado por IPs observadas.",
    },
    {
        "id": "credentials",
        "name": "Credenciales recuperadas",
        "category": "Credenciales",
        "description": "Detecta credenciales guardadas por importaciones NetExec persistidas en la tabla credentials.",
        "data_sources": ["credentials"],
        "evidence_policy": "Usa SQLite como fuente canónica; la nota CREDENCIALES.md es una representación gestionada de esos datos.",
    },
    {
        "id": "web-evidence",
        "name": "Evidencia web disponible",
        "category": "Evidencia web",
        "description": "Detecta evidencias web guardadas en enrichments y prioriza interfaces propias de activos industriales cuando el servicio/producto observado contiene términos OT como HMI, SCADA, PLC, Historian, WinCC, FactoryTalk, Ignition, AVEVA, ThinManager o gateway.",
        "data_sources": ["enrichments", "scan_results", "hosts", "scans"],
        "evidence_policy": "Solo se crea si existe Screenshot/Websource en SQLite; la clasificación OT se basa en service_name/product/version observados o en activo crítico declarado.",
    },
    {
        "id": "industrial-service",
        "name": "Servicio industrial expuesto",
        "category": "Exposición OT",
        "description": "Detecta puertos incluidos en la opción de escaneo Nmap de puertos OT sobre redes Purdue L3 o inferiores.",
        "data_sources": ["scan_results", "hosts", "scans", "networks"],
        "evidence_policy": "Es un candidato de exposición, no una vulnerabilidad; requiere validación del auditor antes de convertirlo en finding.",
    },
    {
        "id": "attack-path",
        "name": "Ruta de ataque indirecta",
        "category": "Attack path",
        "description": "Detecta activos con rutas de visibilidad indirectas de dos o más saltos usando capas L3/L7.",
        "data_sources": ["visibility_diagram", "attack_path"],
        "evidence_policy": "Usa el cálculo local de attack path basado en relaciones de visibilidad; no asume explotación real.",
    },
]

_FINDING_CANDIDATE_RULES_BY_ID = {
    rule["id"]: rule
    for rule in _FINDING_CANDIDATE_RULES
}


def _finding_clean(value, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default


def _finding_truncate(value, max_len: int = 260) -> str:
    text = " ".join(_finding_clean(value).split())
    if len(text) <= max_len:
        return text
    return f"{text[:max_len - 1].rstrip()}…"


def _finding_slug(value: str) -> str:
    slug = "".join(ch.lower() if ch.isascii() and ch.isalnum() else "-" for ch in _finding_clean(value))
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug.strip("-")[:140] or "item"


def _finding_id(kind: str, *parts) -> str:
    return f"{kind}:{_finding_slug('|'.join(_finding_clean(part) for part in parts))}"


def _finding_unique(values, limit: int = None) -> list:
    seen = set()
    result = []
    for value in values or []:
        text = _finding_clean(value)
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
        if limit and len(result) >= limit:
            break
    return result


def _finding_join(values, limit: int = 8, empty: str = "Sin datos") -> str:
    unique = _finding_unique(values, limit=limit)
    if not unique:
        return empty
    suffix = ""
    if values and len(_finding_unique(values)) > len(unique):
        suffix = "…"
    return ", ".join(unique) + suffix


def _finding_network_levels(network: dict) -> list:
    levels = []
    for level in (network or {}).get("purdue_levels") or []:
        try:
            parsed = float(level)
        except (TypeError, ValueError):
            continue
        if parsed in {0.0, 1.0, 2.0, 3.0, 3.5, 4.0, 5.0}:
            levels.append(parsed)
    return sorted(set(levels), reverse=True)


def _finding_format_level(level) -> str:
    try:
        parsed = float(level)
    except (TypeError, ValueError):
        return str(level)
    return str(int(parsed)) if parsed.is_integer() else str(parsed)


def _finding_purdue_level_name(level) -> str:
    labels = {
        5.0: "Internet DMZ",
        4.0: "Enterprise Zone",
        3.5: "Plant DMZ",
        3.0: "Control Center / Processing LAN",
        2.0: "Local HMI LAN",
        1.0: "Controller LAN",
        0.0: "Physical Process / Field I/O",
    }
    try:
        parsed = float(level)
    except (TypeError, ValueError):
        return f"Nivel {level}"
    return labels.get(parsed, f"Nivel {_finding_format_level(parsed)}")


def _finding_network_label(network: dict) -> str:
    if not network:
        return "Red desconocida"
    display = _finding_clean(network.get("display_name"), "Red")
    net_range = _finding_clean(network.get("range"))
    system = _finding_clean(network.get("system_name"))
    levels = _finding_network_levels(network)
    level_text = f" · Purdue L{', L'.join(_finding_format_level(level) for level in levels)}" if levels else ""
    range_text = f" ({net_range})" if net_range and net_range != display else ""
    system_text = f"{system} / " if system else ""
    return f"{system_text}{display}{range_text}{level_text}"


def _finding_origin_label(origin: dict) -> str:
    if not origin:
        return "Origen desconocido"
    locations = _finding_join(origin.get("locations") or [], limit=3, empty="")
    ip = _finding_clean(origin.get("ip"), "sin IP")
    return f"{locations} ({ip})" if locations else ip


def _finding_layer_labels(layer_keys: list) -> str:
    labels = []
    for layer_key in layer_keys or []:
        meta = _DIAGRAM_LAYER_META.get(layer_key) or {}
        labels.append(meta.get("label") or str(layer_key).upper())
    return _finding_join(labels, limit=5, empty="Sin capa")


def _finding_evidence(*rows) -> list:
    evidence = []
    for label, value in rows:
        text = _finding_clean(value)
        if text:
            evidence.append({"label": label, "value": text})
    return evidence


def _finding_report_hint(title: str, summary: str, evidence: list, impact: str, recommendation: str) -> str:
    evidence_text = "\n".join(
        f"- {item['label']}: {item['value']}"
        for item in evidence
        if item.get("value")
    )
    sections = [
        f"### {title}",
        summary,
    ]
    if evidence_text:
        sections.append(f"Evidencia observada:\n{evidence_text}")
    if impact:
        sections.append(f"Impacto potencial:\n{impact}")
    if recommendation:
        sections.append(f"Recomendación:\n{recommendation}")
    return "\n\n".join(sections)


def _finding_candidate(kind: str, category: str, severity: str, title: str, summary: str,
                       impact: str, recommendation: str, evidence: list, links: list = None,
                       confidence: str = "media", tags: list = None, assets: list = None,
                       origins: list = None, rule_id: str = None) -> dict:
    severity_key = _finding_clean(severity, "info").lower()
    if severity_key not in _FINDING_SEVERITY_ORDER:
        severity_key = "info"
    resolved_rule_id = rule_id or kind
    rule = _FINDING_CANDIDATE_RULES_BY_ID.get(resolved_rule_id) or {}
    candidate = {
        "id": _finding_id(kind, title, summary),
        "kind": kind,
        "rule_id": resolved_rule_id,
        "rule_name": rule.get("name") or resolved_rule_id,
        "category": category,
        "severity": severity_key,
        "severity_label": _FINDING_SEVERITY_LABEL[severity_key],
        "severity_rank": _FINDING_SEVERITY_ORDER[severity_key],
        "confidence": confidence,
        "title": title,
        "summary": summary,
        "impact": impact,
        "recommendation": recommendation,
        "evidence": evidence or [],
        "links": links or [],
        "tags": _finding_unique(tags or [], limit=12),
        "assets": _finding_unique(assets or [], limit=24),
        "origins": _finding_unique(origins or [], limit=24),
        "rule": rule,
    }
    candidate["report_hint"] = _finding_report_hint(
        candidate["title"],
        candidate["summary"],
        candidate["evidence"],
        candidate["impact"],
        candidate["recommendation"],
    )
    return candidate


def _finding_add_candidate(candidates: list, seen: set, candidate: dict):
    candidate_id = candidate.get("id")
    if not candidate_id or candidate_id in seen:
        return
    seen.add(candidate_id)
    candidates.append(candidate)


def _finding_host_networks(ip_value: str, networks: list) -> list:
    try:
        ip_obj = ipaddress.ip_address(str(ip_value or "").strip())
    except ValueError:
        return []
    matches = []
    for network in networks or []:
        try:
            parsed = ipaddress.ip_network(str(network.get("range") or ""), strict=False)
        except ValueError:
            continue
        if parsed.version == ip_obj.version and ip_obj in parsed:
            matches.append((parsed.prefixlen, network))
    if not matches:
        return []
    best_prefix = max(item[0] for item in matches)
    return [network for prefix, network in matches if prefix == best_prefix]


def _finding_ot_web_matches(service_text: str) -> list:
    terms = {
        "hmi": "HMI",
        "scada": "SCADA",
        "plc": "PLC",
        "historian": "Historian",
        "ignition": "Ignition",
        "wincc": "WinCC",
        "factorytalk": "FactoryTalk",
        "aveva": "AVEVA",
        "thinmanager": "ThinManager",
        "gateway": "Gateway",
    }
    normalized = _finding_clean(service_text).lower()
    return [label for token, label in terms.items() if token in normalized]


@router.get("/api/finding-candidate-rules")
async def get_finding_candidate_rules():
    """Devuelve las reglas locales usadas para generar candidatos de hallazgos."""
    return {
        "rules": _FINDING_CANDIDATE_RULES,
        "count": len(_FINDING_CANDIDATE_RULES),
        "principle": "Los candidatos no son findings finales: cada regla debe apoyarse en evidencias locales y ser revisada por el auditor.",
    }


@router.get("/api/finding-candidates")
def _get_finding_candidates_sync(organization: str, include_medium: bool = True):
    """Sugiere hallazgos candidatos revisables para acelerar la redacción del informe."""
    try:
        org = organization.upper()
        org_url = quote(org, safe="")
        links = {
            "results": f"/pentest/{org_url}/recon/results",
            "visibility": f"/pentest/{org_url}/recon/visibility-diagram",
            "attack_path": f"/pentest/{org_url}/recon/attack-path",
            "findings": f"/pentest/{org_url}/recon/findings",
            "global_map": f"/pentest/{org_url}/recon/global-map",
        }

        diagram = _get_visibility_diagram_sync(org)
        networks = {network["id"]: network for network in diagram.get("networks", [])}
        origins = {origin["id"]: origin for origin in diagram.get("origins", [])}
        critical_by_ip = {
            critical["ip"]: critical
            for critical in diagram.get("critical_hosts", [])
            if critical.get("ip")
        }
        candidates = []
        seen = set()

        for relation in diagram.get("relations", []):
            origin = origins.get(relation.get("source_origin_id"))
            target_network = networks.get(relation.get("target_network_id"))
            target_levels = _finding_network_levels(target_network)
            source_networks = [
                networks[source_id]
                for source_id in relation.get("source_network_ids") or []
                if source_id in networks
            ]
            source_levels = [
                level
                for network in source_networks
                for level in _finding_network_levels(network)
            ]
            source_max_level = max(source_levels) if source_levels else None
            target_min_level = min(target_levels) if target_levels else None
            enterprise_to_ot = source_max_level is not None and source_max_level >= 4 and target_min_level is not None and target_min_level <= 3
            plant_dmz_to_cell = source_max_level == 3.5 and target_min_level is not None and target_min_level <= 2
            if enterprise_to_ot or plant_dmz_to_cell:
                severity = "critical" if target_min_level is not None and target_min_level <= 2 else "high"
                target_hosts = relation.get("target_ips") or []
                evidence = _finding_evidence(
                    ("Origen", _finding_origin_label(origin)),
                    ("Red origen", _finding_join([_finding_network_label(network) for network in source_networks], limit=4)),
                    ("Red destino", _finding_network_label(target_network)),
                    ("Zona Purdue destino", _finding_purdue_level_name(target_min_level)),
                    ("Hosts visibles", _finding_join(target_hosts, limit=8)),
                    ("Capas de detección", _finding_layer_labels(relation.get("layer_keys"))),
                    ("Escaneos implicados", _finding_join(relation.get("scan_ids"), limit=8)),
                )
                target_level_text = " / ".join(f"L{_finding_format_level(level)}" for level in target_levels)
                source_level_text = f"L{_finding_format_level(source_max_level)}"
                title = f"Visibilidad desde Purdue {source_level_text} hacia {target_network.get('display_name') if target_network else 'red OT'}"
                summary = (
                    f"El origen {_finding_origin_label(origin)} en una zona Purdue {source_level_text} alcanza "
                    f"{len(target_hosts)} host(s) en una red destino {target_level_text} ({_finding_purdue_level_name(target_min_level)})."
                )
                _finding_add_candidate(candidates, seen, _finding_candidate(
                    "purdue-cross-level",
                    "Segmentación",
                    severity,
                    title,
                    summary,
                    "La conectividad directa entre IT/DMZ y redes OT de supervisión, control o proceso puede facilitar movimiento lateral y exposición de activos industriales.",
                    "Revisar reglas de filtrado, rutas, ACL y saltos permitidos; documentar únicamente los flujos justificados y bloquear el resto.",
                    evidence,
                    links=[{"label": "Ver diagrama de visibilidad", "href": links["visibility"]}],
                    confidence="alta",
                    tags=["Purdue", "segmentación", "visibilidad"],
                    assets=target_hosts,
                    origins=[_finding_origin_label(origin)],
                ))

            for target_ip in relation.get("target_ips") or []:
                critical = critical_by_ip.get(target_ip)
                if not critical:
                    continue
                target_levels = _finding_network_levels(target_network)
                source_max_level = max(source_levels) if source_levels else None
                severity = "critical" if (target_levels and min(target_levels) <= 2) or source_max_level == 5 else "high"
                evidence = _finding_evidence(
                    ("Activo crítico", f"{critical.get('device_name') or target_ip} ({target_ip})"),
                    ("Motivo de criticidad", critical.get("reason")),
                    ("Origen con visibilidad", _finding_origin_label(origin)),
                    ("Red destino", _finding_network_label(target_network)),
                    ("Capas de detección", _finding_layer_labels(relation.get("layer_keys"))),
                )
                _finding_add_candidate(candidates, seen, _finding_candidate(
                    "critical-reachable",
                    "Activos críticos",
                    severity,
                    f"Activo crítico alcanzable: {critical.get('device_name') or target_ip}",
                    f"El activo crítico {target_ip} aparece alcanzable desde {_finding_origin_label(origin)}.",
                    "La exposición de activos críticos reduce las barreras de contención y puede convertir una visibilidad de red en una ruta de compromiso operativo.",
                    "Validar si el flujo está autorizado, restringirlo a bastiones o servicios concretos y monitorizar los intentos de acceso a este activo.",
                    evidence,
                    links=[
                        {"label": "Ver visibilidad", "href": links["visibility"]},
                        {"label": "Analizar attack path", "href": f"{links['attack_path']}?target_ip={quote(target_ip, safe='')}&layers=l3,l7"},
                    ],
                    confidence="alta",
                    tags=["activo crítico", "exposición"],
                    assets=[target_ip],
                    origins=[_finding_origin_label(origin)],
                ))

        for network in diagram.get("networks", []):
            network_text = " ".join([
                _finding_clean(network.get("system_name")),
                _finding_clean(network.get("display_name")),
                _finding_clean(network.get("range")),
                _finding_join(network.get("network_names") or [], limit=5, empty=""),
            ]).lower()
            looks_shadow = (
                network.get("is_unknown")
                or "shadow" in network_text
                or "proveedor" in network_text
                or "vendor" in network_text
                or "no inventari" in network_text
            )
            if not looks_shadow:
                continue
            incoming_origins = [
                _finding_origin_label(origins[origin_id])
                for origin_id in network.get("incoming_origin_ids") or []
                if origin_id in origins
            ]
            critical_hosts = [
                f"{host.get('device_name') or host.get('ip')} ({host.get('ip')})"
                for host in network.get("critical_hosts") or []
            ]
            severity = "high" if incoming_origins or critical_hosts else "medium"
            evidence = _finding_evidence(
                ("Red", _finding_network_label(network)),
                ("Tipo", "Descubierta/no inventariada" if network.get("is_unknown") else "Declarada como no inventariada o proveedor"),
                ("Hosts conocidos", network.get("known_host_count")),
                ("Orígenes con visibilidad entrante", _finding_join(incoming_origins, limit=6)),
                ("Activos críticos asociados", _finding_join(critical_hosts, limit=6)),
            )
            _finding_add_candidate(candidates, seen, _finding_candidate(
                "shadow-network",
                "Inventario",
                severity,
                f"Red no inventariada o de proveedor: {network.get('display_name') or network.get('range')}",
                "Se ha detectado una red que requiere validación de inventario, ownership y exposición real dentro del alcance.",
                "Las redes no inventariadas suelen ocultar accesos de terceros, saltos de mantenimiento o activos fuera del control habitual.",
                "Confirmar propietario, propósito, punto de entrada y necesidad de conectividad; registrar la red y aislarla si no está justificada.",
                evidence,
                links=[
                    {"label": "Ver mapa global", "href": links["global_map"]},
                    {"label": "Ver visibilidad", "href": links["visibility"]},
                ],
                confidence="media",
                tags=["inventario", "terceros", "shadow IT/OT"],
                assets=[host.get("ip") for host in network.get("critical_hosts") or []],
                origins=incoming_origins,
            ))

        conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        try:
            credential_rows = conn.execute("""
                SELECT domain, username, password, credtype, source_protocol, source_host_ip, scan_id, created_at
                FROM credentials
                WHERE UPPER(organization_name) = UPPER(?)
                ORDER BY created_at DESC, domain, username
            """, (org,)).fetchall()

            web_rows = conn.execute("""
                SELECT h.ip_address,
                       COALESCE(NULLIF(TRIM(h.hostname), ''), '') AS hostname,
                       sr.port, COALESCE(sr.protocol, 'tcp') AS protocol,
                       COALESCE(sr.service_name, '') AS service_name,
                       COALESCE(sr.product, '') AS product,
                       COALESCE(sr.version, '') AS version,
                       s.id AS scan_id, s.location, s.myip AS source_ip,
                       SUM(CASE WHEN LOWER(e.enrichment_type) = 'screenshot' THEN 1 ELSE 0 END) AS screenshot_count,
                       SUM(CASE WHEN LOWER(e.enrichment_type) IN ('websource', 'source', 'source_code') THEN 1 ELSE 0 END) AS source_count
                FROM enrichments e
                JOIN scan_results sr ON sr.id = e.scan_result_id
                JOIN hosts h ON h.id = sr.host_id
                JOIN scans s ON s.id = sr.scan_id
                WHERE UPPER(s.organization_name) = UPPER(?)
                  AND COALESCE(s.scan_mode, 'active') != 'passive'
                  AND LOWER(e.enrichment_type) IN ('screenshot', 'websource', 'source', 'source_code')
                  AND sr.port IS NOT NULL
                GROUP BY h.ip_address, h.hostname, sr.port, COALESCE(sr.protocol, 'tcp'),
                         COALESCE(sr.service_name, ''), COALESCE(sr.product, ''), COALESCE(sr.version, ''),
                         s.id, s.location, s.myip
                ORDER BY h.ip_address, sr.port
                LIMIT 40
            """, (org,)).fetchall()

            ot_port_placeholders = ",".join("?" for _ in _FINDING_OT_PORTS)
            service_rows = conn.execute(f"""
                SELECT DISTINCT h.ip_address,
                       COALESCE(NULLIF(TRIM(h.hostname), ''), '') AS hostname,
                       sr.port, COALESCE(sr.protocol, 'tcp') AS protocol,
                       COALESCE(sr.service_name, '') AS service_name,
                       COALESCE(sr.product, '') AS product,
                       COALESCE(sr.version, '') AS version,
                       s.id AS scan_id, s.location, s.myip AS source_ip
                FROM scan_results sr
                JOIN hosts h ON h.id = sr.host_id
                JOIN scans s ON s.id = sr.scan_id
                WHERE UPPER(s.organization_name) = UPPER(?)
                  AND COALESCE(s.scan_mode, 'active') != 'passive'
                  AND COALESCE(sr.discovery_method, 'unknown') != 'passive_capture'
                  AND sr.port IS NOT NULL
                  AND sr.port IN ({ot_port_placeholders})
                ORDER BY h.ip_address, sr.port
                LIMIT 60
            """, (org, *_FINDING_OT_PORTS)).fetchall()
        finally:
            conn.close()

        if credential_rows:
            privileged_rows = []
            for row in credential_rows:
                username = _finding_clean(row["username"]).lower()
                password = _finding_clean(row["password"]).lower()
                credtype = _finding_clean(row["credtype"]).lower()
                if any(token in username for token in ("admin", "adm", "svc", "engineer")) or password in {"admin", "password", "welcome1!"} or credtype in {"ntlm", "hash"}:
                    privileged_rows.append(row)
            credential_samples = [
                f"{_finding_clean(row['domain'], '.')}\\{row['username']} ({_finding_clean(row['credtype'], 'secreto')}, {_finding_clean(row['source_protocol'], 'origen desconocido')} desde {_finding_clean(row['source_host_ip'], 'sin host')})"
                for row in credential_rows[:8]
            ]
            source_hosts = _finding_unique([row["source_host_ip"] for row in credential_rows], limit=12)
            evidence = _finding_evidence(
                ("Credenciales únicas", len(credential_rows)),
                ("Dominios", _finding_join([row["domain"] for row in credential_rows], limit=8)),
                ("Usuarios de muestra", _finding_join(credential_samples, limit=8)),
                ("Hosts origen", _finding_join(source_hosts, limit=8)),
                ("Protocolos", _finding_join([row["source_protocol"] for row in credential_rows], limit=8)),
            )
            _finding_add_candidate(candidates, seen, _finding_candidate(
                "credentials",
                "Credenciales",
                "critical" if privileged_rows else "high",
                "Credenciales recuperadas durante la auditoría",
                f"Se han almacenado {len(credential_rows)} credencial(es) o secreto(s) asociados a la organización.",
                "Las credenciales recuperadas pueden permitir movimiento lateral, acceso persistente o pivote hacia redes y sistemas OT.",
                "Revisar origen de la exposición, rotar secretos, forzar MFA donde aplique y analizar reutilización de cuentas en IT/OT.",
                evidence,
                links=[
                    {"label": "Ver bitácora", "href": f"/pentest/{org_url}/bitacora"},
                    {"label": "Crear finding", "href": links["findings"]},
                ],
                confidence="alta",
                tags=["credenciales", "movimiento lateral"],
                assets=source_hosts,
            ))

        for row in web_rows:
            row_dict = dict(row)
            ip_value = _finding_clean(row_dict.get("ip_address"))
            port_value = row_dict.get("port")
            service_text = " ".join([
                _finding_clean(row_dict.get("service_name")),
                _finding_clean(row_dict.get("product")),
                _finding_clean(row_dict.get("version")),
            ]).lower()
            ot_matches = _finding_ot_web_matches(service_text)
            is_critical_asset = ip_value in critical_by_ip
            is_ot_console = bool(ot_matches) or is_critical_asset
            if not is_ot_console and not include_medium:
                continue
            endpoint = f"{ip_value}:{port_value}/{_finding_clean(row_dict.get('protocol'), 'tcp')}"
            severity = "high" if is_ot_console else "medium"
            detection_reason = (
                f"Términos OT observados: {_finding_join(ot_matches, limit=8)}"
                if ot_matches
                else "Activo crítico declarado" if is_critical_asset
                else "Evidencia web sin término OT específico"
            )
            evidence = _finding_evidence(
                ("Consola/servicio", f"{endpoint} · {_finding_clean(row_dict.get('service_name'), 'web')} {_finding_clean(row_dict.get('product'))}".strip()),
                ("Motivo de clasificación", detection_reason),
                ("Activo", f"{ip_value} · {row_dict.get('hostname')}" if row_dict.get("hostname") else ip_value),
                ("Capturas", row_dict.get("screenshot_count")),
                ("Código fuente", row_dict.get("source_count")),
                ("Origen del escaneo", f"{row_dict.get('location') or 'sin ubicación'} ({row_dict.get('source_ip') or 'sin IP origen'})"),
            )
            row_links = [
                {"label": "Ver resultados", "href": links["results"]},
                {"label": "Crear finding", "href": links["findings"]},
            ]
            if row_dict.get("screenshot_count"):
                row_links.insert(0, {
                    "label": "Ver captura",
                    "href": f"/api/evidence/screenshot/{row_dict.get('scan_id')}/{quote(ip_value, safe='')}/{port_value}",
                })
            _finding_add_candidate(candidates, seen, _finding_candidate(
                "web-evidence",
                "Evidencia web",
                severity,
                f"{'Interfaz industrial web' if is_ot_console else 'Interfaz web'} expuesta en {endpoint}",
                f"Existe evidencia visual/código de una interfaz web en {endpoint}. {detection_reason}.",
                "Las interfaces web de activos industriales o plataformas de operación facilitan fingerprinting, validación de exposición y potencial acceso interactivo.",
                "Clasificar la criticidad de la consola, verificar autenticación, endurecimiento, exposición entre redes y capturar evidencias representativas para informe.",
                evidence,
                links=row_links,
                confidence="alta" if is_ot_console else "media",
                tags=["web", "evidencia", "OT" if is_ot_console else "servicio"],
                assets=[ip_value],
                origins=[_finding_clean(row_dict.get("source_ip"))],
            ))

        for row in service_rows:
            row_dict = dict(row)
            ip_value = _finding_clean(row_dict.get("ip_address"))
            matched_networks = _finding_host_networks(ip_value, diagram.get("networks", []))
            target_network = matched_networks[0] if matched_networks else None
            levels = _finding_network_levels(target_network)
            min_level = min(levels) if levels else None
            if min_level is not None and min_level > 3:
                continue
            endpoint = f"{ip_value}:{row_dict.get('port')}/{_finding_clean(row_dict.get('protocol'), 'tcp')}"
            relation_origins = []
            for relation in diagram.get("relations", []):
                if ip_value in (relation.get("target_ips") or []):
                    origin = origins.get(relation.get("source_origin_id"))
                    if origin:
                        relation_origins.append(_finding_origin_label(origin))
            evidence = _finding_evidence(
                ("Servicio industrial", f"{endpoint} · {_finding_clean(row_dict.get('service_name'), 'servicio')} {_finding_clean(row_dict.get('product'))}".strip()),
                ("Red", _finding_network_label(target_network)),
                ("Zona Purdue", _finding_purdue_level_name(min_level) if min_level is not None else "Sin nivel declarado"),
                ("Orígenes con visibilidad", _finding_join(relation_origins, limit=8)),
                ("Escaneo", f"{row_dict.get('location') or 'sin ubicación'} ({row_dict.get('source_ip') or 'sin IP origen'})"),
            )
            severity = "critical" if ip_value in critical_by_ip or (min_level is not None and min_level <= 1) else "high"
            _finding_add_candidate(candidates, seen, _finding_candidate(
                "industrial-service",
                "Exposición OT",
                severity,
                f"Servicio industrial expuesto en {endpoint}",
                f"Se ha identificado un puerto de la lista OT de Nmap en una red Purdue {_finding_format_level(min_level) if min_level is not None else 'sin clasificar'} ({_finding_network_label(target_network)}).",
                "Los servicios industriales expuestos pueden permitir reconocimiento específico, escritura no autenticada o interacción directa con proceso si no existen controles adicionales.",
                "Limitar accesos a estaciones autorizadas, aplicar listas de control, segmentar por función y revisar autenticación/firmware del equipo.",
                evidence,
                links=[
                    {"label": "Ver visibilidad", "href": links["visibility"]},
                    {"label": "Analizar attack path", "href": f"{links['attack_path']}?target_ip={quote(ip_value, safe='')}&layers=l3,l7"},
                ],
                confidence="media",
                tags=["OT", "servicio industrial", "Purdue"],
                assets=[ip_value],
                origins=relation_origins,
            ))

        try:
            attack_candidates = _get_attack_path_candidates_sync(org, min_hops=2, limit=10, layers="l3,l7")
        except Exception:
            attack_candidates = {"candidates": []}

        for item in attack_candidates.get("candidates", []):
            target_ip = _finding_clean(item.get("ip"))
            stats = item.get("stats") or {}
            target_network = item.get("target_network") or {}
            is_critical = target_ip in critical_by_ip or "crítico:" in _finding_clean(item.get("label")).lower()
            max_hops = stats.get("max_hops") or 0
            severity = "critical" if is_critical or max_hops >= 3 else "high"
            evidence = _finding_evidence(
                ("Objetivo", item.get("label") or target_ip),
                ("Red objetivo", _finding_network_label(target_network)),
                ("Saltos máximos", max_hops),
                ("Orígenes alcanzables", stats.get("reachable_count")),
                ("Orígenes con ruta indirecta", stats.get("indirect_count")),
                ("Capas evaluadas", "L3/L7"),
            )
            _finding_add_candidate(candidates, seen, _finding_candidate(
                "attack-path",
                "Attack path",
                severity,
                f"Ruta de ataque de {max_hops} saltos hacia {target_ip}",
                f"El activo {target_ip} presenta rutas indirectas desde {stats.get('indirect_count') or 0} origen(es), con hasta {max_hops} salto(s).",
                "Una ruta indirecta evidencia que un atacante podría pivotar por visibilidad entre segmentos hasta alcanzar un objetivo que no siempre es accesible de forma directa.",
                "Validar los pivotes reales, priorizar cortes de visibilidad intermedia y documentar la ruta como narrativa técnica en el informe.",
                evidence,
                links=[{"label": "Abrir attack path", "href": f"{links['attack_path']}?target_ip={quote(target_ip, safe='')}&layers=l3,l7"}],
                confidence="media",
                tags=["attack path", "pivot", "visibilidad"],
                assets=[target_ip],
            ))

        if not include_medium:
            candidates = [
                candidate for candidate in candidates
                if candidate.get("severity_rank", 0) >= _FINDING_SEVERITY_ORDER["high"]
            ]

        candidates.sort(
            key=lambda item: (
                -item.get("severity_rank", 0),
                item.get("category", ""),
                item.get("title", "").lower(),
            )
        )

        summary = {
            "total": len(candidates),
            "critical": len([item for item in candidates if item.get("severity") == "critical"]),
            "high": len([item for item in candidates if item.get("severity") == "high"]),
            "medium": len([item for item in candidates if item.get("severity") == "medium"]),
            "low": len([item for item in candidates if item.get("severity") == "low"]),
            "info": len([item for item in candidates if item.get("severity") == "info"]),
            "categories": {},
        }
        for candidate in candidates:
            category = candidate.get("category") or "Otros"
            summary["categories"][category] = summary["categories"].get(category, 0) + 1

        return {
            "organization": org,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "mode": "candidate_review",
            "summary": summary,
            "source": {
                "database": "sqlite",
                "visibility_stats": diagram.get("stats") or {},
                "attack_layers": "l3,l7",
            },
            "candidates": candidates,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generando candidatos de hallazgos: {e}")


async def get_finding_candidates(organization: str, include_medium: bool = True):
    return await run_in_threadpool(_get_finding_candidates_sync, organization, include_medium)


@router.get("/api/recon-dashboard/export")
async def export_recon_dashboard(organization: str):
    """Exporta el Dashboard de reconocimiento en JSON editable por el cliente."""
    try:
        org = organization.upper()
        networks = storage.get_networks(org)
        critical_devices = storage.get_critical_devices(org)
        network_devices = storage.get_network_devices(org)

        systems = set()
        for item in networks + critical_devices + network_devices:
            systems.add(item.get("system_name") or "")
        if not systems:
            systems.add("")

        network_by_id = {n["id"]: n for n in networks}
        device_by_id = {d["id"]: d for d in network_devices}
        exported_systems = []

        for system in sorted(systems, key=lambda value: (value == "", value.lower())):
            system_name = system or None
            system_networks = [n for n in networks if (n.get("system_name") or None) == system_name]
            system_critical = [
                d for d in critical_devices
                if (d.get("system_name") or None) == system_name
            ]
            system_electronics = [
                d for d in network_devices
                if (d.get("system_name") or None) == system_name
            ]

            exported_systems.append({
                "system_name": system_name or "",
                "networks": [
                    {
                        "name": n["network_name"],
                        "range": n["network_range"],
                        "purdue_level": n.get("purdue_level"),
                    }
                    for n in system_networks
                ],
                "critical_devices": [
                    {
                        "name": d["name"],
                        "ips": [ip.strip() for ip in d["ips"].split(",") if ip.strip()],
                        "reason": d["reason"],
                    }
                    for d in system_critical
                ],
                "network_electronics": [
                    {
                        "name": d["name"],
                        "type": d["device_type"],
                        "management_ip": d.get("management_ip") or "",
                        "connected_to": [
                            device_by_id[item_id]["name"]
                            for item_id in d.get("connected_device_ids", [])
                            if item_id in device_by_id
                        ],
                        "accessible_networks": [
                            _network_label(network_by_id[item_id])
                            for item_id in d.get("accessible_network_ids", [])
                            if item_id in network_by_id
                        ],
                        "scan_origins": d.get("origin_locations", []),
                        "notes": d.get("notes") or "",
                    }
                    for d in system_electronics
                ],
            })

        payload = {
            "format": "arsenalot-recon-dashboard-v1",
            "organization": org,
            "instructions": (
                "Editar este JSON y volver a importarlo en ArsenalOT. "
                "Tipos de electrónica válidos: firewall, router, switch. "
                "purdue_level admite valores 0, 1, 2, 3, 3.5, 4 o 5."
            ),
            "systems": exported_systems,
        }
        data = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")
        headers = {
            "Content-Disposition": f"attachment; filename=recon_dashboard_{org.lower()}.json"
        }
        return StreamingResponse(io.BytesIO(data), media_type="application/json", headers=headers)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error exportando Dashboard: {e}")


@router.post("/api/recon-dashboard/import")
async def import_recon_dashboard(file: UploadFile = File(...), organization: Optional[str] = None):
    """Importa un JSON de Dashboard de reconocimiento y rellena sus secciones."""
    try:
        raw = await file.read()
        payload = json.loads(raw.decode("utf-8"))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"JSON inválido: {e}")

    org = (organization or payload.get("organization") or "").strip().upper()
    if not org:
        raise HTTPException(status_code=400, detail="El JSON debe incluir organization o debe enviarse por query.")

    stats = {
        "networks": 0,
        "critical_devices": 0,
        "network_devices": 0,
    }
    try:
        storage.create_organization(org)

        # 1) Redes, para poder resolver referencias por nombre en electrónica.
        networks = storage.get_networks(org)
        network_lookup = _network_lookup(networks)

        for system in _dashboard_systems(payload):
            system_name = _dashboard_system_name(system)
            for item in system.get("networks", []):
                name = (item.get("network_name") or item.get("name") or "").strip()
                network_range = (item.get("network_range") or item.get("range") or "").strip()
                if not name or not network_range:
                    continue
                purdue_level = item.get("purdue_level", item.get("purdue"))
                existing = _find_existing_network(networks, system_name, name, network_range)
                if existing:
                    storage.update_network(
                        existing["id"],
                        name,
                        network_range,
                        system_name=system_name,
                        purdue_level=purdue_level,
                    )
                    network_id = existing["id"]
                else:
                    network_id = storage.add_network(
                        org,
                        name,
                        network_range,
                        system_name=system_name,
                        purdue_level=purdue_level,
                    )
                refreshed = storage.get_networks(org)
                networks = refreshed
                network = next((n for n in refreshed if n["id"] == network_id), None)
                if network:
                    _register_network_lookup(network_lookup, network)
                stats["networks"] += 1

        # 2) Dispositivos críticos.
        critical_devices = storage.get_critical_devices(org)
        for system in _dashboard_systems(payload):
            system_name = _dashboard_system_name(system)
            for item in system.get("critical_devices", []):
                name = (item.get("name") or "").strip()
                ips = _split_ips(item.get("ips"))
                reason = (item.get("reason") or "").strip()
                if not name or not ips:
                    continue
                existing = next((
                    d for d in critical_devices
                    if (d.get("system_name") or None) == system_name
                    and d.get("name", "").strip().lower() == name.lower()
                    and d.get("ips", "").replace(" ", "") == ips.replace(" ", "")
                ), None)
                if existing:
                    storage.update_critical_device(
                        existing["id"], name, ips, reason, system_name=system_name
                    )
                else:
                    storage.add_critical_device(
                        org, name, ips, reason, system_name=system_name
                    )
                critical_devices = storage.get_critical_devices(org)
                stats["critical_devices"] += 1

        # 3) Electrónica de red en dos pasadas para resolver conexiones físicas por nombre.
        network_devices = storage.get_network_devices(org)
        device_lookup = _device_lookup(network_devices)

        pending_connections = []
        for system in _dashboard_systems(payload):
            system_name = _dashboard_system_name(system)
            system_key = system_name or ""
            for item in system.get("network_electronics", []):
                name = (item.get("name") or "").strip()
                device_type = (item.get("device_type") or item.get("type") or "").strip()
                if not name or not device_type:
                    continue
                refs = item.get("accessible_network_ids") or item.get("accessible_networks") or []
                accessible_ids = _resolve_lookup_refs(refs, network_lookup)

                origins = item.get("origin_locations") or item.get("scan_origins") or []
                key = _device_lookup_key(system_key, name)
                existing_id = device_lookup.get(key)
                if existing_id:
                    storage.update_network_device(
                        existing_id,
                        name=name,
                        device_type=device_type,
                        system_name=system_name,
                        management_ip=item.get("management_ip"),
                        accessible_network_ids=accessible_ids,
                        origin_locations=origins,
                        connected_device_ids=[],
                        notes=item.get("notes"),
                    )
                    device_id = existing_id
                else:
                    device_id = storage.add_network_device(
                        org,
                        name=name,
                        device_type=device_type,
                        system_name=system_name,
                        management_ip=item.get("management_ip"),
                        accessible_network_ids=accessible_ids,
                        origin_locations=origins,
                        connected_device_ids=[],
                        notes=item.get("notes"),
                    )
                _register_device_lookup(device_lookup, device_id, system_key, name)
                pending_connections.append({
                    "id": device_id,
                    "system_key": system_key,
                    "name": name,
                    "device_type": device_type,
                    "system_name": system_name,
                    "management_ip": item.get("management_ip"),
                    "accessible_ids": accessible_ids,
                    "origins": origins,
                    "notes": item.get("notes"),
                    "connected_to": (
                        item.get("connected_device_ids")
                        or item.get("connected_to")
                        or []
                    ),
                })
                stats["network_devices"] += 1

        for item in pending_connections:
            connected_ids = []
            for ref in _coerce_list(item["connected_to"]):
                if isinstance(ref, int):
                    connected_ids.append(ref)
                else:
                    name = str(ref).strip().lower()
                    resolved = (
                        device_lookup.get((item["system_key"], name))
                        or device_lookup.get(("", name))
                    )
                    if resolved and resolved != item["id"]:
                        connected_ids.append(resolved)
            storage.update_network_device(
                item["id"],
                name=item["name"],
                device_type=item["device_type"],
                system_name=item["system_name"],
                management_ip=item["management_ip"],
                accessible_network_ids=item["accessible_ids"],
                origin_locations=item["origins"],
                connected_device_ids=connected_ids,
                notes=item["notes"],
            )

        return {"status": "success", "organization": org, "stats": stats}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error importando Dashboard: {e}")


# ------------------------------------------------------------------ #
#  EXPORT CSV DE RESULTADOS                                           #
# ------------------------------------------------------------------ #

@router.get("/api/results/export-csv")
async def export_results_csv(
    organization: Optional[str] = None,
    location: Optional[str] = None,
    scan_id: Optional[int] = None,
):
    """Exporta solo resultados activos en formato CSV."""
    conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    cursor = conn.cursor()

    output = io.StringIO()
    writer = csv.writer(output)

    header = [
        "TIPO", "IP", "Hostname", "MAC",
        "Fabricante_Observado", "Puerto",
        "Protocolo", "Servicio", "Producto", "Versión", "Organización",
        "Ubicación", "IP_Origen", "Origen_Desc", "Crítico", "Scan ID"
    ]
    writer.writerow(header)

    where = "WHERE COALESCE(s.scan_mode, 'active') != 'passive' AND COALESCE(sr.discovery_method, 'unknown') != 'passive_capture'"
    res_params = []
    if organization:
        where += " AND UPPER(s.organization_name) = UPPER(?)"
        res_params.append(organization)
    if location:
        where += " AND UPPER(s.location) = UPPER(?)"
        res_params.append(location)
    if scan_id:
        where += " AND sr.scan_id = ?"
        res_params.append(scan_id)

    query = f"""
        SELECT h.ip_address,
               COALESCE(NULLIF(TRIM(m.hostname), ''), NULLIF(TRIM(h.hostname), '')) AS hostname,
               NULLIF(TRIM(m.mac_address), '') AS mac_address,
               NULLIF(TRIM(m.vendor), '') AS vendor,
               sr.port, sr.protocol, sr.service_name, sr.product, sr.version,
               s.organization_name, s.location, s.myip AS source_ip,
               sr.discovery_method, s.id AS scan_id
        FROM scan_results sr
        JOIN hosts h ON h.id = sr.host_id
        JOIN scans s ON s.id = sr.scan_id
        LEFT JOIN host_scan_metadata m ON m.scan_id = sr.scan_id AND m.host_id = sr.host_id
        {where} ORDER BY h.ip_address, sr.port
    """
    rows = cursor.execute(query, res_params).fetchall()

    critical_ips = set()
    if organization:
        crit_devs = storage.get_critical_devices(organization)
        for d in crit_devs:
            for ip in d['ips'].split(','):
                ip_clean = ip.strip()
                if ip_clean:
                    critical_ips.add(ip_clean)

    for row in rows:
        writer.writerow([
            "ACTIVO", row["ip_address"], row["hostname"],
            row["mac_address"],
            row["vendor"],
            row["port"], row["protocol"], row["service_name"],
            row["product"], row["version"], row["organization_name"],
            row["location"], row["source_ip"], row["discovery_method"],
            "SÍ" if row["ip_address"] in critical_ips else "No",
            row["scan_id"]
        ])

    conn.close()

    csv_content = output.getvalue()
    org_label = (organization or "todos").lower()
    filename = f"resultados_{org_label}.csv"
    headers = {"Content-Disposition": f"attachment; filename={filename}"}
    return StreamingResponse(
        iter([csv_content]),
        media_type="text/csv",
        headers=headers,
    )
