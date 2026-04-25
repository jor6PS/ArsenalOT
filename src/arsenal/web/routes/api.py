import csv
import io
import ipaddress
import json
import sqlite3
from typing import Optional, List
from fastapi import APIRouter, HTTPException, UploadFile, File
from pydantic import BaseModel
from fastapi.responses import PlainTextResponse, StreamingResponse

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


@router.get("/api/access-vector-diagram")
async def get_access_vector_diagram(organization: str):
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
                                 purdue_level: int = None, is_unknown: bool = False,
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
                "purdue_level admite valores 0, 1, 2, 3, 4 o 5."
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
