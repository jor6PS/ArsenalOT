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
    conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    if organization:
        query = """
            SELECT DISTINCT location
            FROM scans
            WHERE UPPER(organization_name) = UPPER(?)
            ORDER BY location
        """
        locations = cursor.execute(query, (organization,)).fetchall()
    else:
        query = """
            SELECT DISTINCT location 
            FROM scans 
            ORDER BY location
        """
        locations = cursor.execute(query).fetchall()
    
    conn.close()
    
    return [{"location": loc["location"]} for loc in locations]

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


def _diagram_origin_label(value: str) -> str:
    return str(value or "").strip().upper()


def _diagram_target_networks(value: str) -> list:
    networks = []
    for token in str(value or "").replace(",", " ").split():
        cleaned = token.strip().strip("[](){};")
        if not cleaned:
            continue
        if cleaned.count(":") == 1 and "." in cleaned:
            cleaned = cleaned.rsplit(":", 1)[0]
        try:
            networks.append(ipaddress.ip_network(cleaned, strict=False))
        except ValueError:
            continue
    return networks


def _diagram_add_link(links: list, seen: set, source: str, target: str,
                      link_type: str, label: str = ""):
    key = (source, target, link_type, label)
    if not source or not target or key in seen:
        return
    seen.add(key)
    links.append({
        "source": source,
        "target": target,
        "type": link_type,
        "label": label,
    })


@router.get("/api/access-vector-diagram")
async def get_access_vector_diagram(organization: str):
    """Devuelve datos normalizados para dibujar vectores de acceso sin depender de servicios externos."""
    try:
        org = organization.upper()
        networks = storage.get_networks(org)
        network_devices = storage.get_network_devices(org)
        critical_devices = storage.get_critical_devices(org)

        conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        scans = conn.execute("""
            SELECT id, organization_name, location, target_range, status,
                   scan_mode, scan_type, started_at
            FROM scans
            WHERE UPPER(organization_name) = UPPER(?)
            ORDER BY started_at DESC
        """, (org,)).fetchall()
        conn.close()

        network_by_id = {int(item["id"]): dict(item) for item in networks}
        device_by_id = {int(item["id"]): dict(item) for item in network_devices}

        systems = set()
        for item in networks + network_devices + critical_devices:
            systems.add(item.get("system_name") or "")
        if not systems:
            systems.add("")

        origins = {}
        for scan in scans:
            origin_label = _diagram_origin_label(scan["location"])
            if not origin_label:
                continue
            entry = origins.setdefault(origin_label, {
                "id": f"origin:{origin_label}",
                "name": origin_label,
                "scan_count": 0,
                "running_count": 0,
                "targets": [],
                "linked": False,
            })
            entry["scan_count"] += 1
            if scan["status"] == "running":
                entry["running_count"] += 1
            target_range = str(scan["target_range"] or "").strip()
            if target_range and target_range not in entry["targets"]:
                entry["targets"].append(target_range)

        for device in network_devices:
            for origin in device.get("origin_locations") or []:
                origin_label = _diagram_origin_label(origin)
                if not origin_label:
                    continue
                origins.setdefault(origin_label, {
                    "id": f"origin:{origin_label}",
                    "name": origin_label,
                    "scan_count": 0,
                    "running_count": 0,
                    "targets": [],
                    "linked": False,
                })

        links = []
        seen_links = set()

        for device in network_devices:
            device_id = f"device:{device['id']}"
            for origin in device.get("origin_locations") or []:
                origin_label = _diagram_origin_label(origin)
                if not origin_label:
                    continue
                origins[origin_label]["linked"] = True
                _diagram_add_link(
                    links, seen_links, f"origin:{origin_label}", device_id,
                    "origin_device", "origen declarado"
                )

            for network_id in device.get("accessible_network_ids") or []:
                if int(network_id) in network_by_id:
                    _diagram_add_link(
                        links, seen_links, device_id, f"network:{int(network_id)}",
                        "device_network", "red accesible"
                    )

            for peer_id in device.get("connected_device_ids") or []:
                if int(peer_id) in device_by_id:
                    _diagram_add_link(
                        links, seen_links, device_id, f"device:{int(peer_id)}",
                        "device_device", "conectado"
                    )

        parsed_networks = []
        for network in networks:
            try:
                parsed = ipaddress.ip_network(network["network_range"], strict=False)
            except ValueError:
                parsed = None
            parsed_networks.append((network, parsed))

        for scan in scans:
            origin_label = _diagram_origin_label(scan["location"])
            target_range = str(scan["target_range"] or "").strip()
            if not origin_label or not target_range:
                continue
            for target_net in _diagram_target_networks(target_range):
                for network, parsed in parsed_networks:
                    if parsed and target_net.overlaps(parsed):
                        _diagram_add_link(
                            links, seen_links, f"origin:{origin_label}", f"network:{network['id']}",
                            "scan_target", "objetivo escaneado"
                        )

        return {
            "organization": org,
            "systems": [
                {
                    "id": f"system:{system or '__none__'}",
                    "name": system or "Sin sistema",
                    "raw_name": system or None,
                }
                for system in sorted(systems, key=lambda value: (value == "", value.lower()))
            ],
            "origins": sorted(origins.values(), key=lambda item: item["name"]),
            "networks": [
                {
                    "id": f"network:{item['id']}",
                    "raw_id": item["id"],
                    "system_name": item.get("system_name") or None,
                    "name": item["network_name"],
                    "range": item["network_range"],
                    "purdue_level": item.get("purdue_level"),
                }
                for item in networks
            ],
            "network_devices": [
                {
                    "id": f"device:{item['id']}",
                    "raw_id": item["id"],
                    "system_name": item.get("system_name") or None,
                    "name": item["name"],
                    "device_type": item["device_type"],
                    "management_ip": item.get("management_ip") or "",
                    "origin_locations": item.get("origin_locations") or [],
                    "accessible_network_ids": item.get("accessible_network_ids") or [],
                    "connected_device_ids": item.get("connected_device_ids") or [],
                    "notes": item.get("notes") or "",
                }
                for item in network_devices
            ],
            "critical_devices": [
                {
                    "id": f"critical:{item['id']}",
                    "raw_id": item["id"],
                    "system_name": item.get("system_name") or None,
                    "name": item["name"],
                    "ips": item.get("ips") or "",
                    "reason": item.get("reason") or "",
                }
                for item in critical_devices
            ],
            "links": links,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generando diagrama de vectores: {e}")


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
        "TIPO", "IP", "Hostname", "MAC_Observada", "MAC_Conocida_Global",
        "Fabricante_Observado", "Fabricante_Conocido_Global", "Puerto",
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
               NULLIF(TRIM(h.mac_address), '') AS known_mac_address,
               NULLIF(TRIM(m.vendor), '') AS vendor,
               NULLIF(TRIM(h.vendor), '') AS known_vendor,
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
            row["mac_address"], row["known_mac_address"],
            row["vendor"], row["known_vendor"],
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
