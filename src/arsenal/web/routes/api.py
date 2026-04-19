import csv
import io
import json
import sqlite3
from typing import Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from fastapi.responses import PlainTextResponse, StreamingResponse

from arsenal.web.core.models import NetworkCreateRequest, NetworkUpdateRequest, CriticalDeviceRequest, CriticalDeviceUpdateRequest
from arsenal.web.core.deps import storage

router = APIRouter()

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
    
    result_filter = "WHERE 1=1"
    result_params = []
    
    if organization:
        scan_filter += " AND UPPER(s.organization_name) = UPPER(?)"
        scan_params.append(organization)
        result_filter += " AND UPPER(s.organization_name) = UPPER(?)"
        result_params.append(organization)

    if location:
        scan_filter += " AND UPPER(s.location) = UPPER(?)"
        scan_params.append(location)
        result_filter += " AND UPPER(s.location) = UPPER(?)"
        result_params.append(location)
        
    if scan_id:
        scan_filter += " AND s.id = ?"
        scan_params.append(scan_id)
        result_filter += " AND sr.scan_id = ?"
        result_params.append(scan_id)
    
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
    
    # Determinar si el escaneo solicitado es pasivo
    is_single_passive = False
    if scan_id:
        mode_row = cursor.execute("SELECT scan_mode FROM scans WHERE id = ?", (scan_id,)).fetchone()
        is_single_passive = mode_row and mode_row[0] == 'passive'

    # Hosts
    if is_single_passive:
        hosts_query = """
            SELECT COUNT(DISTINCT ip) FROM (
                SELECT src_ip as ip FROM passive_conversations WHERE scan_id = ?
                UNION
                SELECT dst_ip as ip FROM passive_conversations WHERE scan_id = ?
            )
        """
        hosts_count = cursor.execute(hosts_query, (scan_id, scan_id)).fetchone()[0]
    else:
        # Hosts activos + Hosts de otros escaneos pasivos si no hay scan_id
        hosts_query = f"""
            SELECT COUNT(DISTINCT h.id) 
            FROM hosts h
            JOIN scan_results sr ON sr.host_id = h.id
            JOIN scans s ON s.id = sr.scan_id
            {scan_filter}
        """
        hosts_count = cursor.execute(hosts_query, scan_params).fetchone()[0]
        
        # Si no hay scan_id, sumar hosts de conversaciones pasivas
        if not scan_id:
            passive_hosts_query = f"""
                SELECT COUNT(DISTINCT ip) FROM (
                    SELECT src_ip as ip FROM passive_conversations pc JOIN scans s ON s.id = pc.scan_id {scan_filter.replace('s.', 's.')}
                    UNION
                    SELECT dst_ip as ip FROM passive_conversations pc JOIN scans s ON s.id = pc.scan_id {scan_filter.replace('s.', 's.')}
                )
            """
            # Nota: Esto es una aproximación, idealmente sería un UNION total de IPs para evitar duplicados entre tablas
            # pero por simplicidad y siguiendo la "separación total", los tratamos como conjuntos distintos o los sumamos.
            # El usuario pidió separación, así que contarlos por separado o sumarlos es aceptable.
            hosts_count += cursor.execute(passive_hosts_query, scan_params * 2).fetchone()[0]
    
    # Puertos / Conversaciones
    if is_single_passive:
        ports_count = cursor.execute(
            "SELECT COUNT(*) FROM passive_conversations WHERE scan_id = ?", (scan_id,)
        ).fetchone()[0]
    else:
        ports_query = f"""
            SELECT COUNT(*) 
            FROM scan_results sr
            JOIN scans s ON s.id = sr.scan_id
            {scan_filter}
        """
        ports_count = cursor.execute(ports_query, scan_params).fetchone()[0]
        
        if not scan_id:
            passive_conv_query = f"SELECT COUNT(*) FROM passive_conversations pc JOIN scans s ON s.id = pc.scan_id {scan_filter}"
            ports_count += cursor.execute(passive_conv_query, scan_params).fetchone()[0]
    
    # Vulnerabilidades (Solo activas por ahora)
    vulns_query = f"""
        SELECT COUNT(*) 
        FROM vulnerabilities v
        JOIN scan_results sr ON sr.id = v.scan_result_id
        JOIN scans s ON s.id = sr.scan_id
        {scan_filter}
    """
    vulns_count = cursor.execute(vulns_query, scan_params).fetchone()[0]
    
    # Screenshots
    screenshots_query = f"""
        SELECT COUNT(*) 
        FROM enrichments e
        JOIN scan_results sr ON sr.id = e.scan_result_id
        JOIN scans s ON s.id = sr.scan_id
        {scan_filter} AND e.enrichment_type = 'Screenshot'
    """
    screenshots_count = cursor.execute(screenshots_query, scan_params).fetchone()[0]
    
    # Source codes
    sources_query = f"""
        SELECT COUNT(*) 
        FROM enrichments e
        JOIN scan_results sr ON sr.id = e.scan_result_id
        JOIN scans s ON s.id = sr.scan_id
        {scan_filter} AND e.enrichment_type = 'Websource'
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


@router.post("/api/organizations")
async def create_organization(body: CreateOrgRequest):
    """Crea una organización y su estructura de bitácora."""
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="El nombre no puede estar vacío.")
    storage.create_organization(name, body.description)
    return {"ok": True, "name": name.upper()}

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
                lines.append(f"  - {net['network_name']}: {net['network_range']}")
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
                system_name=request.system_name
            )
        return {"status": "success", "message": "Red añadida correctamente"}
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
            
        if deleted:
            return {"status": "success", "message": "Red eliminada correctamente"}
        else:
            raise HTTPException(status_code=404, detail="Red no encontrada")
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
                system_name=request.system_name
            )
            if updated:
                return {"status": "success", "message": "Red actualizada correctamente"}
            else:
                raise HTTPException(status_code=404, detail="Red no encontrada")
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
        )
        return {"status": "success", "id": new_id, "message": "Dispositivo crítico añadido"}
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
        )
        if updated:
            return {"status": "success", "message": "Dispositivo crítico actualizado"}
        else:
            raise HTTPException(status_code=404, detail="Dispositivo no encontrado")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/api/critical-devices/{device_id}")
async def delete_critical_device(device_id: int):
    """Elimina un dispositivo crítico por ID."""
    try:
        deleted = storage.delete_critical_device(device_id)
        if deleted:
            return {"status": "success", "message": "Dispositivo crítico eliminado"}
        raise HTTPException(status_code=404, detail="Dispositivo no encontrado")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ------------------------------------------------------------------ #
#  EXPORT CSV DE RESULTADOS                                           #
# ------------------------------------------------------------------ #

@router.get("/api/results/export-csv")
async def export_results_csv(
    organization: Optional[str] = None,
    location: Optional[str] = None,
    scan_id: Optional[int] = None,
):
    """Exporta los resultados filtrados en formato CSV, manejando activos y pasivos."""
    conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    cursor = conn.cursor()

    # 1. Determinar si estamos exportando un scan pasivo específico
    is_passive_only = False
    if scan_id:
        mode_row = cursor.execute("SELECT scan_mode FROM scans WHERE id = ?", (scan_id,)).fetchone()
        is_passive_only = mode_row and mode_row[0] == 'passive'

    output = io.StringIO()
    writer = csv.writer(output)

    if is_passive_only:
        # --- EXPORTAR SOLO PASIVO (Formato específico) ---
        writer.writerow(["IP Origen", "MAC Origen", "Puerto Origen", "IP Destino", "MAC Destino", "Puerto Destino", "Protocolo", "Última Vez", "Organización", "Ubicación", "Scan ID"])
        passive_data = storage.get_passive_results(scan_id=scan_id)
        for r in passive_data:
            writer.writerow([
                r['src_ip'], r['src_mac'] or "", r['src_port'] or "",
                r['dst_ip'], r['dst_mac'] or "", r['dst_port'] or "",
                r['protocol'] or "", r['last_seen'],
                r['organization_name'], r['location'], r['scan_id']
            ])
    else:
        # --- EXPORTAR ACTIVO (+ PASIVO SI ES "TODOS") ---
        # Cabecera genérica que acomoda ambos si es necesario
        header = ["TIPO", "IP/Origen", "Hostname/Destino", "Puerto", "Protocolo", "Servicio/Info", "Producto/MAC_Or", "Versión/MAC_Des", "Organización", "Ubicación", "Origen_Desc", "Crítico", "Scan ID"]
        writer.writerow(header)

        # A. Resultados Activos
        where = "WHERE 1=1"
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
            SELECT h.ip_address, h.hostname, sr.port, sr.protocol, sr.service_name, sr.product, sr.version,
                   s.organization_name, s.location, sr.discovery_method, s.id AS scan_id
            FROM scan_results sr JOIN hosts h ON h.id = sr.host_id JOIN scans s ON s.id = sr.scan_id
            {where} ORDER BY h.ip_address, sr.port
        """
        rows = cursor.execute(query, res_params).fetchall()
        
        # IPs críticas
        critical_ips = set()
        if organization:
            crit_devs = storage.get_critical_devices(organization)
            for d in crit_devs:
                for ip in d['ips'].split(','):
                    ip_clean = ip.strip()
                    if ip_clean: critical_ips.add(ip_clean)

        for row in rows:
            writer.writerow([
                "ACTIVO", row["ip_address"], row["hostname"], row["port"], row["protocol"],
                row["service_name"], row["product"], row["version"], row["organization_name"],
                row["location"], row["discovery_method"], "SÍ" if row["ip_address"] in critical_ips else "No",
                row["scan_id"]
            ])

        # B. Resultados Pasivos (solo si no se filtró por un scan activo específico)
        # Si hay scan_id y NO es passive_only (ya manejado arriba), entonces es activo_only, no añadimos pasivos.
        # B. Resultados Pasivos
        # Siempre intentamos obtener resultados pasivos si no hay un filtro que lo impida
        passive_data = storage.get_passive_results(scan_id=scan_id, organization=organization, location=location)
        for r in passive_data:
            writer.writerow([
                "PASIVO", r['src_ip'], r['dst_ip'], r['src_port'], r['protocol'],
                f"Conv a {r['dst_ip']}:{r['dst_port']}", r['src_mac'], r['dst_mac'],
                r['organization_name'], r['location'], "passive_capture", "No", r['scan_id']
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
