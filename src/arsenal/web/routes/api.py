import csv
import io
import sqlite3
from typing import Optional
from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse, StreamingResponse

from arsenal.web.core.models import NetworkCreateRequest, CriticalDeviceRequest
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
        scan_filter += " AND s.organization_name = ?"
        scan_params.append(organization.upper())
        result_filter += " AND s.organization_name = ?"
        result_params.append(organization.upper())
        
    if location:
        scan_filter += " AND s.location = ?"
        scan_params.append(location.upper())
        result_filter += " AND s.location = ?"
        result_params.append(location.upper())
        
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
    
    # Escaneos
    total_scans_query = f"SELECT COUNT(*) FROM scans s {scan_filter}"
    total_scans = cursor.execute(total_scans_query, scan_params).fetchone()[0]
    
    completed_query = f"SELECT COUNT(*) FROM scans s {scan_filter} AND s.status = 'completed'"
    completed_scans = cursor.execute(completed_query, scan_params).fetchone()[0]
    
    running_query = f"SELECT COUNT(*) FROM scans s {scan_filter} AND s.status = 'running'"
    running_scans_count = cursor.execute(running_query, scan_params).fetchone()[0]
    
    # Hosts
    hosts_query = f"""
        SELECT COUNT(DISTINCT h.id) 
        FROM hosts h
        JOIN scan_results sr ON sr.host_id = h.id
        JOIN scans s ON s.id = sr.scan_id
        {scan_filter}
    """
    hosts_count = cursor.execute(hosts_query, scan_params).fetchone()[0]
    
    # Puertos
    ports_query = f"""
        SELECT COUNT(*) 
        FROM scan_results sr
        JOIN scans s ON s.id = sr.scan_id
        {scan_filter}
    """
    ports_count = cursor.execute(ports_query, scan_params).fetchone()[0]
    
    # Vulnerabilidades
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

@router.get("/api/organizations")
async def get_organizations():
    """Obtiene lista de organizaciones."""
    conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    orgs = cursor.execute("SELECT name, description, created_at FROM organizations ORDER BY name").fetchall()
    conn.close()
    
    return [{"name": org["name"], "description": org["description"], "created_at": org["created_at"]} for org in orgs]

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
            WHERE organization_name = ?
            ORDER BY location
        """
        locations = cursor.execute(query, (organization.upper(),)).fetchall()
    else:
        query = """
            SELECT DISTINCT location 
            FROM scans 
            ORDER BY location
        """
        locations = cursor.execute(query).fetchall()
    
    conn.close()
    
    return [{"location": loc["location"]} for loc in locations]

@router.get("/api/networks")
async def get_networks(organization: str):
    """Obtiene lista de redes vinculadas a una organización."""
    try:
        networks = getattr(storage, 'get_networks', lambda org: [])(organization.upper())
        return [dict(n) for n in networks]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error obteniendo redes: {str(e)}")

@router.get("/api/networks/export", response_class=PlainTextResponse)
async def export_networks(organization: str):
    """Exporta las redes de una organización en un archivo TXT formateado."""
    try:
        networks = getattr(storage, 'get_networks', lambda org: [])(organization.upper())
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
    """Exporta los resultados filtrados en formato CSV."""
    conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    cursor = conn.cursor()

    where = "WHERE 1=1"
    params = []
    if organization:
        where += " AND s.organization_name = ?"
        params.append(organization.upper())
    if location:
        where += " AND s.location = ?"
        params.append(location.upper())
    if scan_id:
        where += " AND sr.scan_id = ?"
        params.append(scan_id)

    query = f"""
        SELECT
            h.ip_address,
            h.hostname,
            sr.port,
            sr.protocol,
            sr.service_name,
            sr.product,
            sr.version,
            s.organization_name,
            s.location,
            sr.discovery_method,
            s.id AS scan_id
        FROM scan_results sr
        JOIN hosts h ON h.id = sr.host_id
        JOIN scans s ON s.id = sr.scan_id
        {where}
        ORDER BY h.ip_address, sr.port
    """
    rows = cursor.execute(query, params).fetchall()
    
    # Obtener IPs críticas para marcar en el CSV
    critical_ips = set()
    if organization:
        crit_devs = storage.get_critical_devices(organization)
        for d in crit_devs:
            for ip in d['ips'].split(','):
                ip_clean = ip.strip()
                if ip_clean:
                    critical_ips.add(ip_clean)

    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["IP", "Hostname", "Puerto", "Protocolo", "Servicio",
                     "Producto", "Versión", "Organización", "Ubicación",
                     "Origen Descubrimiento", "Scan ID", "Crítico"])
    for row in rows:
        writer.writerow([
            row["ip_address"] or "",
            row["hostname"] or "",
            row["port"] or "",
            row["protocol"] or "",
            row["service_name"] or "",
            row["product"] or "",
            row["version"] or "",
            row["organization_name"] or "",
            row["location"] or "",
            row["discovery_method"] or "",
            row["scan_id"] or "",
            "SÍ" if row["ip_address"] in critical_ips else "No"
        ])

    csv_content = output.getvalue()
    org_label = (organization or "all").lower()
    filename = f"resultados_{org_label}.csv"
    headers = {"Content-Disposition": f"attachment; filename={filename}"}
    return StreamingResponse(
        iter([csv_content]),
        media_type="text/csv",
        headers=headers,
    )
