#!/usr/bin/env python3
"""
Aplicación web para gestión de escaneos de red
"""

import os
import sys

# Verificar que se está ejecutando con sudo
if os.geteuid() != 0:
    print("="*70)
    print("  ⚠️  ERROR: Esta aplicación requiere privilegios de administrador")
    print("="*70)
    print("\nAlgunas funcionalidades (como ARP scan) requieren permisos de root.")
    print("Por favor, ejecuta la aplicación con sudo:\n")
    print("  sudo python3 web_app.py\n")
    print("O si usas uvicorn directamente:")
    print("  sudo uvicorn web_app:app --host 0.0.0.0 --port 8000\n")
    sys.exit(1)

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import List, Optional, Dict
import asyncio
import json
import subprocess
import threading
import sqlite3
from pathlib import Path
from datetime import datetime
import uuid

from arsenal.core.storage import ScanStorage
from arsenal.scripts.check_env import check_dependencies
from arsenal.core.export_import import export_data, import_data
from fastapi import UploadFile, File, Form
from arsenal.core.parsers.nmap_parser import NmapXMLParser
from arsenal.core.parsers.vulnerability_parser import VulnerabilityParser
from arsenal.core.scanners import HostDiscovery, PortScanner, PassiveCapture, ServiceDetection
import shutil
import ipaddress
import re
import tempfile
import time

app = FastAPI(title="ArsenalOT - Gestión de Escaneos")

# Rutas absolutas para encontrar static y templates desde cualquier lugar
BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

# Configurar templates y archivos estáticos
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Almacenamiento de conexiones WebSocket
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
    
    async def connect(self, websocket: WebSocket, scan_id: str):
        await websocket.accept()
        self.active_connections[scan_id] = websocket
    
    def disconnect(self, scan_id: str):
        if scan_id in self.active_connections:
            del self.active_connections[scan_id]
    
    async def send_progress(self, scan_id: str, message: dict):
        if scan_id not in self.active_connections:
            return  # Conexión no existe, no intentar enviar
        
        websocket = self.active_connections[scan_id]
        
        # Verificar estado de la conexión
        try:
            # Intentar enviar el mensaje
            await websocket.send_json(message)
        except (WebSocketDisconnect, ConnectionError, RuntimeError, asyncio.CancelledError):
            # Conexión cerrada o error, desconectar limpiamente
            self.disconnect(scan_id)
        except Exception as e:
            # Verificar si el error es por conexión cerrada
            error_str = str(e).lower()
            if any(keyword in error_str for keyword in ['closed', 'disconnect', 'connection']):
                # Conexión cerrada, solo desconectar sin loguear
                self.disconnect(scan_id)
            else:
                # Otro error, desconectar y loguear solo si no es un error de conexión
                print(f"Error enviando progreso a scan {scan_id}: {e}")
                self.disconnect(scan_id)

manager = ConnectionManager()
storage = ScanStorage()

# Modelos Pydantic
class ScanConfig(BaseModel):
    organization: str
    location: str
    target_range: Optional[str] = "0.0.0.0/0"  # Opcional, por defecto para pasivo
    interface: str = "eth0"
    scan_mode: str = "active"  # active o passive
    # Opciones para escaneos activos
    host_discovery: bool = True
    nmap: bool = True
    nmap_speed: str = "normal"  # rapido, normal, lento
    nmap_versions: bool = False
    nmap_vulns: bool = False
    nmap_ot_ports: bool = True
    nmap_it_ports: bool = True
    custom_ports: Optional[str] = None
    custom_nmap_command: Optional[str] = None
    screenshots: bool = False
    source_code: bool = False
    # Opciones para escaneos pasivos
    pcap_filter: Optional[str] = None  # Filtro BPF para tshark (ej: "tcp port 80")

class Neo4jConfig(BaseModel):
    ip: str
    username: str
    password: str
    organization: Optional[str] = None
    location: Optional[str] = None

class NetworkCreateRequest(BaseModel):
    organization: str
    network_name: str
    network_range: str
    system_name: Optional[str] = None

# Escaneos en ejecución
running_scans: Dict[str, threading.Thread] = {}
running_processes: Dict[str, subprocess.Popen] = {}  # Almacenar procesos para poder cancelarlos

@app.get("/", response_class=HTMLResponse)
async def main_dashboard(request: Request):
    """Dashboard principal de la plataforma ArsenalOT."""
    return templates.TemplateResponse("main.html", {"request": request})

@app.get("/pentest", response_class=HTMLResponse)
async def pentest_orgs_page(request: Request):
    """Página para seleccionar o crear organizaciones."""
    return templates.TemplateResponse("pentest_orgs.html", {"request": request})

@app.get("/pentest/{org_name}", response_class=HTMLResponse)
async def pentest_phases_page(request: Request, org_name: str):
    """Página para seleccionar la fase de ataque de una organización."""
    return templates.TemplateResponse("pentest_phases.html", {"request": request, "org_name": org_name})

@app.get("/pentest/{org_name}/recon", response_class=HTMLResponse)
async def recon_dashboard(request: Request, org_name: str):
    """Dashboard de reconocimiento (antiguo dashboard principal)."""
    return templates.TemplateResponse("dashboard.html", {"request": request, "org_name": org_name})

@app.get("/pentest/{org_name}/recon/scan", response_class=HTMLResponse)
async def recon_scan_page(request: Request, org_name: str):
    """Página de configuración de escaneo."""
    return templates.TemplateResponse("scan.html", {"request": request, "org_name": org_name})

@app.get("/pentest/{org_name}/recon/results", response_class=HTMLResponse)
async def recon_results_page(request: Request, org_name: str):
    """Página de resultados."""
    return templates.TemplateResponse("results.html", {"request": request, "org_name": org_name})

@app.get("/pentest/{org_name}/recon/neo4j", response_class=HTMLResponse)
async def recon_neo4j_page(request: Request, org_name: str):
    """Página para exportar a Neo4j."""
    return templates.TemplateResponse("neo4j.html", {"request": request, "org_name": org_name})

# API Endpoints
@app.get("/api/stats")
async def get_stats(
    organization: Optional[str] = None,
    location: Optional[str] = None,
    scan_id: Optional[int] = None
):
    """Obtiene estadísticas generales o filtradas."""
    conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Construir filtros para las consultas
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
    
    # Organizaciones (filtradas según los filtros aplicados)
    # Organizaciones (filtradas según los filtros aplicados)
    if organization:
        orgs_count = 1
    elif scan_id:
        # Si hay scan_id, contar solo la organización de ese escaneo
        org_query = """
            SELECT COUNT(DISTINCT s.organization_name)
            FROM scans s
            WHERE s.id = ?
        """
        orgs_count = cursor.execute(org_query, [scan_id]).fetchone()[0]
    else:
        # Sin filtros, todas las organizaciones
        orgs_count = cursor.execute("SELECT COUNT(DISTINCT name) FROM organizations").fetchone()[0]
    
    # Escaneos (filtrados)
    total_scans_query = f"SELECT COUNT(*) FROM scans s {scan_filter}"
    total_scans = cursor.execute(total_scans_query, scan_params).fetchone()[0]
    
    completed_query = f"SELECT COUNT(*) FROM scans s {scan_filter} AND s.status = 'completed'"
    completed_scans = cursor.execute(completed_query, scan_params).fetchone()[0]
    
    running_query = f"SELECT COUNT(*) FROM scans s {scan_filter} AND s.status = 'running'"
    running_scans_count = cursor.execute(running_query, scan_params).fetchone()[0]
    
    # Hosts (filtrados por escaneos)
    # Hosts (filtrados por escaneos)
    hosts_query = f"""
        SELECT COUNT(DISTINCT h.id) 
        FROM hosts h
        JOIN scan_results sr ON sr.host_id = h.id
        JOIN scans s ON s.id = sr.scan_id
        {scan_filter}
    """
    hosts_count = cursor.execute(hosts_query, scan_params).fetchone()[0]
    
    # Puertos (filtrados)
    ports_query = f"""
        SELECT COUNT(*) 
        FROM scan_results sr
        JOIN scans s ON s.id = sr.scan_id
        {scan_filter}
    """
    ports_count = cursor.execute(ports_query, scan_params).fetchone()[0]
    
    # Vulnerabilidades (filtradas)
    vulns_query = f"""
        SELECT COUNT(*) 
        FROM vulnerabilities v
        JOIN scan_results sr ON sr.id = v.scan_result_id
        JOIN scans s ON s.id = sr.scan_id
        {scan_filter}
    """
    vulns_count = cursor.execute(vulns_query, scan_params).fetchone()[0]
    
    # Screenshots (filtrados)
    screenshots_query = f"""
        SELECT COUNT(*) 
        FROM enrichments e
        JOIN scan_results sr ON sr.id = e.scan_result_id
        JOIN scans s ON s.id = sr.scan_id
        {scan_filter} AND e.enrichment_type = 'Screenshot'
    """
    screenshots_count = cursor.execute(screenshots_query, scan_params).fetchone()[0]
    
    # Source codes (filtrados)
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

@app.get("/api/organizations")
async def get_organizations():
    """Obtiene lista de organizaciones."""
    conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    orgs = cursor.execute("SELECT name, description, created_at FROM organizations ORDER BY name").fetchall()
    conn.close()
    
    return [{"name": org["name"], "description": org["description"], "created_at": org["created_at"]} for org in orgs]

@app.get("/api/locations")
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

@app.get("/api/networks")
async def get_networks(organization: str):
    """Obtiene lista de redes vinculadas a una organización."""
    try:
        networks = getattr(storage, 'get_networks', lambda org: [])(organization.upper())
        return [dict(n) for n in networks]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error obteniendo redes: {str(e)}")

@app.get("/api/networks/export", response_class=PlainTextResponse)
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

@app.post("/api/networks")
async def create_network(request: NetworkCreateRequest):
    """Añade una nueva red a una organización."""
    try:
        # Asegurar que la organización existe por si acaso
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

@app.delete("/api/networks/{network_id}")
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
@app.get("/api/scans/list")
async def get_scans_list(organization: Optional[str] = None, location: Optional[str] = None):
    """Obtiene lista de escaneos para dropdowns."""
    try:
        conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = "SELECT id, organization_name, location, target_range, started_at, scan_mode, scan_type FROM scans WHERE 1=1"
        params = []
        
        if organization:
            query += " AND organization_name = ?"
            params.append(organization.upper())
        
        if location:
            query += " AND location = ?"
            params.append(location.upper())
        
        query += " ORDER BY started_at DESC LIMIT 100"
        
        scans = cursor.execute(query, params).fetchall()
        conn.close()
        
        result = []
        for scan in scans:
            # Formatear target_range: si es pasivo y es "0.0.0.0/0", mostrar "Escaneo Pasivo"
            # sqlite3.Row no tiene método .get(), usar acceso directo con manejo de None
            target_range_val = scan["target_range"] if scan["target_range"] is not None else ""
            scan_mode_val = scan["scan_mode"] if scan["scan_mode"] is not None else "active"
            scan_type_val = scan["scan_type"] if scan["scan_type"] is not None else None
            
            target_display = target_range_val
            
            if scan_mode_val == "passive" and (target_display == "0.0.0.0/0" or not target_display):
                target_display = "🎧 Escaneo Pasivo"
            elif scan_mode_val == "passive":
                target_display = f"🎧 Pasivo: {target_display}"
            
            result.append({
                "id": scan["id"],
                "organization": scan["organization_name"],
                "location": scan["location"],
                "target": target_display,
                "target_range": target_range_val,  # Mantener original para uso interno
                "scan_mode": scan_mode_val,
                "scan_type": scan_type_val,
                "started_at": scan["started_at"]
            })
        
        return result
    except Exception as e:
        import traceback
        error_detail = traceback.format_exc()
        print(f"❌ Error en /api/scans/list: {e}")
        print(error_detail)
        raise HTTPException(status_code=500, detail=f"Error obteniendo lista de escaneos: {str(e)}")

@app.get("/api/scans")
async def get_scans(
    organization: Optional[str] = None, 
    location: Optional[str] = None,
    scan_id: Optional[int] = None,
    status: Optional[str] = None
):
    """Obtiene lista de escaneos. Detecta automáticamente escaneos zombie."""
    from datetime import timedelta
    
    conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    cursor = conn.cursor()
    
    # Detectar y limpiar escaneos zombie automáticamente
    # Escaneos con vulnerabilidades pueden tardar más (4 horas)
    # Escaneos normales (2 horas)
    # IMPORTANTE: Solo marcar como zombie si NO está en running_processes (no está realmente en ejecución)
    # y NO se ha actualizado en el último tiempo y NO hay actividad reciente
    cutoff_time_normal = datetime.now() - timedelta(hours=2)
    cutoff_time_vulns = datetime.now() - timedelta(hours=4)
    
    # Buscar escaneos zombie (normales) - solo si no tienen resultados, son muy antiguos Y no están en ejecución
    zombies_normal = cursor.execute("""
        SELECT s.id FROM scans s
        WHERE s.status = 'running' 
        AND s.started_at < ?
        AND s.enable_vulnerability_scan = 0
        AND NOT EXISTS (
            SELECT 1 FROM scan_results sr WHERE sr.scan_id = s.id
        )
    """, (cutoff_time_normal.isoformat(),)).fetchall()
    
    # Buscar escaneos zombie (con vulnerabilidades) - solo si no tienen resultados, son muy antiguos Y no están en ejecución
    zombies_vulns = cursor.execute("""
        SELECT s.id FROM scans s
        WHERE s.status = 'running' 
        AND s.started_at < ?
        AND s.enable_vulnerability_scan = 1
        AND NOT EXISTS (
            SELECT 1 FROM scan_results sr WHERE sr.scan_id = s.id
        )
    """, (cutoff_time_vulns.isoformat(),)).fetchall()
    
    zombies = list(zombies_normal) + list(zombies_vulns)
    
    if zombies:
        for zombie in zombies:
            scan_id = zombie['id']
            scan_id_str = str(scan_id)
            
            # NO marcar como zombie si el thread está realmente en ejecución
            if scan_id_str in running_scans:
                thread = running_scans[scan_id_str]
                # Verificar si el thread sigue vivo
                if thread.is_alive():
                    continue  # Saltar este escaneo, está realmente en ejecución
            
            # NO marcar como zombie si el proceso está realmente en ejecución (para escaneos pasivos)
            if scan_id_str in running_processes:
                process = running_processes[scan_id_str]
                # Verificar si el proceso sigue vivo
                if process.poll() is None:  # None significa que el proceso sigue ejecutándose
                    continue  # Saltar este escaneo, está realmente en ejecución
            
            # Verificar si hay resultados
            hosts_count = cursor.execute("""
                SELECT COUNT(DISTINCT host_id) FROM scan_results WHERE scan_id = ?
            """, (scan_id,)).fetchone()[0]
            
            ports_count = cursor.execute("""
                SELECT COUNT(*) FROM scan_results WHERE scan_id = ?
            """, (scan_id,)).fetchone()[0]
            
            # Si hay resultados, marcar como completado, si no, como fallido
            if hosts_count > 0 or ports_count > 0:
                status = 'completed'
                error_message = None
            else:
                status = 'failed'
                error_message = "Escaneo zombie detectado y limpiado automáticamente."
            
            cursor.execute("""
                UPDATE scans
                SET status = ?, completed_at = ?, hosts_discovered = ?,
                    ports_found = ?, error_message = ?
                WHERE id = ?
            """, (status, datetime.now().isoformat(), hosts_count, ports_count, 
                  error_message, scan_id))
        
        conn.commit()
        print(f"🧹 Limpiados {len(zombies)} escaneo(s) zombie automáticamente")
    
    # Obtener escaneos
    query = "SELECT * FROM scans WHERE 1=1"
    params = []
    
    if organization:
        query += " AND organization_name = ?"
        params.append(organization.upper())
        
    if location:
        query += " AND location = ?"
        params.append(location.upper())
        
    if scan_id:
        query += " AND id = ?"
        params.append(scan_id)
    
    if status:
        query += " AND status = ?"
        params.append(status)
    
    query += " ORDER BY started_at DESC LIMIT 50"
    
    scans = cursor.execute(query, params).fetchall()
    conn.close()
    
    # Enriquecer con información de si está realmente en ejecución
    result = []
    for scan in scans:
        scan_dict = dict(scan)
        scan_id_str = str(scan_dict['id'])
        
        # Verificar si está realmente en ejecución
        if scan_dict['status'] == 'running':
            if scan_id_str in running_processes:
                process = running_processes[scan_id_str]
                if process.poll() is None:  # Proceso sigue vivo
                    scan_dict['is_really_running'] = True
                else:
                    # Proceso terminó pero no se actualizó el estado
                    scan_dict['is_really_running'] = False
            else:
                scan_dict['is_really_running'] = False
        else:
            scan_dict['is_really_running'] = False
        
        result.append(scan_dict)
    
    return result

@app.post("/api/scans/cleanup-zombies")
async def cleanup_zombie_scans_endpoint(max_hours: float = 2.0):
    """Limpia escaneos zombie manualmente."""
    from datetime import timedelta
    
    conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cutoff_time = datetime.now() - timedelta(hours=max_hours)
    zombies = cursor.execute("""
        SELECT id FROM scans
        WHERE status = 'running' AND started_at < ?
    """, (cutoff_time.isoformat(),)).fetchall()
    
    cleaned = 0
    for zombie in zombies:
        scan_id = zombie['id']
        hosts_count = cursor.execute("""
            SELECT COUNT(DISTINCT host_id) FROM scan_results WHERE scan_id = ?
        """, (scan_id,)).fetchone()[0]
        
        ports_count = cursor.execute("""
            SELECT COUNT(*) FROM scan_results WHERE scan_id = ?
        """, (scan_id,)).fetchone()[0]
        
        if hosts_count > 0 or ports_count > 0:
            status = 'completed'
            error_message = None
        else:
            status = 'failed'
            error_message = f"Escaneo zombie limpiado manualmente (más de {max_hours}h sin actualizar)."
        
        cursor.execute("""
            UPDATE scans
            SET status = ?, completed_at = ?, hosts_discovered = ?,
                ports_found = ?, error_message = ?
            WHERE id = ?
        """, (status, datetime.now().isoformat(), hosts_count, ports_count, 
              error_message, scan_id))
        cleaned += 1
    
    conn.commit()
    conn.close()
    
    return {"cleaned": cleaned, "message": f"Se limpiaron {cleaned} escaneo(s) zombie"}

@app.get("/api/scan/{scan_id}/status")
async def get_scan_status(scan_id: int):
    """Obtiene el estado detallado de un escaneo."""
    conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    scan = cursor.execute("""
        SELECT id, status, hosts_discovered, ports_found, error_message, 
               started_at, completed_at, target_range, scan_mode, pcap_file,
               organization_name, location
        FROM scans WHERE id = ?
    """, (scan_id,)).fetchone()
    
    conn.close()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    
    result = dict(scan)
    
    # Verificar si tiene archivo XML de Nmap
    scan_dir = storage.get_scan_directory(
        scan['organization_name'],
        scan['location'],
        scan_id
    )
    nmap_xml_path = scan_dir / "evidence" / "nmap_scan.xml"
    result['has_nmap'] = nmap_xml_path.exists() if scan_dir.exists() else False
    
    # Verificar si tiene archivo PCAP (acceso directo a sqlite3.Row, no usar .get())
    pcap_file_val = scan['pcap_file'] if scan['pcap_file'] is not None else None
    result['has_pcap'] = bool(pcap_file_val and Path(pcap_file_val).exists())
    
    return result

@app.get("/api/scan/{scan_id}/info")
async def get_scan_info(scan_id: int):
    """Obtiene información sobre un escaneo (si tiene nmap, pcap, etc)."""
    try:
        conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        scan = cursor.execute("""
            SELECT id, organization_name, location, scan_mode, pcap_file
            FROM scans WHERE id = ?
        """, (scan_id,)).fetchone()
        conn.close()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Escaneo no encontrado")
        
        # Acceder correctamente a sqlite3.Row (no tiene .get())
        scan_mode_val = scan['scan_mode'] if scan['scan_mode'] is not None else 'active'
        pcap_file_val = scan['pcap_file'] if scan['pcap_file'] is not None else None
        
        # Verificar si tiene archivo XML de Nmap
        scan_dir = storage.get_scan_directory(
            scan['organization_name'],
            scan['location'],
            scan_id
        )
        nmap_xml_path = scan_dir / "evidence" / "nmap_scan.xml"
        has_nmap = nmap_xml_path.exists() if scan_dir.exists() else False
        
        # Verificar si tiene archivo PCAP
        has_pcap = False
        if pcap_file_val:
            pcap_path = Path(pcap_file_val)
            has_pcap = pcap_path.exists()
        
        return {
            "scan_id": scan['id'],
            "scan_mode": scan_mode_val,
            "has_nmap": has_nmap,
            "has_pcap": has_pcap
        }
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        error_detail = traceback.format_exc()
        print(f"❌ Error en /api/scan/{scan_id}/info: {e}")
        print(error_detail)
        raise HTTPException(status_code=500, detail=f"Error obteniendo información del escaneo: {str(e)}")

@app.post("/api/scan/start")
async def start_scan(config: ScanConfig):
    """Inicia un nuevo escaneo (activo o pasivo)."""
    # Validar scan_mode
    if config.scan_mode not in ["active", "passive"]:
        raise HTTPException(
            status_code=400, 
            detail=f"Modo de escaneo inválido: '{config.scan_mode}'. Debe ser 'active' o 'passive'"
        )
    
    # Validar target_range para escaneos activos
    if config.scan_mode == "active":
        if not config.target_range or config.target_range.strip() == "":
            raise HTTPException(status_code=400, detail="target_range es requerido para escaneos activos")
        if not check_dependencies(check_optional=False, check_screenshots=config.screenshots):
            raise HTTPException(status_code=400, detail="Dependencias críticas faltantes")
    elif config.scan_mode == "passive":
        # Para escaneos pasivos, target_range no es crítico (usar por defecto si no se proporciona)
        if not config.target_range or config.target_range.strip() == "":
            config.target_range = "0.0.0.0/0"
        # Verificar que tshark esté disponible usando el sistema de verificación de dependencias
        from arsenal.scripts.check_env import DependencyChecker
        checker = DependencyChecker()
        tshark_found = checker.check_command(
            'tshark',
            'tshark (Wireshark)',
            'Necesario para escaneos pasivos de tráfico de red',
            critical=True,
            install_instructions=checker._get_tshark_install()
        )
        if not tshark_found:
            install_cmd = checker._get_tshark_install()
            raise HTTPException(
                status_code=400,
                detail=f"tshark (Wireshark) es requerido para escaneos pasivos pero no está instalado. Instala ejecutando: {install_cmd}"
            )
    
    # Determinar scan_type según el modo
    scan_type = "passive" if config.scan_mode == "passive" else config.nmap_speed
    
    # Crear escaneo en BD
    scan_id = storage.start_scan(
        organization=config.organization,
        location=config.location,
        scan_type=scan_type,
        target_range=config.target_range,
        interface=config.interface,
        enable_version_detection=config.nmap_versions if config.scan_mode == "active" else False,
        enable_vulnerability_scan=config.nmap_vulns if config.scan_mode == "active" else False,
        enable_screenshots=config.screenshots if config.scan_mode == "active" else False,
        enable_source_code=config.source_code if config.scan_mode == "active" else False,
        scan_mode=config.scan_mode
    )
    
    # Iniciar escaneo en background según el modo
    if config.scan_mode == "passive":
        scan_thread = threading.Thread(
            target=run_passive_scan_background,
            args=(scan_id, config, str(scan_id)),
            daemon=True
        )
    else:
        scan_thread = threading.Thread(
            target=run_scan_background,
            args=(scan_id, config, str(scan_id)),
            daemon=True
        )
    scan_thread.start()
    running_scans[str(scan_id)] = scan_thread
    
    return {"scan_id": scan_id, "status": "started", "mode": config.scan_mode}

@app.post("/api/scan/{scan_id}/cancel")
async def cancel_scan(scan_id: int):
    """Cancela un escaneo en ejecución (activo o pasivo)."""
    scan_id_str = str(scan_id)
    
    # Verificar si el escaneo está en ejecución
    if scan_id_str not in running_processes:
        # Verificar en la BD si está running
        conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        scan = cursor.execute("SELECT status FROM scans WHERE id = ?", (scan_id,)).fetchone()
        conn.close()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Escaneo no encontrado")
        if scan['status'] != 'running':
            raise HTTPException(status_code=400, detail=f"El escaneo no está en ejecución (estado: {scan['status']})")
        
        # Si no está en running_processes pero está running, marcar como cancelado
        storage.complete_scan(scan_id, error_message="Escaneo cancelado por el usuario")
        return {"status": "success", "message": "Escaneo cancelado"}
    
    # Obtener el proceso
    process = running_processes[scan_id_str]
    
    try:
        # Terminar el proceso
        process.terminate()
        try:
            process.wait(timeout=5)
        except:
            process.kill()
        
        # Marcar como cancelado en la BD
        storage.complete_scan(scan_id, error_message="Escaneo cancelado por el usuario")
        
        # Limpiar de los diccionarios
        if scan_id_str in running_processes:
            del running_processes[scan_id_str]
        if scan_id_str in running_scans:
            del running_scans[scan_id_str]
        
        return {"status": "success", "message": "Escaneo cancelado correctamente"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error cancelando escaneo: {str(e)}")

@app.get("/api/scan/{scan_id}/pcap")
async def download_pcap(scan_id: int):
    """Descarga el archivo pcap de un escaneo pasivo."""
    try:
        # Obtener información del escaneo
        conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        scan = cursor.execute("""
            SELECT organization_name, location, pcap_file, scan_mode 
            FROM scans WHERE id = ?
        """, (scan_id,)).fetchone()
        conn.close()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Escaneo no encontrado")
        
        scan_mode_val = scan['scan_mode'] if scan['scan_mode'] is not None else 'active'
        if scan_mode_val != 'passive':
            raise HTTPException(status_code=400, detail="Este escaneo no es pasivo, no tiene archivo pcap")
        
        pcap_file = scan['pcap_file']
        if not pcap_file:
            raise HTTPException(status_code=404, detail="No se encontró archivo pcap para este escaneo. El escaneo pasivo puede no haber generado archivo aún.")
        
        pcap_path = Path(pcap_file)
        if not pcap_path.exists():
            raise HTTPException(
                status_code=404, 
                detail=f"El archivo pcap no existe en el sistema de archivos: {pcap_file}"
            )
        
        # Retornar el archivo
        return FileResponse(
            path=str(pcap_path),
            filename=pcap_path.name,
            media_type='application/vnd.tcpdump.pcap',
            headers={
                "Content-Disposition": f"attachment; filename={pcap_path.name}"
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        error_detail = traceback.format_exc()
        print(f"❌ Error descargando PCAP para escaneo {scan_id}: {e}")
        print(error_detail)
        raise HTTPException(status_code=500, detail=f"Error descargando archivo pcap: {str(e)}")

@app.post("/api/scan/import-xml")
async def import_nmap_xml(
    xml_file: UploadFile = File(...),
    organization: str = Form(...),
    location: str = Form(...)
):
    """Importa un escaneo Nmap desde un archivo XML."""
    try:
        # Validar que el archivo es XML
        if not xml_file.filename.endswith('.xml'):
            raise HTTPException(status_code=400, detail="El archivo debe ser un XML de Nmap")
        
        # Guardar temporalmente el archivo para parsearlo primero
        with tempfile.NamedTemporaryFile(delete=False, suffix='.xml') as tmp_file:
            shutil.copyfileobj(xml_file.file, tmp_file)
            tmp_xml_path = tmp_file.name
        
        # Parsear XML para extraer información del escaneo
        parser = NmapXMLParser(tmp_xml_path)
        parsed_data = parser.parse()
        scan_info = parsed_data.get('scan_info', {})
        
        # Extraer el rango/target del escaneo
        target_range = 'imported_from_xml'
        nmap_args = scan_info.get('args', '')
        
        # Intentar extraer el target de los argumentos del comando Nmap
        # El target suele ser el último argumento que no es una opción
        if nmap_args:
            # Buscar IPs o rangos en los argumentos
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b'
            ip_ranges = re.findall(ip_pattern, nmap_args)
            if ip_ranges:
                # Usar el primer rango encontrado, o todos si hay múltiples
                if len(ip_ranges) == 1:
                    target_range = ip_ranges[0]
                else:
                    # Si hay múltiples, usar el primero o combinarlos
                    target_range = ip_ranges[0] if len(ip_ranges[0]) <= 20 else ', '.join(ip_ranges[:3])
        
        # Si no se encontró en args, intentar construir un rango desde los hosts encontrados
        if target_range == 'imported_from_xml' and parsed_data.get('hosts'):
            hosts = list(parsed_data['hosts'].keys())
            if hosts:
                if len(hosts) == 1:
                    target_range = hosts[0]
                elif len(hosts) <= 5:
                    target_range = ', '.join(hosts)
                else:
                    # Si hay muchos hosts, usar el primero y último
                    sorted_hosts = sorted(hosts, key=lambda x: ipaddress.ip_address(x) if '.' in x else x)
                    target_range = f"{sorted_hosts[0]} - {sorted_hosts[-1]} ({len(hosts)} hosts)"
        
        # Construir el nombre del escaneo con el rango
        scan_name = f"imported ({target_range})"
        
        # Crear escaneo en BD con el rango extraído
        scan_id = storage.start_scan(
            organization=organization,
            location=location,
            scan_type='imported',
            target_range=target_range,
            interface='N/A',
            nmap_command=scan_name,
            enable_version_detection=True,
            enable_vulnerability_scan=False,
            enable_screenshots=False,
            enable_source_code=False
        )
        
        # Obtener directorio del escaneo
        scan_dir = storage.get_scan_directory(organization, location, scan_id)
        evidence_dir = scan_dir / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        nmap_xml_path = evidence_dir / "nmap_scan.xml"
        
        # Copiar el archivo XML al directorio del escaneo
        shutil.copy2(tmp_xml_path, nmap_xml_path)
        os.unlink(tmp_xml_path)  # Eliminar archivo temporal
        
        # Procesar hosts
        total_hosts = len(parsed_data['hosts'])
        hosts_processed = 0
        ports_processed = 0
        
        # Subredes privadas para determinar subnet
        private_subnets = [
            ipaddress.ip_network(subnet) for subnet in ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16']
        ]
        
        for host_ip, host_data in parsed_data['hosts'].items():
            try:
                # Determinar subred
                subnet = "Public IP"
                for private_net in private_subnets:
                    try:
                        if ipaddress.ip_address(host_ip) in private_net:
                            subnet = str(private_net)
                            break
                    except:
                        pass
                
                # Obtener hostname
                hostname = host_data.get('hostname') or None
                
                # Preparar datos adicionales del host
                host_additional_data = {
                    'hostnames': host_data.get('hostnames', []),
                    'mac_address': host_data.get('mac_address'),
                    'vendor': host_data.get('vendor'),
                    'os': host_data.get('os', {}),
                    'host_scripts': host_data.get('host_scripts', {})
                }
                
                # Si no hay puertos abiertos, registrar el host de todas formas
                if not host_data.get('ports'):
                    storage.save_host_result(
                        scan_id=scan_id,
                        host_ip=host_ip,
                        port=None,
                        protocol=None,
                        state=host_data.get('status', 'up'),
                        service_data={},
                        subnet=subnet,
                        hostname=hostname,
                        host_data=host_additional_data,
                        discovery_method='nmap'
                    )
                    hosts_processed += 1
                    continue
                
                # Procesar puertos
                for port_key, port_data in host_data['ports'].items():
                    # Extraer número de puerto y protocolo
                    if isinstance(port_key, str) and '/' in port_key:
                        port_num_str, proto = port_key.split('/', 1)
                        port_num = int(port_num_str)
                    else:
                        port_num = int(port_key) if isinstance(port_key, str) else port_key
                        proto = port_data.get('protocol', 'tcp')
                    
                    # Preparar datos del servicio
                    service_data = {
                        'name': port_data.get('name', ''),
                        'product': port_data.get('product', ''),
                        'version': port_data.get('version', ''),
                        'extrainfo': port_data.get('extrainfo', ''),
                        'cpe': port_data.get('cpe', ''),
                        'reason': port_data.get('reason', ''),
                        'reason_ttl': port_data.get('reason_ttl', ''),
                        'conf': port_data.get('conf', 0),
                        'scripts': port_data.get('scripts', {})
                    }
                    
                    # Guardar resultado en base de datos
                    storage.save_host_result(
                        scan_id=scan_id,
                        host_ip=host_ip,
                        port=port_num,
                        protocol=proto,
                        state=port_data['state'],
                        service_data=service_data,
                        subnet=subnet,
                        hostname=hostname,
                        host_data=host_additional_data,
                        discovery_method='nmap'
                    )
                    ports_processed += 1
                    
                    # Procesar vulnerabilidades de scripts NSE
                    scripts = port_data.get('scripts', {})
                    for script_id, script_output in scripts.items():
                        if isinstance(script_output, dict):
                            output_text = script_output.get('output', '')
                            script_data = script_output
                        else:
                            output_text = str(script_output)
                            script_data = {}
                        
                        # Extraer vulnerabilidades
                        vulnerabilities = VulnerabilityParser.extract_vulnerabilities(
                            script_id, output_text, script_data
                        )
                        
                        # Guardar cada vulnerabilidad
                        for vuln in vulnerabilities:
                            storage.save_vulnerability(
                                scan_id=scan_id,
                                host_ip=host_ip,
                                port=port_num,
                                protocol=proto,
                                vulnerability_type=vuln.get('type', 'unknown'),
                                title=vuln.get('title', ''),
                                description=vuln.get('description', ''),
                                severity=vuln.get('severity', 'info'),
                                cvss_score=vuln.get('cvss', None),
                                references=vuln.get('references', ''),
                                script_id=script_id,
                                script_output=output_text
                            )
                
                hosts_processed += 1
            except Exception as e:
                print(f"Error procesando host {host_ip}: {e}")
                continue
        
        # Marcar escaneo como completado
        storage.complete_scan(scan_id)
        
        return {
            "status": "success",
            "scan_id": scan_id,
            "message": f"Escaneo importado exitosamente",
            "stats": {
                "hosts_processed": hosts_processed,
                "ports_processed": ports_processed,
                "total_hosts": total_hosts
            }
        }
    except Exception as e:
        # Si hay error, marcar el escaneo como fallido
        if 'scan_id' in locals():
            storage.complete_scan(scan_id, error_message=str(e))
        raise HTTPException(status_code=500, detail=f"Error importando XML: {str(e)}")

@app.post("/api/scan/import-pcap")
async def import_pcap(
    pcap_file: UploadFile = File(...),
    organization: str = Form(...),
    location: str = Form(...)
):
    """Importa un escaneo pasivo desde un archivo PCAP."""
    try:
        # Validar que el archivo es PCAP
        filename_lower = pcap_file.filename.lower()
        if not (filename_lower.endswith('.pcap') or filename_lower.endswith('.pcapng')):
            raise HTTPException(status_code=400, detail="El archivo debe ser un PCAP o PCAPNG")
        
        # Crear escaneo en BD con modo pasivo
        scan_id = storage.start_scan(
            organization=organization,
            location=location,
            scan_type='imported',
            target_range='0.0.0.0/0',  # Pasivo, no hay target específico
            interface='N/A',
            nmap_command='imported_pcap',
            enable_version_detection=False,
            enable_vulnerability_scan=False,
            enable_screenshots=False,
            enable_source_code=False,
            scan_mode='passive',
            pcap_file=None  # Se actualizará después de guardar el archivo
        )
        
        # Obtener directorio del escaneo
        scan_dir = storage.get_scan_directory(organization, location, scan_id)
        evidence_dir = scan_dir / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        
        # Determinar extensión del archivo
        file_ext = '.pcap' if filename_lower.endswith('.pcap') else '.pcapng'
        pcap_path = evidence_dir / f"capture{file_ext}"
        
        # Guardar el archivo PCAP
        with open(pcap_path, 'wb') as f:
            shutil.copyfileobj(pcap_file.file, f)
        
        # Actualizar el registro del scan con la ruta del PCAP
        conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL")
        cursor = conn.cursor()
        cursor.execute("UPDATE scans SET pcap_file = ? WHERE id = ?", (str(pcap_path), scan_id))
        conn.commit()
        conn.close()
        
        # Procesar el PCAP usando la misma función que se usa en escaneos pasivos
        process_pcap_file(scan_id, str(pcap_path), organization, location)
        
        # Contar hosts y puertos finales
        conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL")
        cursor = conn.cursor()
        
        hosts_count = cursor.execute("""
            SELECT COUNT(DISTINCT host_id) FROM scan_results WHERE scan_id = ?
        """, (scan_id,)).fetchone()[0]
        
        ports_count = cursor.execute("""
            SELECT COUNT(*) FROM scan_results WHERE scan_id = ? AND port IS NOT NULL
        """, (scan_id,)).fetchone()[0]
        
        conn.close()
        
        # Marcar escaneo como completado
        storage.complete_scan(scan_id, hosts_count=hosts_count, ports_count=ports_count)
        
        return {
            "status": "success",
            "scan_id": scan_id,
            "message": f"PCAP importado y procesado exitosamente",
            "stats": {
                "hosts_processed": hosts_count,
                "ports_processed": ports_count
            }
        }
    except Exception as e:
        # Si hay error, marcar el escaneo como fallido
        if 'scan_id' in locals():
            storage.complete_scan(scan_id, error_message=str(e))
        raise HTTPException(status_code=500, detail=f"Error importando PCAP: {str(e)}")

def run_scan_background(scan_id: int, config: ScanConfig, ws_id: str):
    """Ejecuta el escaneo en background usando scanners directamente."""
    try:
        # Importar módulos de screenshots/source code si están disponibles
        try:
            from protocols.web import take_screenshot, get_source
            WEB_PROTOCOLS_AVAILABLE = True
        except ImportError:
            WEB_PROTOCOLS_AVAILABLE = False
            take_screenshot = None
            get_source = None
        
        # Actualizar progreso inicial
        try:
            conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
            conn.execute("PRAGMA journal_mode=WAL")
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE scans 
                SET status = 'running', hosts_discovered = 0, ports_found = 0
                WHERE id = ?
            """, (scan_id,))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[Scan {scan_id}] Error actualizando estado inicial: {e}")
        
        # Obtener directorio del escaneo
        scan_dir = storage.get_scan_directory(config.organization, config.location, scan_id)
        evidence_dir = scan_dir / "evidence"
        img_dir = evidence_dir / "img"
        source_dir = evidence_dir / "source"
        nmap_xml_path = evidence_dir / "nmap_scan.xml"
        
        # Crear directorios necesarios
        evidence_dir.mkdir(parents=True, exist_ok=True)
        img_dir.mkdir(parents=True, exist_ok=True)
        source_dir.mkdir(parents=True, exist_ok=True)
        
        # Subredes privadas para determinar subnet
        private_subnets = [
            ipaddress.ip_network(subnet) for subnet in ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16']
        ]
        
        discovered_ips = set()
        
        # ============================================================================
        # PASO 1: HOST DISCOVERY (si está habilitado)
        # ============================================================================
        if config.host_discovery:
            print(f"[Scan {scan_id}] 🔍 Iniciando descubrimiento de hosts...")
            try:
                host_discovery = HostDiscovery(interface=config.interface)
                discovered_ips = host_discovery.discover_hosts(config.target_range)
                print(f"[Scan {scan_id}] ✅ Descubiertos {len(discovered_ips)} hosts")
                
                # Guardar hosts descubiertos en la BD
                for host_ip in discovered_ips:
                    try:
                        # Determinar subred
                        subnet = "Public IP"
                        for private_net in private_subnets:
                            try:
                                if ipaddress.ip_address(host_ip) in private_net:
                                    subnet = str(private_net)
                                    break
                            except:
                                pass
                        
                        storage.save_discovered_host(
                            scan_id=scan_id,
                            host_ip=host_ip,
                            discovery_method='host_discovery',
                            subnet=subnet
                        )
                    except Exception as e:
                        print(f"[Scan {scan_id}] ⚠️  Error guardando host {host_ip}: {e}")
            except Exception as e:
                print(f"[Scan {scan_id}] ⚠️  Error en host discovery: {e}")
                import traceback
                traceback.print_exc()
        
        # ============================================================================
        # PASO 2: NMAP SCAN (si está habilitado)
        # ============================================================================
        if config.nmap:
            print(f"[Scan {scan_id}] 🔍 Iniciando escaneo Nmap...")
            
            # Determinar targets: usar IPs descubiertas si hay, sino usar el rango
            if discovered_ips:
                targets = sorted(list(discovered_ips))
                target_str = ' '.join(targets)
                print(f"[Scan {scan_id}] 📋 Escaneando {len(targets)} hosts descubiertos...")
            else:
                target_str = config.target_range
                print(f"[Scan {scan_id}] 📋 Escaneando rango: {target_str}")
            
            try:
                # Crear scanner de puertos
                port_scanner = PortScanner(output_file=str(nmap_xml_path))
                
                # Ejecutar escaneo Nmap
                xml_file = port_scanner.scan(
                    target_range=target_str,
                    speed=config.nmap_speed,
                    ot_ports=config.nmap_ot_ports,
                    it_ports=config.nmap_it_ports,
                    custom_ports=config.custom_ports,
                    enable_versions=config.nmap_versions,
                    enable_vulns=config.nmap_vulns,
                    output_file=str(nmap_xml_path)
                )
                
                if not xml_file or not Path(xml_file).exists():
                    raise Exception("Nmap no generó el archivo XML de salida")
                
                print(f"[Scan {scan_id}] ✅ Nmap completado. Procesando resultados...")
                
                # Procesar resultados XML
                parser = NmapXMLParser(nmap_xml_path)
                parsed_data = parser.parse()
                
                total_hosts = len(parsed_data['hosts'])
                hosts_processed = 0
                ports_processed = 0
                
                print(f"[Scan {scan_id}] 📊 Procesando {total_hosts} host(s)...")
                
                # Procesar cada host
                for host_ip, host_data in parsed_data['hosts'].items():
                    try:
                        # Determinar subred
                        subnet = "Public IP"
                        for private_net in private_subnets:
                            try:
                                if ipaddress.ip_address(host_ip) in private_net:
                                    subnet = str(private_net)
                                    break
                            except:
                                pass
                        
                        # Obtener hostname
                        hostname = host_data.get('hostname') or None
                        
                        # Preparar datos adicionales del host
                        host_additional_data = {
                            'hostnames': host_data.get('hostnames', []),
                            'mac_address': host_data.get('mac_address'),
                            'vendor': host_data.get('vendor'),
                            'os': host_data.get('os', {}),
                            'host_scripts': host_data.get('host_scripts', {})
                        }
                        
                        # Si no hay puertos abiertos, registrar el host de todas formas
                        if not host_data.get('ports'):
                            storage.save_host_result(
                                scan_id=scan_id,
                                host_ip=host_ip,
                                port=None,
                                protocol=None,
                                state=host_data.get('status', 'up'),
                                service_data={},
                                subnet=subnet,
                                hostname=hostname,
                                host_data=host_additional_data,
                                discovery_method='nmap'
                            )
                            hosts_processed += 1
                            continue
                        
                        # Procesar puertos
                        for port_key, port_data in host_data['ports'].items():
                            # Extraer número de puerto y protocolo
                            if isinstance(port_key, str) and '/' in port_key:
                                port_num_str, proto = port_key.split('/', 1)
                                port_num = int(port_num_str)
                            else:
                                port_num = int(port_key) if isinstance(port_key, str) else port_key
                                proto = port_data.get('protocol', 'tcp')
                            
                            # Preparar datos del servicio
                            service_data = {
                                'name': port_data.get('name', ''),
                                'product': port_data.get('product', ''),
                                'version': port_data.get('version', ''),
                                'extrainfo': port_data.get('extrainfo', ''),
                                'cpe': port_data.get('cpe', ''),
                                'reason': port_data.get('reason', ''),
                                'reason_ttl': port_data.get('reason_ttl', ''),
                                'conf': port_data.get('conf', 0),
                                'scripts': port_data.get('scripts', {})
                            }
                            
                            # Guardar resultado en base de datos
                            storage.save_host_result(
                                scan_id=scan_id,
                                host_ip=host_ip,
                                port=port_num,
                                protocol=proto,
                                state=port_data['state'],
                                service_data=service_data,
                                subnet=subnet,
                                hostname=hostname,
                                host_data=host_additional_data,
                                discovery_method='nmap'
                            )
                            ports_processed += 1
                            
                            # Procesar vulnerabilidades de scripts NSE
                            scripts = port_data.get('scripts', {})
                            for script_id, script_output in scripts.items():
                                if isinstance(script_output, dict):
                                    output_text = script_output.get('output', '')
                                    script_data = script_output
                                else:
                                    output_text = str(script_output)
                                    script_data = {}
                                
                                # Extraer vulnerabilidades
                                vulnerabilities = VulnerabilityParser.extract_vulnerabilities(
                                    script_id, output_text, script_data
                                )
                                
                                # Guardar cada vulnerabilidad
                                for vuln in vulnerabilities:
                                    storage.save_vulnerability(
                                        scan_id=scan_id,
                                        host_ip=host_ip,
                                        port=port_num,
                                        protocol=proto,
                                        vulnerability_type=vuln.get('type', 'unknown'),
                                        title=vuln.get('title', ''),
                                        description=vuln.get('description', ''),
                                        severity=vuln.get('severity', 'info'),
                                        cvss_score=vuln.get('cvss', None),
                                        references=vuln.get('references', ''),
                                        script_id=script_id,
                                        script_output=output_text
                                    )
                            
                            # Screenshots (si está habilitado y es servicio web)
                            if config.screenshots and WEB_PROTOCOLS_AVAILABLE and take_screenshot:
                                if port_num in [80, 443, 8080, 8443, 8000] or 'http' in service_data.get('name', '').lower():
                                    try:
                                        screenshot = take_screenshot(host_ip, port_num, str(img_dir))
                                        if screenshot:
                                            storage.save_enrichment(
                                                scan_id=scan_id,
                                                host_ip=host_ip,
                                                port=port_num,
                                                protocol=proto,
                                                enrichment_type='Screenshot',
                                                data=screenshot,
                                                file_path=str(img_dir / f"{host_ip}_{port_num}.png")
                                            )
                                    except Exception as e:
                                        print(f"[Scan {scan_id}] ⚠️  Error tomando screenshot de {host_ip}:{port_num}: {e}")
                            
                            # Source code (si está habilitado y es servicio web)
                            if config.source_code and WEB_PROTOCOLS_AVAILABLE and get_source:
                                if port_num in [80, 443, 8080, 8443, 8000] or 'http' in service_data.get('name', '').lower():
                                    try:
                                        source = get_source(host_ip, port_num, str(source_dir))
                                        if source:
                                            storage.save_enrichment(
                                                scan_id=scan_id,
                                                host_ip=host_ip,
                                                port=port_num,
                                                protocol=proto,
                                                enrichment_type='Websource',
                                                data=source,
                                                file_path=str(source_dir / f"{host_ip}_{port_num}.txt")
                                            )
                                    except Exception as e:
                                        print(f"[Scan {scan_id}] ⚠️  Error obteniendo source code de {host_ip}:{port_num}: {e}")
                        
                        hosts_processed += 1
                    except Exception as e:
                        print(f"[Scan {scan_id}] ⚠️  Error procesando host {host_ip}: {e}")
                        import traceback
                        traceback.print_exc()
                        continue
                
                print(f"[Scan {scan_id}] ✅ Procesados {hosts_processed} hosts y {ports_processed} puertos")
                
            except Exception as e:
                print(f"[Scan {scan_id}] ❌ Error en escaneo Nmap: {e}")
                import traceback
                traceback.print_exc()
                raise
        
        # Contar hosts y puertos finales
        try:
            conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
            conn.execute("PRAGMA journal_mode=WAL")
            cursor = conn.cursor()
            
            hosts_count = cursor.execute("""
                SELECT COUNT(DISTINCT host_id) FROM scan_results WHERE scan_id = ?
            """, (scan_id,)).fetchone()[0]
            
            ports_count = cursor.execute("""
                SELECT COUNT(*) FROM scan_results WHERE scan_id = ? AND port IS NOT NULL
            """, (scan_id,)).fetchone()[0]
            
            conn.close()
            storage.complete_scan(scan_id, hosts_count=hosts_count, ports_count=ports_count)
            print(f"[Scan {scan_id}] ✅ ESCANEO COMPLETADO EXITOSAMENTE")
            print(f"[Scan {scan_id}]    Hosts descubiertos: {hosts_count}")
            print(f"[Scan {scan_id}]    Puertos encontrados: {ports_count}")
        except Exception as e:
            print(f"[Scan {scan_id}] ⚠️  Error contando resultados finales: {e}")
            import traceback
            traceback.print_exc()
            # Intentar contar resultados aunque haya error, para no marcar como failed prematuramente
            try:
                conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
                conn.execute("PRAGMA journal_mode=WAL")
                cursor = conn.cursor()
                hosts_count = cursor.execute("""
                    SELECT COUNT(DISTINCT host_id) FROM scan_results WHERE scan_id = ?
                """, (scan_id,)).fetchone()[0]
                ports_count = cursor.execute("""
                    SELECT COUNT(*) FROM scan_results WHERE scan_id = ? AND port IS NOT NULL
                """, (scan_id,)).fetchone()[0]
                conn.close()
                storage.complete_scan(scan_id, hosts_count=hosts_count, ports_count=ports_count)
            except:
                # Solo si realmente no podemos contar, completar sin parámetros
                storage.complete_scan(scan_id)
            
    except Exception as e:
        error_msg = f"Error ejecutando escaneo: {str(e)}"
        print(f"\n[Scan {scan_id}] ❌ ERROR CRÍTICO")
        print(f"[Scan {scan_id}]    {error_msg}")
        import traceback
        traceback.print_exc()
        storage.complete_scan(scan_id, error_message=error_msg[:1000])
    finally:
        # Limpiar procesos de los diccionarios
        if str(scan_id) in running_processes:
            del running_processes[str(scan_id)]
        if str(scan_id) in running_scans:
            del running_scans[str(scan_id)]

def run_passive_scan_background(scan_id: int, config: ScanConfig, ws_id: str):
    """Ejecuta un escaneo pasivo capturando tráfico usando PassiveCapture."""
    import time
    
    # Obtener información del escaneo
    conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
    conn.execute("PRAGMA journal_mode=WAL")
    cursor = conn.cursor()
    scan_info = cursor.execute("""
        SELECT organization_name, location FROM scans WHERE id = ?
    """, (scan_id,)).fetchone()
    conn.close()
    
    if not scan_info:
        print(f"[Scan {scan_id}] ❌ Escaneo no encontrado en BD")
        return
    
    organization, location = scan_info
    
    # Actualizar estado a running
    try:
        conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL")
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE scans 
            SET status = 'running', hosts_discovered = 0, ports_found = 0
            WHERE id = ?
        """, (scan_id,))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[Scan {scan_id}] Error actualizando estado inicial: {e}")
        return
    
    # Obtener directorio del escaneo
    scan_dir = storage.get_scan_directory(organization, location, scan_id)
    pcap_dir = scan_dir / "pcap"
    pcap_dir.mkdir(exist_ok=True)
    
    # Generar nombre de archivo pcap
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    pcap_file = pcap_dir / f"capture_{scan_id:06d}_{timestamp}.pcap"
    
    # Actualizar BD con la ruta del pcap
    try:
        conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL")
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE scans SET pcap_file = ? WHERE id = ?
        """, (str(pcap_file), scan_id))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[Scan {scan_id}] Error guardando ruta del pcap: {e}")
    
    print(f"[Scan {scan_id}] 🎧 Iniciando captura pasiva...")
    print(f"[Scan {scan_id}]    Interfaz: {config.interface}")
    print(f"[Scan {scan_id}]    Filtro: {config.pcap_filter or 'Ninguno'}")
    print(f"[Scan {scan_id}]    Archivo: {pcap_file}\n")
    
    try:
        # Usar PassiveCapture para iniciar la captura
        passive_capture = PassiveCapture(interface=config.interface)
        process = passive_capture.start_capture(
            output_file=str(pcap_file),
            filter=config.pcap_filter,
            duration=86400  # 24 horas máximo
        )
        
        # Guardar proceso para poder cancelarlo
        running_processes[str(scan_id)] = process
        
        print(f"[Scan {scan_id}] ✅ Captura iniciada (PID: {process.pid})")
        
        # Procesar pcap periódicamente mientras se captura
        last_process_time = time.time()
        process_interval = 30  # Procesar cada 30 segundos
        
        while True:
            # Verificar si el proceso sigue corriendo
            if process.poll() is not None:
                # Proceso terminó
                return_code = process.returncode
                if return_code != 0:
                    error_msg = f"tshark terminó con código {return_code}"
                    print(f"[Scan {scan_id}] ❌ {error_msg}")
                    storage.complete_scan(scan_id, error_message=error_msg)
                else:
                    # Proceso completado normalmente
                    print(f"[Scan {scan_id}] ✅ Captura completada")
                    # Procesar pcap final
                    process_pcap_file(scan_id, str(pcap_file), organization, location)
                break
            
            # Procesar pcap periódicamente
            current_time = time.time()
            if current_time - last_process_time >= process_interval:
                if pcap_file.exists() and pcap_file.stat().st_size > 0:
                    try:
                        process_pcap_file(scan_id, str(pcap_file), organization, location)
                        last_process_time = current_time
                    except Exception as e:
                        print(f"[Scan {scan_id}] ⚠️  Error procesando pcap: {e}")
            
            # Pequeña pausa
            time.sleep(1)
            
            # Verificar si el escaneo fue cancelado (marcado como tal en BD)
            try:
                conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
                conn.execute("PRAGMA journal_mode=WAL")
                cursor = conn.cursor()
                status = cursor.execute("SELECT status FROM scans WHERE id = ?", (scan_id,)).fetchone()
                conn.close()
                if status and status[0] != 'running':
                    # Escaneo fue cancelado o completado
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except:
                        process.kill()
                    break
            except Exception:
                pass
        
        # Procesar pcap final si aún existe
        if pcap_file.exists() and pcap_file.stat().st_size > 0:
            try:
                process_pcap_file(scan_id, str(pcap_file), organization, location)
            except Exception as e:
                print(f"[Scan {scan_id}] ⚠️  Error procesando pcap final: {e}")
        
        # Contar hosts y puertos finales
        try:
            conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
            conn.execute("PRAGMA journal_mode=WAL")
            cursor = conn.cursor()
            
            hosts_count = cursor.execute("""
                SELECT COUNT(DISTINCT host_id) FROM scan_results WHERE scan_id = ?
            """, (scan_id,)).fetchone()[0]
            
            ports_count = cursor.execute("""
                SELECT COUNT(*) FROM scan_results WHERE scan_id = ? AND port IS NOT NULL
            """, (scan_id,)).fetchone()[0]
            
            conn.close()
            storage.complete_scan(scan_id, hosts_count=hosts_count, ports_count=ports_count)
            print(f"[Scan {scan_id}] ✅ ESCANEO PASIVO COMPLETADO")
            print(f"[Scan {scan_id}]    Hosts descubiertos: {hosts_count}")
            print(f"[Scan {scan_id}]    Puertos encontrados: {ports_count}")
        except Exception as e:
            print(f"[Scan {scan_id}] ⚠️  Error contando resultados finales: {e}")
            storage.complete_scan(scan_id)
            
    except Exception as e:
        error_msg = f"Error ejecutando escaneo pasivo: {str(e)}"
        print(f"\n[Scan {scan_id}] ❌ ERROR CRÍTICO")
        print(f"[Scan {scan_id}]    {error_msg}")
        import traceback
        traceback.print_exc()
        storage.complete_scan(scan_id, error_message=error_msg[:1000])
    finally:
        # Limpiar procesos de los diccionarios
        if str(scan_id) in running_processes:
            del running_processes[str(scan_id)]
        if str(scan_id) in running_scans:
            del running_scans[str(scan_id)]

def process_pcap_file(scan_id: int, pcap_file: str, organization: str, location: str):
    """Procesa un archivo pcap usando PassiveCapture y guarda resultados en la BD."""
    try:
        # Usar PassiveCapture para extraer conexiones
        passive_capture = PassiveCapture()
        connections = passive_capture.extract_connections(pcap_file)
        
        print(f"[Scan {scan_id}] 📊 Procesando {len(connections)} conexiones del pcap...")
        
        # Subredes privadas para determinar subnet
        private_subnets = [
            ipaddress.ip_network(subnet) for subnet in ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16']
        ]
        
        # Guardar conexiones en la BD (solo IPs privadas)
        for ip, port, protocol in connections:
            try:
                # Validar IP y verificar que sea privada
                ip_obj = ipaddress.ip_address(ip)
                if not ip_obj.is_private:
                    # IP pública, saltar
                    continue
                
                # Determinar subred
                subnet = "Private IP (unknown subnet)"
                for private_net in private_subnets:
                    try:
                        if ip_obj in private_net:
                            subnet = str(private_net)
                            break
                    except:
                        pass
                
                # Guardar host si no existe (solo IPs privadas)
                storage.save_discovered_host(scan_id, ip, discovery_method='passive_capture', subnet=subnet)
                
                # Guardar puerto descubierto
                conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA foreign_keys = ON")
                cursor = conn.cursor()
                
                # Obtener host_id
                host_row = cursor.execute("SELECT id FROM hosts WHERE ip_address = ?", (ip,)).fetchone()
                if host_row:
                    host_id = host_row[0]
                    
                    # Verificar si ya existe este resultado
                    existing = cursor.execute("""
                        SELECT id FROM scan_results 
                        WHERE scan_id = ? AND host_id = ? AND port = ? AND protocol = ?
                    """, (scan_id, host_id, port, protocol)).fetchone()
                    
                    if not existing:
                        # Guardar resultado
                        cursor.execute("""
                            INSERT INTO scan_results 
                            (scan_id, host_id, port, protocol, state, discovered_at, discovery_method)
                            VALUES (?, ?, ?, ?, 'open', datetime('now'), ?)
                        """, (scan_id, host_id, port, protocol, 'passive_capture'))
                        conn.commit()
                    
                conn.close()
            except (ValueError, ipaddress.AddressValueError):
                continue  # IP inválida, saltar
            except Exception as e:
                print(f"[Scan {scan_id}] ⚠️  Error guardando {ip}:{port}/{protocol}: {e}")
                continue
        
        print(f"[Scan {scan_id}] ✅ Procesamiento de pcap completado")
        
    except Exception as e:
        print(f"[Scan {scan_id}] ❌ Error procesando pcap: {e}")
        import traceback
        traceback.print_exc()

@app.websocket("/ws/scan/{scan_id}")
async def websocket_scan_progress(websocket: WebSocket, scan_id: str):
    """WebSocket para recibir progreso del escaneo."""
    await manager.connect(websocket, scan_id)
    try:
        last_status = None
        last_hosts = -1
        last_ports = -1
        
        # Obtener estado del escaneo desde la BD periódicamente
        while True:
            try:
                # Obtener progreso real del escaneo
                conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                scan = cursor.execute(
                    """SELECT status, hosts_discovered, ports_found, error_message, 
                              started_at, completed_at, target_range 
                       FROM scans WHERE id = ?""",
                    (scan_id,)
                ).fetchone()
                conn.close()
                
                if scan:
                    # Calcular tiempo transcurrido
                    started = datetime.fromisoformat(scan["started_at"]) if scan["started_at"] else None
                    elapsed = None
                    if started:
                        elapsed_seconds = (datetime.now() - started).total_seconds()
                        elapsed = f"{int(elapsed_seconds // 60)}m {int(elapsed_seconds % 60)}s"
                    
                    # Solo enviar si cambió algo
                    current_hosts = scan["hosts_discovered"] or 0
                    current_ports = scan["ports_found"] or 0
                    
                    if (scan["status"] != last_status or 
                        current_hosts != last_hosts or 
                        current_ports != last_ports):
                        
                        message = {
                            "type": "progress",
                            "status": scan["status"],
                            "hosts_discovered": current_hosts,
                            "ports_found": current_ports,
                            "error_message": scan["error_message"],
                            "elapsed_time": elapsed,
                            "target": scan["target_range"],
                            "timestamp": datetime.now().isoformat()
                        }
                        
                        try:
                            await manager.send_progress(scan_id, message)
                        except Exception:
                            # Conexión cerrada, salir del loop
                            break
                        last_status = scan["status"]
                        last_hosts = current_hosts
                        last_ports = current_ports
                    
                    # Si el escaneo terminó, enviar mensaje final y cerrar
                    if scan["status"] in ["completed", "failed"]:
                        final_message = {
                            "type": "completed" if scan["status"] == "completed" else "failed",
                            "status": scan["status"],
                            "hosts_discovered": current_hosts,
                            "ports_found": current_ports,
                            "error_message": scan["error_message"],
                            "message": "Escaneo completado exitosamente" if scan["status"] == "completed" else f"Escaneo falló: {scan['error_message'] or 'Error desconocido'}"
                        }
                        try:
                            await manager.send_progress(scan_id, final_message)
                            await asyncio.sleep(0.5)  # Dar tiempo para enviar el mensaje final
                        except Exception:
                            pass  # Conexión ya cerrada, continuar
                        break
                else:
                    # Escaneo no encontrado
                    try:
                        await manager.send_progress(scan_id, {
                            "type": "error",
                            "message": f"Escaneo {scan_id} no encontrado"
                        })
                    except Exception:
                        pass  # Conexión cerrada
                    break
                
                await asyncio.sleep(2)  # Actualizar cada 2 segundos
            except asyncio.CancelledError:
                break
            except Exception as e:
                # Error obteniendo progreso, enviar mensaje de error
                error_msg = {
                    "type": "error",
                    "message": f"Error obteniendo progreso: {str(e)}"
                }
                try:
                    await manager.send_progress(scan_id, error_msg)
                except:
                    pass
                await asyncio.sleep(2)
    except WebSocketDisconnect:
        pass  # Cliente desconectado normalmente
    except asyncio.CancelledError:
        pass  # Conexión cancelada (servidor cerrando)
    except Exception as e:
        print(f"Error en WebSocket para scan {scan_id}: {e}")
    finally:
        # Siempre limpiar la conexión
        manager.disconnect(scan_id)

@app.get("/api/scan/{scan_id}/results/live")
async def get_scan_results_live(scan_id: int):
    """Obtiene resultados parciales de un escaneo en progreso o completado."""
    conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Verificar que el escaneo existe y obtener status y error_message
    scan = cursor.execute("SELECT id, status, error_message FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not scan:
        conn.close()
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    
    query = """
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
            s.id as scan_id,
            sr.id as scan_result_id,
            sr.state,
            COALESCE(sr.discovery_method, 'unknown') as discovery_method
        FROM scan_results sr
        JOIN hosts h ON h.id = sr.host_id
        JOIN scans s ON s.id = sr.scan_id
        WHERE s.id = ?
        ORDER BY h.ip_address, COALESCE(sr.port, 0)
        LIMIT 5000
    """
    
    results = cursor.execute(query, (scan_id,)).fetchall()
    
    # Obtener el estado del escaneo para devolverlo también
    scan_status = scan['status']
    
    # Obtener información de enrichments (screenshots y source code) para cada resultado
    enriched_results = []
    for row in results:
        result_dict = dict(row)
        
        # Buscar screenshots y source code para este scan_result
        enrichments = cursor.execute("""
            SELECT enrichment_type, file_path
            FROM enrichments
            WHERE scan_result_id = ?
        """, (result_dict['scan_result_id'],)).fetchall()
        
        result_dict['has_screenshot'] = any(e['enrichment_type'] == 'Screenshot' for e in enrichments)
        result_dict['has_source_code'] = any(e['enrichment_type'] == 'Websource' for e in enrichments)
        
        enriched_results.append(result_dict)
    
    # Obtener estadísticas actualizadas
    stats = cursor.execute("""
        SELECT 
            COUNT(DISTINCT h.id) as hosts_count,
            COUNT(sr.id) as ports_count
        FROM scan_results sr
        JOIN hosts h ON h.id = sr.host_id
        WHERE sr.scan_id = ?
    """, (scan_id,)).fetchone()
    
    conn.close()
    
    # Obtener error_message si existe (sqlite3.Row no tiene .get())
    error_message = scan["error_message"] if scan["error_message"] else None
    
    return {
        "scan_id": scan_id,
        "status": scan["status"],
        "error_message": error_message,
        "results": enriched_results,
        "stats": {
            "hosts": stats["hosts_count"] if stats else 0,
            "ports": stats["ports_count"] if stats else 0
        }
    }

@app.get("/api/results")
async def get_results(
    organization: Optional[str] = None,
    location: Optional[str] = None,
    scan_id: Optional[int] = None
):
    """Obtiene resultados de escaneos con información de screenshots y source code."""
    conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    query = """
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
            s.id as scan_id,
            sr.id as scan_result_id,
            sr.state,
            COALESCE(sr.discovery_method, 'unknown') as discovery_method
        FROM scan_results sr
        JOIN hosts h ON h.id = sr.host_id
        JOIN scans s ON s.id = sr.scan_id
        WHERE 1=1
    """
    params = []
    
    if organization:
        query += " AND s.organization_name = ?"
        params.append(organization.upper())
    
    if location:
        query += " AND s.location = ?"
        params.append(location.upper())
    
    if scan_id:
        query += " AND s.id = ?"
        params.append(scan_id)
    
    query += " ORDER BY s.started_at DESC, h.ip_address, COALESCE(sr.port, 0) LIMIT 1000"
    
    results = cursor.execute(query, params).fetchall()
    
    # Obtener información de enrichments (screenshots y source code) para cada resultado
    enriched_results = []
    for row in results:
        result_dict = dict(row)
        
        # Buscar screenshots y source code para este scan_result
        enrichments = cursor.execute("""
            SELECT enrichment_type, file_path
            FROM enrichments
            WHERE scan_result_id = ?
        """, (result_dict['scan_result_id'],)).fetchall()
        
        result_dict['has_screenshot'] = any(e['enrichment_type'] == 'Screenshot' for e in enrichments)
        result_dict['has_source_code'] = any(e['enrichment_type'] == 'Websource' for e in enrichments)
        
        # Obtener rutas de archivos
        screenshot_path = next((e['file_path'] for e in enrichments if e['enrichment_type'] == 'Screenshot'), None)
        source_path = next((e['file_path'] for e in enrichments if e['enrichment_type'] == 'Websource'), None)
        
        result_dict['screenshot_path'] = screenshot_path
        result_dict['source_code_path'] = source_path
        
        enriched_results.append(result_dict)
    
    conn.close()
    
    return enriched_results

@app.delete("/api/scan/{scan_id}")
async def delete_scan(scan_id: int):
    """Elimina un escaneo y todos sus resultados."""
    try:
        success = storage.delete_scan(scan_id)
        if success:
            return {"status": "success", "message": f"Escaneo {scan_id} eliminado correctamente"}
        else:
            raise HTTPException(status_code=404, detail=f"Escaneo {scan_id} no encontrado")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error eliminando escaneo: {str(e)}")

@app.delete("/api/location")
async def delete_location(organization: str, location: str):
    """Elimina una ubicación y todos sus escaneos."""
    try:
        deleted_count = storage.delete_location(organization, location)
        return {
            "status": "success",
            "message": f"Ubicación '{location}' de '{organization}' eliminada correctamente",
            "deleted_count": deleted_count
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error eliminando ubicación: {str(e)}")

@app.delete("/api/organization/{organization}")
async def delete_organization(organization: str):
    """Elimina una organización completa y todos sus datos."""
    try:
        result = storage.delete_organization(organization)
        return {
            "status": "success",
            "message": f"Organización '{organization}' eliminada correctamente",
            **result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error eliminando organización: {str(e)}")

@app.get("/api/evidence/screenshot/{scan_id}/{ip}/{port}")
async def get_screenshot(scan_id: int, ip: str, port: int):
    """Sirve una captura de pantalla."""
    try:
        # Buscar el archivo de screenshot en la base de datos
        conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Obtener información del escaneo primero
        scan_info = cursor.execute("""
            SELECT organization_name, location FROM scans WHERE id = ?
        """, (scan_id,)).fetchone()
        
        if not scan_info:
            conn.close()
            raise HTTPException(status_code=404, detail="Escaneo no encontrado")
        
        # Obtener el scan_result_id
        scan_result = cursor.execute("""
            SELECT sr.id 
            FROM scan_results sr
            JOIN hosts h ON h.id = sr.host_id
            WHERE sr.scan_id = ? AND h.ip_address = ? AND sr.port = ?
        """, (scan_id, ip, port)).fetchone()
        
        if not scan_result:
            conn.close()
            raise HTTPException(status_code=404, detail="Resultado de escaneo no encontrado")
        
        # Buscar el screenshot
        screenshot = cursor.execute("""
            SELECT file_path
            FROM enrichments
            WHERE scan_result_id = ? AND enrichment_type = 'Screenshot'
        """, (scan_result['id'],)).fetchone()
        
        conn.close()
        
        if not screenshot or not screenshot['file_path']:
            raise HTTPException(status_code=404, detail="Screenshot no encontrado")
        
        # Construir la ruta del archivo
        file_path = Path(screenshot['file_path'])
        
        # Si es relativo, intentar desde el directorio actual
        if not file_path.is_absolute():
            # Intentar desde el directorio actual
            abs_path = Path.cwd() / file_path
            if not abs_path.exists():
                # Intentar desde el directorio del escaneo usando el nombre del archivo
                scan_dir = storage.get_scan_directory(
                    scan_info['organization_name'],
                    scan_info['location'],
                    scan_id
                )
                # El archivo debería estar en evidence/img/
                abs_path = scan_dir / "evidence" / "img" / file_path.name
                if not abs_path.exists():
                    # Intentar con la ruta completa relativa
                    abs_path = scan_dir / file_path
            file_path = abs_path
        
        if not file_path.exists():
            raise HTTPException(status_code=404, detail=f"Archivo de screenshot no existe: {file_path}")
        
        return FileResponse(
            path=str(file_path),
            media_type="image/png",
            filename=file_path.name
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error obteniendo screenshot: {str(e)}")

@app.get("/api/evidence/nmap/{scan_id}")
async def get_nmap_xml(scan_id: int):
    """Sirve el archivo XML de evidencia de Nmap para un escaneo."""
    try:
        # Obtener información del escaneo
        conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        scan = cursor.execute("""
            SELECT organization_name, location, scan_mode FROM scans WHERE id = ?
        """, (scan_id,)).fetchone()
        conn.close()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Escaneo no encontrado")
        
        # Verificar que el escaneo sea activo (tiene nmap) - acceso directo a sqlite3.Row
        scan_mode_val = scan['scan_mode'] if scan['scan_mode'] is not None else 'active'
        if scan_mode_val == 'passive':
            raise HTTPException(status_code=400, detail="Este escaneo es pasivo y no tiene archivo XML de Nmap")
        
        scan_dir = storage.get_scan_directory(
            scan['organization_name'], 
            scan['location'], 
            scan_id
        )
        
        nmap_xml_path = scan_dir / "evidence" / "nmap_scan.xml"
        
        if not nmap_xml_path.exists():
            raise HTTPException(status_code=404, detail="Archivo XML de Nmap no encontrado para este escaneo")
        
        # Leer y servir el archivo XML
        from fastapi.responses import FileResponse
        return FileResponse(
            path=str(nmap_xml_path),
            media_type="application/xml",
            filename=f"nmap_scan_{scan_id}.xml",
            headers={
                "Content-Disposition": f"attachment; filename=nmap_scan_{scan_id}.xml"
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error obteniendo XML de Nmap: {str(e)}")

@app.get("/api/evidence/nmap/{scan_id}/view")
async def view_nmap_xml(scan_id: int):
    """Sirve el archivo XML de Nmap para visualización (sin descarga forzada)."""
    try:
        # Obtener información del escaneo
        conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        scan = cursor.execute("""
            SELECT organization_name, location FROM scans WHERE id = ?
        """, (scan_id,)).fetchone()
        conn.close()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Escaneo no encontrado")
        
        scan_dir = storage.get_scan_directory(
            scan['organization_name'], 
            scan['location'], 
            scan_id
        )
        
        nmap_xml_path = scan_dir / "evidence" / "nmap_scan.xml"
        
        if not nmap_xml_path.exists():
            raise HTTPException(status_code=404, detail="Archivo XML de Nmap no encontrado")
        
        # Leer el contenido del XML
        with open(nmap_xml_path, 'r', encoding='utf-8') as f:
            xml_content = f.read()
        
        return JSONResponse(content={"xml": xml_content})
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error obteniendo XML de Nmap: {str(e)}")

@app.get("/api/evidence/source/{scan_id}/{ip}/{port}")
async def get_source_code(scan_id: int, ip: str, port: int):
    """Sirve el código fuente de un servicio web."""
    try:
        # Buscar el archivo de source code en la base de datos
        conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Obtener el scan_result_id
        scan_result = cursor.execute("""
            SELECT sr.id 
            FROM scan_results sr
            JOIN hosts h ON h.id = sr.host_id
            WHERE sr.scan_id = ? AND h.ip_address = ? AND sr.port = ?
        """, (scan_id, ip, port)).fetchone()
        
        if not scan_result:
            conn.close()
            raise HTTPException(status_code=404, detail="Resultado de escaneo no encontrado")
        
        # Obtener información del escaneo primero
        scan_info = cursor.execute("""
            SELECT organization_name, location FROM scans WHERE id = ?
        """, (scan_id,)).fetchone()
        
        if not scan_info:
            conn.close()
            raise HTTPException(status_code=404, detail="Escaneo no encontrado")
        
        # Buscar el source code
        source = cursor.execute("""
            SELECT file_path, data
            FROM enrichments
            WHERE scan_result_id = ? AND enrichment_type = 'Websource'
        """, (scan_result['id'],)).fetchone()
        
        conn.close()
        
        if not source:
            raise HTTPException(status_code=404, detail="Código fuente no encontrado")
        
        # Si hay archivo, servirlo
        if source['file_path']:
            file_path = Path(source['file_path'])
            
            # Si es relativo, intentar desde el directorio actual
            if not file_path.is_absolute():
                abs_path = Path.cwd() / file_path
                if not abs_path.exists():
                    scan_dir = storage.get_scan_directory(
                        scan_info['organization_name'],
                        scan_info['location'],
                        scan_id
                    )
                    # Intentar con el nombre del archivo en evidence/source/
                    abs_path = scan_dir / "evidence" / "source" / file_path.name
                    if not abs_path.exists():
                        # Intentar con la ruta completa relativa desde scan_dir
                        abs_path = scan_dir / file_path
                file_path = abs_path
            
            if file_path.exists():
                return FileResponse(
                    path=str(file_path),
                    media_type="text/plain",
                    filename=file_path.name
                )
        
        # Si no hay archivo pero hay data, devolver el contenido
        if source['data']:
            return JSONResponse(content={"content": source['data']})
        
        raise HTTPException(status_code=404, detail="Código fuente no disponible")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error obteniendo código fuente: {str(e)}")

@app.get("/api/scan/{scan_id}/screenshots")
async def get_scan_screenshots(scan_id: int):
    """Obtiene todas las capturas de pantalla de un escaneo."""
    conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    screenshots = cursor.execute("""
        SELECT DISTINCT h.ip_address, sr.port
        FROM enrichments e
        JOIN scan_results sr ON sr.id = e.scan_result_id
        JOIN hosts h ON h.id = sr.host_id
        WHERE sr.scan_id = ? AND e.enrichment_type = 'Screenshot'
        ORDER BY h.ip_address, sr.port
    """, (scan_id,)).fetchall()
    
    conn.close()
    return [dict(row) for row in screenshots]

@app.get("/api/scan/{scan_id}/sources")
async def get_scan_sources(scan_id: int):
    """Obtiene todos los códigos fuente de un escaneo."""
    conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    sources = cursor.execute("""
        SELECT DISTINCT h.ip_address, sr.port
        FROM enrichments e
        JOIN scan_results sr ON sr.id = e.scan_result_id
        JOIN hosts h ON h.id = sr.host_id
        WHERE sr.scan_id = ? AND e.enrichment_type = 'Websource'
        ORDER BY h.ip_address, sr.port
    """, (scan_id,)).fetchall()
    
    conn.close()
    return [dict(row) for row in sources]

@app.get("/api/scan/{scan_id}/vulnerabilities")
async def get_scan_vulnerabilities(scan_id: int):
    """Obtiene todas las vulnerabilidades de un escaneo."""
    conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    vulns = cursor.execute("""
        SELECT 
            v.vulnerability_id,
            v.vulnerability_name,
            v.severity,
            v.description,
            v.cve_id,
            v.cvss_score,
            h.ip_address,
            sr.port
        FROM vulnerabilities v
        JOIN scan_results sr ON sr.id = v.scan_result_id
        JOIN hosts h ON h.id = sr.host_id
        WHERE sr.scan_id = ?
        ORDER BY 
            CASE v.severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
                ELSE 5
            END,
            h.ip_address,
            sr.port
    """, (scan_id,)).fetchall()
    
    conn.close()
    return [dict(row) for row in vulns]

@app.post("/api/database/clear-all")
async def clear_all_database():
    """Elimina TODOS los datos de la base de datos. OPERACIÓN CRÍTICA."""
    try:
        result = storage.delete_all_data()
        return {
            "status": "success",
            "message": "Toda la base de datos ha sido limpiada correctamente",
            **result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error limpiando base de datos: {str(e)}")

@app.post("/api/database/cleanup-orphans")
async def cleanup_orphaned_data():
    """Limpia datos huérfanos de la base de datos."""
    try:
        result = storage.cleanup_orphaned_data()
        return {
            "status": "success",
            "message": "Datos huérfanos limpiados correctamente",
            **result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error limpiando datos huérfanos: {str(e)}")

@app.post("/api/export")
async def export_scans(
    organization: Optional[str] = None,
    location: Optional[str] = None,
    scan_id: Optional[int] = None
):
    """Exporta escaneos y resultados según los filtros proporcionados."""
    try:
        zip_path = export_data(storage, organization, location, scan_id)
        
        return FileResponse(
            path=str(zip_path),
            media_type="application/zip",
            filename=zip_path.name,
            headers={
                "Content-Disposition": f"attachment; filename={zip_path.name}"
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error exportando datos: {str(e)}")


@app.post("/api/import")
async def import_scans(file: UploadFile = File(...)):
    """Importa escaneos y resultados desde un archivo ZIP."""
    temp_path = None
    try:
        # Guardar archivo temporalmente
        temp_path = Path(f"/tmp/import_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip")
        with open(temp_path, 'wb') as f:
            content = await file.read()
            f.write(content)
        
        # Importar datos
        import_stats = import_data(storage, temp_path)
        
        # Eliminar archivo temporal
        if temp_path.exists():
            temp_path.unlink()
        
        return JSONResponse(content={
            "message": "Datos importados correctamente",
            "stats": import_stats
        })
    except Exception as e:
        if temp_path and temp_path.exists():
            temp_path.unlink()
        raise HTTPException(status_code=500, detail=f"Error importando datos: {str(e)}")


@app.post("/api/neo4j/export")
async def export_to_neo4j(config: Neo4jConfig):
    """Exporta resultados a Neo4j."""
    import subprocess
    import sys
    import os
    
    # Configurar variables de entorno para Scan2Neo
    env = os.environ.copy()
    env["NEO4J_USERNAME"] = config.username
    env["NEO4J_PASSWORD"] = config.password
    
    # Obtener la ruta absoluta de la base de datos
    db_path = str(storage.db_path)
    
    cmd = [sys.executable, "Scan2Neo.py", "-r", config.ip, "-d", db_path]
    
    if config.organization:
        cmd.extend(["-o", config.organization])
    if config.location:
        cmd.extend(["-s", config.location])
    
    try:
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=300,
            env=env
        )
        if result.returncode == 0:
            return {"status": "success", "message": result.stdout}
        else:
            return {"status": "error", "message": result.stderr or result.stdout}
    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "La exportación excedió el tiempo máximo (5 minutos)"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/api/neo4j/clear-all")
async def clear_neo4j_database(config: Neo4jConfig):
    """Elimina TODOS los datos de la base de datos Neo4j. OPERACIÓN CRÍTICA."""
    try:
        from py2neo import Graph
        
        # Conectar a Neo4j
        try:
            graph = Graph(f"bolt://{config.ip}:7687", auth=(config.username, config.password))
            # Verificar conexión
            graph.run("RETURN 1")
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Error conectando a Neo4j: {str(e)}")
        
        # Eliminar todos los nodos y relaciones
        try:
            # Primero eliminar todas las relaciones
            graph.run("MATCH ()-[r]->() DELETE r")
            # Luego eliminar todos los nodos
            graph.run("MATCH (n) DELETE n")
            
            # Verificar que se eliminó todo
            node_count = graph.run("MATCH (n) RETURN count(n) as count").evaluate()
            rel_count = graph.run("MATCH ()-[r]->() RETURN count(r) as count").evaluate()
            
            return {
                "status": "success",
                "message": f"Base de datos Neo4j limpiada correctamente. Nodos restantes: {node_count}, Relaciones restantes: {rel_count}",
                "nodes_deleted": True,
                "relationships_deleted": True
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error eliminando datos de Neo4j: {str(e)}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

class Neo4jQueryRequest(BaseModel):
    ip: str
    username: str
    password: str
    organization: Optional[str] = None

def get_neo4j_graph(ip: str, username: str, password: str):
    """Helper para obtener conexión a Neo4j."""
    from py2neo import Graph
    try:
        graph = Graph(f"bolt://{ip}:7687", auth=(username, password))
        graph.run("RETURN 1")  # Verificar conexión
        return graph
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error conectando a Neo4j: {str(e)}")

@app.post("/api/neo4j/connect")
async def test_neo4j_connection(config: Neo4jConfig):
    """Verifica la conexión a Neo4j."""
    try:
        from py2neo import Graph
        graph = Graph(f"bolt://{config.ip}:7687", auth=(config.username, config.password))
        # Intentar una consulta simple
        result = graph.run("RETURN 1 as test").data()
        return {
            "status": "success",
            "connected": True,
            "message": "Conexión exitosa a Neo4j"
        }
    except Exception as e:
        return {
            "status": "error",
            "connected": False,
            "message": f"Error de conexión: {str(e)}"
        }

@app.post("/api/neo4j/dashboard/organizations")
async def get_neo4j_organizations(request: Neo4jQueryRequest):
    """Obtiene lista de organizaciones desde Neo4j."""
    graph = get_neo4j_graph(request.ip, request.username, request.password)
    
    try:
        query = "MATCH (o:ORG) RETURN DISTINCT o.org as org ORDER BY o.org"
        result = graph.run(query).data()
        
        if not result:
            return []
        
        return [{"name": row.get("org", "")} for row in result if row.get("org")]
    except Exception as e:
        print(f"Error obteniendo organizaciones: {e}")
        return []

@app.post("/api/neo4j/dashboard/stats")
async def get_neo4j_dashboard_stats(request: Neo4jQueryRequest):
    """Obtiene estadísticas generales del dashboard."""
    graph = get_neo4j_graph(request.ip, request.username, request.password)
    
    # Construir queries con parámetros seguros
    params = {}
    if request.organization:
        params["org"] = request.organization
        org_filter = "WHERE o.org = $org"
        ip_filter = "WHERE ip.org = $org"
        port_filter = "WHERE p.org = $org"
        seg_filter = "WHERE s.org = $org"
    else:
        org_filter = ""
        ip_filter = ""
        port_filter = ""
        seg_filter = ""
    
    queries = {
        "organizations": f"MATCH (o:ORG) {org_filter} RETURN count(DISTINCT o.org) as count",
        "hosts": f"""
            MATCH (ip:IP) 
            {ip_filter}
            RETURN count(DISTINCT ip.IP) as count
        """,
        "ports": f"""
            MATCH (p:Port) 
            {port_filter}
            RETURN count(p) as count
        """,
        "vulnerabilities": f"""
            MATCH (p:Port) 
            {port_filter}
            WHERE p.Vuln IS NOT NULL AND p.Vuln <> ''
            RETURN count(p) as count
        """,
        "locations": f"""
            MATCH (s:SEG) 
            {seg_filter}
            RETURN count(DISTINCT s.SEG) as count
        """
    }
    
    stats = {}
    for key, query in queries.items():
        try:
            result = graph.run(query, parameters=params).data()
            stats[key] = result[0]["count"] if result else 0
        except Exception as e:
            print(f"Error ejecutando query para {key}: {e}")
            stats[key] = 0
    
    return stats

@app.post("/api/neo4j/dashboard/hosts-by-org")
async def get_neo4j_hosts_by_org(request: Neo4jQueryRequest):
    """Obtiene número de hosts por organización."""
    graph = get_neo4j_graph(request.ip, request.username, request.password)
    
    try:
        query = """
            MATCH (ip:IP)
            RETURN ip.org as org, count(DISTINCT ip.IP) as count
            ORDER BY count DESC
            LIMIT 20
        """
        
        result = graph.run(query).data()
        if not result:
            return []
        
        return [{"org": row.get("org", ""), "count": row.get("count", 0)} for row in result if row.get("org")]
    except Exception as e:
        print(f"Error en hosts-by-org: {e}")
        return []

@app.post("/api/neo4j/dashboard/top-ports")
async def get_neo4j_top_ports(request: Neo4jQueryRequest):
    """Obtiene los puertos más comunes."""
    graph = get_neo4j_graph(request.ip, request.username, request.password)
    
    params = {}
    if request.organization:
        params["org"] = request.organization
        org_filter = "WHERE p.org = $org"
    else:
        org_filter = ""
    
    query = f"""
        MATCH (p:Port)
        {org_filter}
        RETURN p.number as port, count(p) as count
        ORDER BY count DESC
        LIMIT 15
    """
    
    try:
        result = graph.run(query, parameters=params).data()
        if not result:
            return []
        return [{"port": str(row.get("port", "")), "count": row.get("count", 0)} for row in result if row.get("port") is not None]
    except Exception as e:
        print(f"Error en top-ports: {e}")
        return []

@app.post("/api/neo4j/dashboard/vulnerabilities-by-severity")
async def get_neo4j_vulnerabilities_by_severity(request: Neo4jQueryRequest):
    """Obtiene vulnerabilidades agrupadas por severidad."""
    graph = get_neo4j_graph(request.ip, request.username, request.password)
    
    params = {}
    if request.organization:
        params["org"] = request.organization
        org_condition = "p.org = $org AND"
    else:
        org_condition = ""
    
    query = f"""
        MATCH (p:Port)
        WHERE {org_condition} p.Vuln IS NOT NULL AND p.Vuln <> ''
        UNWIND split(p.Vuln, ',') as vuln
        WITH CASE 
            WHEN vuln CONTAINS 'CRITICAL' OR vuln CONTAINS 'Critical' THEN 'CRITICAL'
            WHEN vuln CONTAINS 'HIGH' OR vuln CONTAINS 'High' THEN 'HIGH'
            WHEN vuln CONTAINS 'MEDIUM' OR vuln CONTAINS 'Medium' THEN 'MEDIUM'
            WHEN vuln CONTAINS 'LOW' OR vuln CONTAINS 'Low' THEN 'LOW'
            ELSE 'UNKNOWN'
        END as severity
        RETURN severity, count(*) as count
        ORDER BY 
            CASE severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
                ELSE 5
            END
    """
    
    try:
        result = graph.run(query, parameters=params).data()
        if not result:
            return []
        return [{"severity": row.get("severity", "UNKNOWN"), "count": row.get("count", 0)} for row in result]
    except Exception as e:
        print(f"Error en vulnerabilities-by-severity: {e}")
        return []

@app.post("/api/neo4j/dashboard/services")
async def get_neo4j_top_services(request: Neo4jQueryRequest):
    """Obtiene los servicios más comunes."""
    graph = get_neo4j_graph(request.ip, request.username, request.password)
    
    params = {}
    if request.organization:
        params["org"] = request.organization
        org_condition = "p.org = $org AND"
    else:
        org_condition = ""
    
    query = f"""
        MATCH (p:Port)
        WHERE {org_condition} p.Name IS NOT NULL AND p.Name <> ''
        RETURN p.Name as service, count(p) as count
        ORDER BY count DESC
        LIMIT 15
    """
    
    try:
        result = graph.run(query, parameters=params).data()
        if not result:
            return []
        return [{"service": row.get("service", ""), "count": row.get("count", 0)} for row in result if row.get("service")]
    except Exception as e:
        print(f"Error en services: {e}")
        return []

@app.post("/api/neo4j/dashboard/network-graph")
async def get_neo4j_network_graph(request: Neo4jQueryRequest):
    """Obtiene datos del grafo de red para visualización."""
    graph = get_neo4j_graph(request.ip, request.username, request.password)
    
    params = {}
    if request.organization:
        params["org"] = request.organization
        org_where = "WHERE n.org = $org"
        rel_where = "WHERE a.org = $org AND b.org = $org"
    else:
        org_where = ""
        rel_where = ""
    
    # Obtener nodos
    nodes_query = f"""
        MATCH (n)
        {org_where}
        WITH labels(n) as labels, n, id(n) as node_id
        RETURN 
            node_id as id,
            labels[0] as label,
            CASE labels[0]
                WHEN 'ORG' THEN COALESCE(n.org, 'Unknown')
                WHEN 'SEG' THEN COALESCE(n.SEG, 'Unknown')
                WHEN 'Subred' THEN COALESCE(n.Subred, 'Unknown')
                WHEN 'IP' THEN COALESCE(n.IP, 'Unknown')
                WHEN 'Port' THEN COALESCE(toString(n.number), 'Unknown')
                ELSE 'Unknown'
            END as name,
            CASE labels[0]
                WHEN 'ORG' THEN '#00BFFF'
                WHEN 'SEG' THEN '#4ECDC4'
                WHEN 'Subred' THEN '#9B59B6'
                WHEN 'IP' THEN '#F38181'
                WHEN 'Port' THEN '#FFE66D'
                ELSE '#CCCCCC'
            END as color
        LIMIT 500
    """
    
    # Obtener relaciones
    rels_query = f"""
        MATCH (a)-[r]->(b)
        {rel_where}
        RETURN id(a) as from, id(b) as to, type(r) as type
        LIMIT 1000
    """
    
    try:
        nodes_result = graph.run(nodes_query, parameters=params).data()
        rels_result = graph.run(rels_query, parameters=params).data()
        
        nodes = [{"id": row["id"], "label": str(row["name"]) or "Unknown", "group": row["label"], "color": row["color"]} for row in nodes_result]
        edges = [{"from": row["from"], "to": row["to"], "label": row["type"]} for row in rels_result]
        
        return {"nodes": nodes, "edges": edges}
    except Exception as e:
        print(f"Error obteniendo grafo: {e}")
        raise HTTPException(status_code=500, detail=f"Error obteniendo grafo: {str(e)}")

class CypherQueryRequest(BaseModel):
    ip: str
    username: str
    password: str
    query: str

@app.post("/api/neo4j/dashboard/similar-devices")
async def get_similar_devices(request: Neo4jQueryRequest):
    """Agrupa IPs que probablemente sean activos similares basándose en puertos comunes y enriquecimientos similares."""
    graph = get_neo4j_graph(request.ip, request.username, request.password)
    
    params = {}
    if request.organization:
        params["org"] = request.organization
        org_where = "WHERE ip.org = $org"
    else:
        org_where = ""
    
    try:
        # Consulta mejorada para encontrar IPs con puertos similares
        # Primero, obtener todas las IPs con sus puertos y servicios (solo IPs que tienen puertos)
        query_base = f"""
            MATCH (ip:IP)-[:HAS_PORT]->(p:Port)
            {org_where}
            WHERE ip.IP IS NOT NULL AND ip.IP <> '' AND p.number IS NOT NULL
            WITH ip.IP as ip_addr, 
                 collect(DISTINCT p.number) as ports, 
                 collect(DISTINCT CASE WHEN p.Name IS NOT NULL AND p.Name <> '' THEN p.Name ELSE null END) as services
            WHERE size(ports) > 0
            WITH ip_addr, ports, [s IN services WHERE s IS NOT NULL] as clean_services
            RETURN ip_addr, ports, clean_services
        """
        
        ip_data = {}
        base_result = graph.run(query_base, parameters=params).data()
        for row in base_result:
            ip_addr = str(row.get('ip_addr', ''))
            if ip_addr:
                ip_data[ip_addr] = {
                    'ports': set(row.get('ports', [])),
                    'services': set(row.get('clean_services', []))
                }
        
        if len(ip_data) < 2:
            return []
        
        # Comparar todas las IPs entre sí
        similar_pairs = []
        ip_list = list(ip_data.keys())
        
        for i in range(len(ip_list)):
            for j in range(i + 1, len(ip_list)):
                ip1 = ip_list[i]
                ip2 = ip_list[j]
                
                ports1 = ip_data[ip1]['ports']
                ports2 = ip_data[ip2]['ports']
                services1 = ip_data[ip1]['services']
                services2 = ip_data[ip2]['services']
                
                common_ports = list(ports1 & ports2)
                common_services = list(services1 & services2)
                
                # Criterio de similitud: al menos 2 puertos comunes O (1 puerto común + 1 servicio común)
                if len(common_ports) >= 2 or (len(common_ports) >= 1 and len(common_services) >= 1):
                    similar_pairs.append({
                        'ip1': ip1,
                        'ip2': ip2,
                        'common_ports': common_ports,
                        'common_services': common_services,
                        'port_similarity': len(common_ports),
                        'service_similarity': len(common_services)
                    })
        
        if not similar_pairs:
            return []
        
        # Convertir similar_pairs a formato result para el algoritmo de agrupación
        result = similar_pairs
        
        # Agrupar resultados por grupos similares usando un enfoque mejorado
        ip_to_group = {}  # Mapeo de IP a grupo_id
        groups = {}
        group_id = 0
        
        for row in result:
            ip1 = str(row.get('ip1', ''))
            ip2 = str(row.get('ip2', ''))
            
            if not ip1 or not ip2:
                continue
            
            group1 = ip_to_group.get(ip1)
            group2 = ip_to_group.get(ip2)
            
            if group1 is None and group2 is None:
                # Crear nuevo grupo
                groups[group_id] = {
                    'ips': [ip1, ip2],
                    'common_ports': list(set(row.get('common_ports', []))),
                    'common_services': list(set(row.get('common_services', []))),
                    'similarity_score': row.get('port_similarity', 0) + row.get('service_similarity', 0)
                }
                ip_to_group[ip1] = group_id
                ip_to_group[ip2] = group_id
                group_id += 1
            elif group1 is not None and group2 is None:
                # Agregar ip2 al grupo de ip1
                if ip2 not in groups[group1]['ips']:
                    groups[group1]['ips'].append(ip2)
                ip_to_group[ip2] = group1
            elif group2 is not None and group1 is None:
                # Agregar ip1 al grupo de ip2
                if ip1 not in groups[group2]['ips']:
                    groups[group2]['ips'].append(ip1)
                ip_to_group[ip1] = group2
            elif group1 == group2:
                # Ya están en el mismo grupo, no hacer nada
                pass
            else:
                # Unir dos grupos existentes - mover todas las IPs del grupo2 al grupo1
                for ip in groups[group2]['ips']:
                    if ip not in groups[group1]['ips']:
                        groups[group1]['ips'].append(ip)
                    ip_to_group[ip] = group1
                # Eliminar grupo2
                del groups[group2]
        
        # Limpiar IPs duplicadas en cada grupo y recalcular puertos/servicios comunes del grupo completo
        for group_id, group in groups.items():
            group['ips'] = list(set(group['ips']))
            # Recalcular puertos y servicios comunes para todo el grupo (intersección de todos)
            if len(group['ips']) > 0:
                all_ports = None
                all_services = None
                for ip_addr in group['ips']:
                    if ip_addr in ip_data:
                        if all_ports is None:
                            all_ports = ip_data[ip_addr]['ports'].copy()
                            all_services = ip_data[ip_addr]['services'].copy()
                        else:
                            all_ports = all_ports & ip_data[ip_addr]['ports']
                            all_services = all_services & ip_data[ip_addr]['services']
                group['common_ports'] = sorted(list(all_ports)) if all_ports else []
                group['common_services'] = sorted(list(all_services)) if all_services else []
                group['similarity_score'] = len(all_ports) + len(all_services) if all_ports and all_services else 0
        
        # Convertir a lista para la respuesta
        grouped_results = []
        for gid, group in groups.items():
            if len(group['ips']) >= 2:  # Solo grupos con al menos 2 IPs
                grouped_results.append({
                    'group_id': gid,
                    'ips': group['ips'],
                    'ip_count': len(group['ips']),
                    'common_ports': group['common_ports'],
                    'common_services': group['common_services'],
                    'similarity_score': group['similarity_score']
                })
        
        # Ordenar por número de IPs y puntuación de similitud
        grouped_results.sort(key=lambda x: (x['ip_count'], x['similarity_score']), reverse=True)
        
        return grouped_results[:20]  # Top 20 grupos
        
    except Exception as e:
        print(f"Error en similar-devices: {e}")
        import traceback
        traceback.print_exc()
        return []

@app.post("/api/neo4j/dashboard/duplicate-ips")
async def get_duplicate_ips(request: Neo4jQueryRequest):
    """Encuentra IPs que aparecen en múltiples ubicaciones de la misma organización."""
    graph = get_neo4j_graph(request.ip, request.username, request.password)
    
    if request.organization:
        org_param = request.organization.replace("'", "\\'")
        org_where = f"WHERE ip.org = '{org_param}'"
    else:
        org_where = ""
    
    try:
        # Consulta mejorada para encontrar IPs duplicadas
        # Primero verificar que el filtro esté bien aplicado
        query = f"""
            MATCH (ip:IP)
            {org_where}
            WHERE ip.IP IS NOT NULL AND ip.IP <> '' AND ip.SEG IS NOT NULL AND ip.SEG <> ''
            WITH ip.IP as ip_address, ip.org as org, collect(DISTINCT ip.SEG) as locations
            WHERE size(locations) > 1
            WITH ip_address, org, [loc IN locations WHERE loc IS NOT NULL AND loc <> ''] as clean_locations
            WHERE size(clean_locations) > 1
            RETURN ip_address, org, clean_locations as locations, size(clean_locations) as location_count
            ORDER BY location_count DESC, ip_address
            LIMIT 50
        """
        
        result = graph.run(query).data()
        
        if not result:
            return []
        
        return [
            {
                'ip': str(row.get('ip_address', '')),
                'organization': str(row.get('org', '')),
                'locations': [str(loc) for loc in row.get('locations', []) if loc],
                'location_count': row.get('location_count', 0)
            }
            for row in result
            if row.get('ip_address') and row.get('location_count', 0) > 1
        ]
        
    except Exception as e:
        print(f"Error en duplicate-ips: {e}")
        import traceback
        traceback.print_exc()
        return []

@app.post("/api/neo4j/dashboard/execute-cypher")
async def execute_neo4j_cypher(request: CypherQueryRequest):
    """Ejecuta una consulta Cypher personalizada."""
    graph = get_neo4j_graph(request.ip, request.username, request.password)
    
    try:
        # Validar que la consulta no contenga operaciones peligrosas (solo READ)
        dangerous_keywords = ["DELETE", "DROP", "REMOVE", "DETACH", "SET", "CREATE", "MERGE"]
        query_upper = request.query.upper().strip()
        for keyword in dangerous_keywords:
            if keyword in query_upper:
                raise HTTPException(status_code=400, detail=f"Operación no permitida: {keyword}. Solo se permiten consultas de lectura (MATCH/RETURN).")
        
        # Solo permitir consultas que comiencen con MATCH
        if not query_upper.startswith("MATCH"):
            raise HTTPException(status_code=400, detail="Solo se permiten consultas que comiencen con MATCH")
        
        result = graph.run(request.query).data()
        return {"data": result, "count": len(result)}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error ejecutando consulta: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    import logging
    import socket
    
    # Configurar logging para reducir verbosidad
    # Solo mostrar errores y warnings, no cada petición HTTP
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    
    # Obtener la IP local para mostrar en el log
    host = "0.0.0.0"
    port = 8000
    
    # Intentar obtener la IP local
    try:
        # Conectar a un servidor externo para obtener la IP local
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = "127.0.0.1"
    
    # Mostrar información de acceso
    print("\n" + "="*60)
    print("🚀 Servidor iniciado correctamente")
    print("="*60)
    print(f"📡 Acceso local:    http://127.0.0.1:{port}")
    print(f"🌐 Acceso en red:   http://{local_ip}:{port}")
    print(f"🔗 Dashboard:       http://127.0.0.1:{port}/dashboard")
    print(f"🔗 Neo4j:           http://127.0.0.1:{port}/neo4j")
    print("="*60)
    print("Presiona Ctrl+C para detener el servidor\n")
    
    uvicorn.run(
        app, 
        host=host, 
        port=port,
        log_level="warning"  # Solo warnings y errores
    )

