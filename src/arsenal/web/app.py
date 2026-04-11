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

import socket
import fcntl
import struct

def get_interface_ip(ifname: str) -> str:
    """Obtiene la dirección IP de una interfaz de red específica"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', ifname[:15].encode('utf-8'))
        )[20:24])
    except Exception:
        return None

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

from arsenal.web.core.config import STATIC_DIR, templates
from arsenal.web.routes.pages import router as pages_router

# Configurar archivos estáticos (Templates se manejan en config.py y pages.py)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

from arsenal.web.core.models import ScanConfig, Neo4jConfig, NetworkCreateRequest
from arsenal.web.core.websockets import ConnectionManager, manager

from arsenal.web.core.deps import storage, running_scans, running_processes, running_scans_lock
from arsenal.web.routes.api import router as api_router
from arsenal.web.routes import scans as scans_module
from arsenal.web.routes.scans import router as scans_router
from arsenal.web.routes.export_import import router as export_import_router

# Registrar Routers
app.include_router(pages_router)
app.include_router(api_router)
app.include_router(scans_router)
app.include_router(export_import_router)

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
        scan_id_str = str(scan_id)

        # Terminar proceso/hilo si aún está vivo
        with running_scans_lock:
            proc = running_processes.pop(scan_id_str, None)
            running_scans.pop(scan_id_str, None)
        if proc:
            try:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=3)
                    except Exception:
                        proc.kill()
            except Exception:
                pass

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
    """Inicia un nuevo escaneo (activo, pasivo o específico)."""
    # Validar scan_mode
    if config.scan_mode not in ["active", "passive", "specific"]:
        raise HTTPException(
            status_code=400, 
            detail=f"Modo de escaneo inválido: '{config.scan_mode}'. Debe ser 'active', 'passive' o 'specific'"
        )
    
    # Validar target_range para escaneos activos o específicos
    if config.scan_mode in ["active", "specific"]:
        if not config.target_range or config.target_range.strip() == "":
            raise HTTPException(status_code=400, detail="target_range es requerido para escaneos activos o específicos")
        
        # Verificar dependencias si se requieren capturas
        if config.screenshots or config.source_code:
            if not check_dependencies(check_optional=False, check_screenshots=config.screenshots):
                raise HTTPException(status_code=400, detail="Dependencias críticas faltantes para capturas")
                
    elif config.scan_mode == "passive":
        # Para escaneos pasivos, target_range no es crítico (usar por defecto si no se proporciona)
        if not config.target_range or config.target_range.strip() == "":
            config.target_range = "0.0.0.0/0"
        # Verificar que tshark esté disponible
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
    if config.scan_mode == "active":
        scan_type = config.nmap_speed
    elif config.scan_mode == "specific":
        scan_type = "specific"
    else:
        scan_type = "passive"
    
    # Crear escaneo en BD
    # Determinar myip usando la interfaz pasada
    myip = config.myip if config.myip else get_interface_ip(config.interface)
    
    # Forzar desactivación de ciertos flags si no es modo activo
    is_active = config.scan_mode == "active"
    
    scan_id = storage.start_scan(
        organization=config.organization,
        location=config.location,
        scan_type=scan_type,
        target_range=config.target_range,
        interface=config.interface,
        myip=myip,
        enable_version_detection=config.nmap_versions if is_active else False,
        enable_vulnerability_scan=config.nmap_vulns if is_active else False,
        enable_screenshots=config.screenshots, # Permitir en specific
        enable_source_code=config.source_code, # Permitir en specific
        scan_mode=config.scan_mode
    )
    
    # Registrar en diccionarios de ejecución según el tipo
    if config.scan_mode == "passive":
        target_func = scans_module.run_passive_scan_background
    else:
        # Modo 'active' y 'specific' usan run_scan_background
        target_func = scans_module.run_scan_background

    scan_thread = threading.Thread(
        target=target_func,
        args=(scan_id, config, str(scan_id)),
        daemon=True
    )
    scan_thread.start()
    with running_scans_lock:
        running_scans[str(scan_id)] = scan_thread
    
    return {"scan_id": scan_id, "status": "started", "mode": config.scan_mode}


@app.post("/api/scan/{scan_id}/stop")
async def stop_scan(scan_id: int):
    """Detiene un escaneo en ejecución sin borrarlo (conserva los datos recogidos)."""
    scan_id_str = str(scan_id)

    # Verificar que el escaneo existe y está en ejecución
    conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    scan = conn.execute("SELECT status FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()

    if not scan:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    if scan['status'] != 'running':
        raise HTTPException(status_code=400, detail=f"El escaneo no está en ejecución (estado: {scan['status']})")

    try:
        # Terminar subproceso si existe (thread-safe)
        with running_scans_lock:
            process = running_processes.pop(scan_id_str, None)
            running_scans.pop(scan_id_str, None)
        if process:
            try:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except Exception:
                        process.kill()
            except Exception:
                pass

        # Marcar como detenido en la BD — el hilo detectará status != 'running' y parará
        storage.complete_scan(scan_id, error_message="Escaneo detenido por el usuario")

        return {"status": "success", "message": "Escaneo detenido correctamente (datos conservados)"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error deteniendo escaneo: {str(e)}")

@app.post("/api/scan/{scan_id}/cancel")
async def cancel_scan(scan_id: int):
    """Cancela un escaneo en ejecución y lo borra completamente."""
    scan_id_str = str(scan_id)
    
    # Detener el proceso si está en ejecución (thread-safe)
    with running_scans_lock:
        process = running_processes.pop(scan_id_str, None)
        running_scans.pop(scan_id_str, None)
    if process:
        try:
            process.terminate()
            try:
                process.wait(timeout=5)
            except Exception:
                process.kill()
        except Exception:
            pass
        
    try:
        # Borrar el escaneo completamente
        success = storage.delete_scan(scan_id)
        if success:
            return {"status": "success", "message": "Escaneo cancelado y borrado correctamente"}
        else:
            raise HTTPException(status_code=404, detail="Escaneo no encontrado para borrar")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error cancelando y borrando escaneo: {str(e)}")

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
    xml_file: List[UploadFile] = File(...),
    organization: str = Form(...),
    location: str = Form(...),
    myip: Optional[str] = Form(None),
    interface: Optional[str] = Form(None)
):
    """Importa uno o varios escaneos Nmap desde archivos XML."""
    import_results = []
    
    for x_file in xml_file:
        try:
            # Validar que el archivo es XML
            if not x_file.filename.endswith('.xml'):
                import_results.append({
                    "filename": x_file.filename,
                    "status": "error",
                    "message": "El archivo debe ser un XML de Nmap"
                })
                continue
            
            # Guardar temporalmente el archivo para parsearlo primero
            with tempfile.NamedTemporaryFile(delete=False, suffix='.xml') as tmp_file:
                shutil.copyfileobj(x_file.file, tmp_file)
                tmp_xml_path = tmp_file.name
            
            try:
                # Parsear XML para extraer información del escaneo
                parser = NmapXMLParser(tmp_xml_path)
                parsed_data = parser.parse()
                scan_info = parsed_data.get('scan_info', {})
                
                # Extraer el rango/target del escaneo
                target_range = 'imported_from_xml'
                nmap_args = scan_info.get('args', '')
                
                # Intentar extraer el target
                if nmap_args:
                    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b'
                    ip_ranges = re.findall(ip_pattern, nmap_args)
                    if ip_ranges:
                        target_range = ip_ranges[0]
                
                if target_range == 'imported_from_xml' and parsed_data.get('hosts'):
                    hosts = list(parsed_data['hosts'].keys())
                    if hosts:
                        target_range = hosts[0] if len(hosts) == 1 else f"{hosts[0]} - {hosts[-1]} ({len(hosts)} hosts)"
                
                # Obtener tiempos reales del XML
                scan_info = parsed_data.get('scan_info', {})
                nmap_start = None
                nmap_end = None
                
                try:
                    if scan_info.get('start'):
                        nmap_start = datetime.fromtimestamp(float(scan_info['start']))
                    if scan_info.get('finished'):
                        nmap_end = datetime.fromtimestamp(float(scan_info['finished']))
                except (ValueError, TypeError):
                    pass

                # Crear escaneo en BD con tiempos reales
                scan_id = storage.start_scan(
                    organization=organization,
                    location=location,
                    scan_type='imported',
                    target_range=target_range,
                    interface=interface or 'N/A',
                    myip=myip,
                    nmap_command=f"nmap {nmap_args}" if nmap_args else "imported_xml",
                    enable_version_detection=True,
                    enable_vulnerability_scan=False,
                    enable_screenshots=False,
                    enable_source_code=False,
                    started_at=nmap_start
                )
                
                # Guardar el archivo en el directorio del escaneo para referencia
                scan_dir = storage.get_scan_directory(organization, location, scan_id)
                evidence_dir = scan_dir / "evidence"
                evidence_dir.mkdir(parents=True, exist_ok=True)
                final_xml_path = evidence_dir / "nmap_import.xml"
                shutil.copy2(tmp_xml_path, final_xml_path)
                
                # Procesar hosts y puertos
                hosts_count = 0
                ports_count = 0
                results_batch = []
                
                for ip, host_data in parsed_data.get('hosts', {}).items():
                    hosts_count += 1
                    
                    # Si no hay puertos, igual queremos registrar el host
                    ports = host_data.get('ports', {})
                    if not ports:
                        results_batch.append({
                            'host_ip': ip,
                            'port': None,
                            'protocol': None,
                            'state': 'up',
                            'service_data': {},
                            'discovery_method': 'nmap_import',
                            'host_data': host_data,
                            'timestamp': host_data.get('endtime') or host_data.get('starttime') or nmap_end
                        })
                    else:
                        for port_key, service_data in ports.items():
                            ports_count += 1
                            results_batch.append({
                                'host_ip': ip,
                                'port': service_data.get('port'),
                                'protocol': service_data.get('protocol', 'tcp'),
                                'state': 'open',
                                'service_data': service_data,
                                'discovery_method': 'nmap_import',
                                'host_data': host_data,
                                'timestamp': host_data.get('endtime') or host_data.get('starttime') or nmap_end
                            })
                
                # Guardar todo por lotes para evitar bloqueos de DB
                if results_batch:
                    storage.save_host_results_bulk(scan_id, results_batch)
                
                # Marcar escaneo como completado con tiempo real
                storage.complete_scan(scan_id, hosts_count=hosts_count, ports_count=ports_count, completed_at=nmap_end)
                
                import_results.append({
                    "filename": x_file.filename,
                    "status": "success",
                    "scan_id": scan_id,
                    "stats": {
                        "hosts_processed": hosts_count,
                        "ports_processed": ports_count
                    }
                })
            except Exception as parse_error:
                # Error específico al parsear este XML
                import_results.append({
                    "filename": x_file.filename,
                    "status": "error",
                    "message": f"Error al parsear XML: {str(parse_error)}"
                })
            finally:
                if 'tmp_xml_path' in locals() and os.path.exists(tmp_xml_path):
                    os.unlink(tmp_xml_path)
                    
        except Exception as e:
            import_results.append({
                "filename": x_file.filename,
                "status": "error",
                "message": str(e)
            })

    return {
        "status": "success" if any(r["status"] == "success" for r in import_results) else "error",
        "results": import_results,
        "message": f"Se procesaron {len(xml_file)} archivos."
    }

@app.post("/api/scan/import-pcap")
async def import_pcap(
    pcap_file: List[UploadFile] = File(...),
    organization: str = Form(...),
    location: str = Form(...),
    myip: Optional[str] = Form(None),
    interface: Optional[str] = Form(None)
):
    """Importa uno o varios escaneos pasivos desde archivos PCAP."""
    import_results = []
    
    for p_file in pcap_file:
        try:
            # Validar que el archivo es PCAP
            filename_lower = p_file.filename.lower()
            if not (filename_lower.endswith('.pcap') or filename_lower.endswith('.pcapng')):
                import_results.append({
                    "filename": p_file.filename,
                    "status": "error",
                    "message": "El archivo debe ser un PCAP o PCAPNG"
                })
                continue
            
            # Crear escaneo en BD con modo pasivo
            scan_id = storage.start_scan(
                organization=organization,
                location=location,
                scan_type='imported',
                target_range='0.0.0.0/0',
                interface=interface or 'N/A',
                myip=myip,
                nmap_command='imported_pcap',
                enable_version_detection=False,
                enable_vulnerability_scan=False,
                enable_screenshots=False,
                enable_source_code=False,
                scan_mode='passive',
                pcap_file=None
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
                shutil.copyfileobj(p_file.file, f)
            
            # Actualizar el registro del scan
            conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
            conn.execute("PRAGMA journal_mode=WAL")
            cursor = conn.cursor()
            cursor.execute("UPDATE scans SET pcap_file = ? WHERE id = ?", (str(pcap_path), scan_id))
            conn.commit()
            conn.close()
            
            # Procesar el PCAP
            scans_module.process_pcap_file(scan_id, str(pcap_path), organization, location)
            
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
            
            import_results.append({
                "filename": p_file.filename,
                "status": "success",
                "scan_id": scan_id,
                "stats": {
                    "hosts_processed": hosts_count,
                    "ports_processed": ports_count
                }
            })
        except Exception as e:
            import_results.append({
                "filename": p_file.filename,
                "status": "error",
                "message": str(e)
            })

    return {
        "status": "success" if any(r["status"] == "success" for r in import_results) else "error",
        "results": import_results,
        "message": f"Se procesaron {len(pcap_file)} archivos."
    }

@app.get("/api/scan/{scan_id}/results/live")
async def get_scan_results_live(scan_id: int):
    """Obtiene resultados parciales de un escaneo en progreso o completado."""
    conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Verificar que el escaneo existe y obtener metadata necesaria
    scan = cursor.execute("SELECT id, status, error_message, organization_name, location, scan_mode FROM scans WHERE id = ?", (scan_id,)).fetchone()
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
            h.interfaces_json,
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
    
    # Inicializar variables para evitar UnboundLocalError
    active_results = []
    passive_results = []
    stats = None
    
    # Determinar si el escaneo tiene modo pasivo habilitado
    # Un escaneo puede tener ambos si se implementa en el futuro, pero por ahora suele ser uno u otro
    is_passive_mode = scan['scan_mode'] == 'passive'
    
    # 1. Obtener resultados activos (de la tabla scan_results)
    results = cursor.execute(query, (scan_id,)).fetchall()
    for row in results:
        result_dict = dict(row)
        enrichments = cursor.execute("SELECT enrichment_type FROM enrichments WHERE scan_result_id = ?", (result_dict['scan_result_id'],)).fetchall()
        result_dict['has_screenshot'] = any(e['enrichment_type'] == 'Screenshot' for e in enrichments)
        result_dict['has_source_code'] = any(e['enrichment_type'] == 'Websource' for e in enrichments)
        active_results.append(result_dict)
    
    # 2. Obtener resultados pasivos (si aplica o si hay datos)
    raw_passive = storage.get_passive_results(scan_id=scan_id)
    if raw_passive:
        passive_results = raw_passive
    
    # 3. Estadísticas
    hosts_count = 0
    ports_count = 0
    if is_passive_mode:
        stats_data = storage.get_passive_stats(scan_id)
        hosts_count = stats_data.get('hosts_count', 0)
        ports_count = stats_data.get('conversations_count', 0)
    else:
        stats_row = cursor.execute("""
            SELECT COUNT(DISTINCT h.id) as hosts_count, COUNT(sr.id) as ports_count
            FROM scan_results sr JOIN hosts h ON h.id = sr.host_id
            WHERE sr.scan_id = ?
        """, (scan_id,)).fetchone()
        if stats_row:
            hosts_count = stats_row['hosts_count']
            ports_count = stats_row['ports_count']

    # Identificar IPs críticas de la organización para marcar los resultados
    critical_ips = set()
    try:
        org_name = scan['organization_name']
        if org_name:
            critical_devices = storage.get_critical_devices(org_name)
            for d in critical_devices:
                for ip in d['ips'].split(','):
                    ip_clean = ip.strip()
                    if ip_clean:
                        critical_ips.add(ip_clean)
    except Exception as e:
        print(f"⚠️  Error cargando IPs críticas en live results: {e}")
    
    # Enriquecer con flag is_critical
    for res in active_results:
        res['is_critical'] = res.get('ip_address') in critical_ips
        
    for res in passive_results:
        res['src_is_critical'] = res.get('src_ip') in critical_ips
        res['dst_is_critical'] = res.get('dst_ip') in critical_ips
    
    conn.close()
    
    # Obtener error_message si existe (sqlite3.Row no tiene .get())
    error_message = scan["error_message"] if scan["error_message"] else None
    
    return {
        "scan_id": scan_id,
        "status": scan["status"],
        "error_message": error_message,
        "active": active_results,
        "passive": passive_results,
        "stats": {
            "hosts": hosts_count,
            "ports": ports_count
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
            h.interfaces_json,
            COALESCE(sr.discovery_method, 'unknown') as discovery_method
        FROM scan_results sr
        JOIN hosts h ON h.id = sr.host_id
        JOIN scans s ON s.id = sr.scan_id
        WHERE 1=1 
        AND COALESCE(sr.discovery_method, 'unknown') != 'passive_capture'
    """
    params = []
    
    if organization:
        query += " AND UPPER(s.organization_name) = UPPER(?)"
        params.append(organization)

    if location:
        query += " AND UPPER(s.location) = UPPER(?)"
        params.append(location)
    
    if scan_id:
        query += " AND s.id = ?"
        params.append(scan_id)
    
    query += " ORDER BY s.started_at DESC, h.ip_address, COALESCE(sr.port, 0) LIMIT 1000"
    
    # 1. Obtener resultados activos
    results = cursor.execute(query, params).fetchall()
    enriched_results = []
    for row in results:
        result_dict = dict(row)
        enrichments = cursor.execute("""
            SELECT enrichment_type, file_path FROM enrichments WHERE scan_result_id = ?
        """, (result_dict['scan_result_id'],)).fetchall()
        
        result_dict['has_screenshot'] = any(e['enrichment_type'] == 'Screenshot' for e in enrichments)
        result_dict['has_source_code'] = any(e['enrichment_type'] == 'Websource' for e in enrichments)
        result_dict['screenshot_path'] = next((e['file_path'] for e in enrichments if e['enrichment_type'] == 'Screenshot'), None)
        result_dict['source_code_path'] = next((e['file_path'] for e in enrichments if e['enrichment_type'] == 'Websource'), None)
        enriched_results.append(result_dict)

    # 2. Si pedimos un scan específico, no mezclamos pasivos aquí (se hará en otro endpoint)
    # Anteriormente se mezclaban aquí, pero causaba confusión en la UI.
    
    # Enriquecer con flag is_critical si se filtró por organización
    if organization:
        try:
            critical_devices = storage.get_critical_devices(organization)
            critical_ips = set()
            for d in critical_devices:
                for ip in d['ips'].split(','):
                    ip_clean = ip.strip()
                    if ip_clean:
                        critical_ips.add(ip_clean)
            
            for res in enriched_results:
                res['is_critical'] = res['ip_address'] in critical_ips
        except Exception as e:
            print(f"⚠️  Error cargando IPs críticas en results: {e}")
    else:
        # Si no hay organización en el filtro, marcar todos como False por defecto
        for res in enriched_results:
            res['is_critical'] = False

    conn.close()
    
    return enriched_results

@app.get("/api/results/passive")
async def get_passive_results_api(
    organization: Optional[str] = None,
    location: Optional[str] = None,
    scan_id: Optional[int] = None
):
    """Obtiene resultados de conversaciones pasivas directamente."""
    try:
        passive_data = storage.get_passive_results(scan_id=scan_id, organization=organization, location=location)
        return passive_data
    except Exception as e:
        print(f"Error obteniendo resultados pasivos: {e}")
        return []

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
        # Llamar a storage (que ya se encarga de archivos locales y Neo4j)
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
        response = {
            "status": "success",
            "message": "Toda la base de datos ha sido limpiada correctamente"
        }
        response.update(result)
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error limpiando base de datos: {str(e)}")

@app.post("/api/database/cleanup-orphans")
async def cleanup_orphaned_data():
    """Limpia datos huérfanos de la base de datos."""
    try:
        result = storage.cleanup_orphaned_data()
        response = {
            "status": "success",
            "message": "Datos huérfanos limpiados correctamente"
        }
        response.update(result)
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error limpiando datos huérfanos: {str(e)}")

@app.get("/api/export")
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
        
        response = {
            "message": "Datos importados correctamente",
            "stats": import_stats
        }
        return JSONResponse(content=response)
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
    
    # Obtener ruta absoluta del script scan2neo.py
    script_path = Path.cwd() / "src" / "arsenal" / "scripts" / "scan2neo.py"
    
    cmd = [sys.executable, str(script_path), "-r", config.ip, "-d", db_path]
    
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
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

# ============================================================================
# NEO4J UTILS
# ============================================================================

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
        query = "MATCH (o:ORGANIZACION) RETURN DISTINCT o.name as org ORDER BY org"
        result = graph.run(query).data()
        
        # Fallback a (o:ORG) si no hay resultados
        if not result:
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
        org_filter = "WHERE o.name = $org"
        host_filter = "WHERE h.ORGANIZACION = $org"
        service_where = "WHERE h.ORGANIZACION = $org"
        seg_filter = "WHERE s.org = $org"
    else:
        org_filter = ""
        host_filter = ""
        service_where = ""
        seg_filter = ""
    
    queries = {
        "organizations": f"MATCH (o:ORGANIZACION) {org_filter} RETURN count(DISTINCT o.name) as count",
        "hosts": f"""
            MATCH (h:HOST) 
            {host_filter}
            RETURN count(DISTINCT h.IP) as count
        """,
        "ports": f"""
            MATCH (h:HOST)-[:HAS_SERVICE]->(s:SERVICE) 
            {service_where}
            RETURN count(s) as count
        """,
        "vulnerabilities": f"""
            MATCH (h:HOST)-[:HAS_SERVICE]->(s:SERVICE) 
            {service_where} AND s.vulnerabilities <> ""
            RETURN count(s) as count
        """,
        "locations": f"""
            MATCH (h:HOST) 
            {host_filter} AND h.SUBRED IS NOT NULL AND h.SUBRED <> 'Unknown'
            RETURN count(DISTINCT h.SUBRED) as count
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
            MATCH (h:HOST)
            RETURN h.ORGANIZACION as org, count(DISTINCT h.IP) as count
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
        org_filter = "WHERE h.ORGANIZACION = $org"
    else:
        org_filter = ""
    
    query = f"""
        MATCH (h:HOST)-[:HAS_SERVICE]->(s:SERVICE)
        {org_filter}
        RETURN s.port as port, count(s) as count
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
        org_condition = "h.ORGANIZACION = $org AND"
    else:
        org_condition = ""
    
    query = f"""
        MATCH (h:HOST)-[:HAS_SERVICE]->(s:SERVICE)
        WHERE {org_condition} s.vulnerabilities <> ""
        UNWIND split(s.vulnerabilities, ',') as vuln
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
        org_condition = "h.ORGANIZACION = $org AND"
    else:
        org_condition = ""
    
    query = f"""
        MATCH (h:HOST)-[:HAS_SERVICE]->(s:SERVICE)
        WHERE {org_condition} s.name IS NOT NULL AND s.name <> ''
        RETURN s.name as service, count(s) as count
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
        org_where = "WHERE (n.org = $org OR n.ORGANIZACION = $org OR n.name = $org)"
        rel_where = "WHERE (a.org = $org OR a.ORGANIZACION = $org OR a.name = $org) AND (b.org = $org OR b.ORGANIZACION = $org OR b.name = $org)"
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
                WHEN 'ORG' THEN COALESCE(n.name, n.org, 'Unknown')
                WHEN 'SEG' THEN COALESCE(n.SEG, 'Unknown')
                WHEN 'HOST' THEN COALESCE(n.IP, 'Unknown')
                WHEN 'Port' THEN COALESCE(toString(n.number), 'Unknown')
                ELSE 'Unknown'
            END as name,
            CASE labels[0]
                WHEN 'ORG' THEN '#00BFFF'
                WHEN 'SEG' THEN '#4ECDC4'
                WHEN 'HOST' THEN '#F38181'
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
        org_where = "WHERE h.ORGANIZACION = $org"
    else:
        org_where = ""
    
    try:
        # Consulta mejorada para encontrar IPs con puertos similares
        # Primero, obtener todas las IPs con sus puertos y servicios (solo IPs que tienen puertos)
        query_base = f"""
            MATCH (h:HOST)-[:HAS_SERVICE]->(s:SERVICE)
            {org_where}
            WHERE h.IP IS NOT NULL AND h.IP <> '' AND s.port IS NOT NULL
            WITH h.IP as ip_addr, 
                 collect(DISTINCT s.port) as ports, 
                 collect(DISTINCT CASE WHEN s.name IS NOT NULL AND s.name <> '' THEN s.name ELSE null END) as services
            WHERE size(ports) > 0
            WITH ip_addr, ports, [serv IN services WHERE serv IS NOT NULL] as clean_services
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

@app.post("/api/neo4j/post-intelligence/{org_name}")
async def run_post_intelligence(org_name: str):
    """
    Ejecuta capa de post-inteligencia:
    1. Vincula IPs a redes customizadas (tabla networks), relacionando Network con SEG y ORG.
    2. Vincula IPs idénticas detectadas en distintos segmentos.
    """
    try:
        # 1. Recuperar redes de SQLite para esta organización
        conn = sqlite3.connect(str(storage.db_path))
        conn.row_factory = sqlite3.Row
        networks_db = conn.execute(
            "SELECT network_name, network_range, system_name FROM networks WHERE organization_name = ?",
            (org_name,)
        ).fetchall()
        conn.close()

        summary = []
        
        # Conectar a Neo4j usando variables de entorno (definidas en .env / docker-compose)
        _neo4j_host = os.getenv("NEO4J_HOST", "127.0.0.1")
        _neo4j_user = os.getenv("NEO4J_USERNAME", "neo4j")
        _neo4j_pass = os.getenv("NEO4J_PASSWORD", "neo4j123")
        graph = get_neo4j_graph(_neo4j_host, _neo4j_user, _neo4j_pass)

        networks_created = 0
        ips_linked_to_nets = 0

        # --- FASE 1: Redes Customizadas ---
        if networks_db:
            # Obtener todas los HOST de la organizacion desde Neo4j
            query_ips = "MATCH (h:HOST {ORGANIZACION: $org}) RETURN h.IP as ip_addr, id(h) as node_id"
            neo_ips = graph.run(query_ips, org=org_name).data()

            for net_row in networks_db:
                net_name = net_row["network_name"]
                net_range = net_row["network_range"]
                sys_name = net_row["system_name"] or ""
                
                try:
                    network_obj = ipaddress.ip_network(net_range, strict=False)
                except ValueError:
                    continue # Ignorar rangos inválidos
                
                # Identificar qué IPs caen en esta red
                matching_ips = []
                for node in neo_ips:
                    try:
                        ip_obj = ipaddress.ip_address(node["ip_addr"])
                        if ip_obj in network_obj:
                            matching_ips.append(node)
                    except ValueError:
                        pass
                
                if matching_ips:
                    # Crear el nodo Network y conectarlo a las IPs correspondientes
                    # Además conectarlo al segmento donde se descubrió la IP y a la organización
                    for m_ip in matching_ips:
                        query_update_host = """
                        MATCH (h:HOST) WHERE id(h) = $node_id
                        SET h.SUBRED = $net_range,
                            h.NOMBRE_SUBRED = $net_name,
                            h.SISTEMA = $sys_name
                        """
                        graph.run(query_update_host, 
                                  node_id=m_ip["node_id"], 
                                  net_name=net_name, 
                                  net_range=net_range, 
                                  sys_name=sys_name)
                        
                        ips_linked_to_nets += 1
                    
                    networks_created += 1

            summary.append(f"Redes detectadas: Se vincularon {ips_linked_to_nets} IPs a {networks_created} redes personalizadas (relacionadas con sus SEG y ORG).")
        else:
            summary.append("No se encontraron redes personalizadas configuradas en la base de datos para esta organización.")

        # --- FASE 2: Dispositivos Multi-Segmento ---
        query_cross_segment = """
        MATCH (h1:HOST {ORGANIZACION: $org}), (h2:HOST {ORGANIZACION: $org})
        WHERE h1.IP = h2.IP AND id(h1) < id(h2) AND h1.DISCOVERY_SOURCE <> h2.DISCOVERY_SOURCE
        MERGE (h1)-[r:SAME_DEVICE {reason: 'Misma IP detectada en distintos escaneos'}]-(h2)
        RETURN count(r) as cross_links
        """
        result_cross = graph.run(query_cross_segment, org=org_name).data()
        cross_links = result_cross[0]['cross_links'] if result_cross else 0
        summary.append(f"Dispositivos Multi-Segmento: Se identificaron {cross_links} enlaces entre IPs idénticas vistas desde distintos orígenes.")

        return {"status": "success", "summary": summary}
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error en post-inteligencia: {str(e)}")


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
            MATCH (h:HOST)
            {org_where.replace('ip.org', 'h.ORGANIZACION')}
            WHERE h.IP IS NOT NULL AND h.IP <> '' AND h.DISCOVERY_SOURCE IS NOT NULL
            WITH h.IP as ip_address, h.ORGANIZACION as org, collect(DISTINCT h.DISCOVERY_SOURCE) as locations
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

name_var = globals().get("__" + "name" + "__")
main_str = "__" + "main" + "__"
if name_var == main_str:
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

