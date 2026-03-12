import sqlite3
import threading
import subprocess
import os
import shutil
import ipaddress
import shlex
import json
import time
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict
from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse

from arsenal.core.scanners import (
    HostDiscovery,
    PortScanner,
    PassiveCapture,
    ServiceDetection,
    IOXIDResolverScanner
)
from arsenal.web.core.models import ScanConfig
from arsenal.web.core.deps import storage, running_scans, running_processes
from arsenal.web.core.websockets import manager
from arsenal.core.parsers.nmap_parser import NmapXMLParser
from arsenal.core.parsers.vulnerability_parser import VulnerabilityParser

router = APIRouter()

# Añadir get_interface_ip from core if needed
from arsenal.scripts.check_env import check_dependencies

# helper definition (was top of app.py)
import socket
import fcntl
import struct
def get_interface_ip(ifname: str) -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(), 0x8915, struct.pack('256s', ifname[:15].encode('utf-8'))
        )[20:24])
    except Exception:
        return None

@router.get("/api/scans/list")
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

@router.get("/api/scans")
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

def run_scan_background(scan_id: int, config: ScanConfig, ws_id: str):
    """Ejecuta el escaneo en background usando scanners directamente."""
    try:
        # Importar módulos de screenshots/source code si están disponibles
        try:
            from arsenal.core.protocols.web import take_screenshot, get_source
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
        

        def is_scan_cancelled():
            """Comprueba si el escaneo ha sido cancelado en la base de datos."""
            try:
                conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
                cursor = conn.cursor()
                status = cursor.execute("SELECT status FROM scans WHERE id = ?", (scan_id,)).fetchone()[0]
                conn.close()
                return status != 'running'
            except:
                return False

        def register_process(proc):
            """Registra un subproceso para poder cancelarlo desde la API."""
            if proc:
                running_processes[str(scan_id)] = proc

        discovered_ips = set()

        
        # ============================================================================
        # PASO 1: HOST DISCOVERY (si está habilitado)
        # ============================================================================
        if config.host_discovery:
            print(f"[Scan {scan_id}] 🔍 Iniciando descubrimiento de hosts...")
            try:
                # Validar comando personalizado
                custom_cmd = config.custom_host_discovery_command
                placeholder = "El comando aparecerá aquí"
                
                if custom_cmd and custom_cmd.strip() and placeholder not in custom_cmd:
                    print(f"[Scan {scan_id}] 📡 Fase 1: Ejecutando comando personalizado: {custom_cmd}")
                    # Execute custom command
                    cmd_args = shlex.split(custom_cmd)
                    
                    # Usar Popen para registrar el proceso antes de que bloquee
                    process = subprocess.Popen(
                        cmd_args,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    register_process(process)
                    stdout, stderr = process.communicate()
                    
                    # Extract IPs using HostDiscovery utility
                    host_discovery = HostDiscovery(interface=config.interface)
                    if process.returncode == 0 or stdout:
                        discovered_ips = host_discovery.extract_ips_from_output(stdout)
                    
                    if process.returncode != 0 and not discovered_ips:
                        print(f"[Scan {scan_id}] ⚠️ El comando de descubrimiento devolvió error y no se encontraron IPs")
                else:
                    host_discovery = HostDiscovery(interface=config.interface)
                    discovered_ips = host_discovery.discover_hosts(
                        config.target_range, 
                        process_callback=register_process,
                        is_cancelled_callback=is_scan_cancelled
                    )
                
                if is_scan_cancelled():
                    print(f"[Scan {scan_id}] 🛑 Escaneo cancelado durante descubrimiento")
                    return
                
                print(f"[Scan {scan_id}] ✅ Descubiertos {len(discovered_ips)} hosts")
                
                # Guardar hosts descubiertos en la BD
                for host_ip in discovered_ips:
                    if is_scan_cancelled(): return
                    try:
                        storage.save_discovered_host(
                            scan_id=scan_id,
                            host_ip=host_ip,
                            discovery_method='host_discovery'
                        )
                    except Exception as e:
                        print(f"[Scan {scan_id}] ⚠️  Error guardando host {host_ip}: {e}")
            except Exception as e:
                print(f"[Scan {scan_id}] ⚠️  Error en host discovery: {e}")
                import traceback
                traceback.print_exc()
        
        # ============================================================================
        # PASO 2: NMAP PING DISCOVERY (FASE 2)
        # ============================================================================
        if config.nmap_icmp:
            print(f"[Scan {scan_id}] 📍 Iniciando Fase 2: Ping Scan...")
            
            # Determinar targets: usar IPs de la Fase 1 si hay, sino el rango
            current_targets = sorted(list(discovered_ips)) if discovered_ips else [config.target_range]
            target_str = ' '.join(current_targets)
            
            try:
                # Archivo temporal para resultados de Ping
                ping_xml_path = evidence_dir / "ping_scan.xml"
                
                # Validar comando personalizado
                custom_cmd = config.custom_ping_command
                placeholder = "El comando aparecerá aquí"
                
                if custom_cmd and custom_cmd.strip() and placeholder not in custom_cmd:
                    print(f"[Scan {scan_id}] 📡 Fase 2: Ejecutando comando personalizado: {custom_cmd}")
                    cmd_str = custom_cmd
                    if '-oX' not in cmd_str:
                        cmd_str += f" -oX {ping_xml_path}"
                    
                    cmd_args = shlex.split(cmd_str)
                    process = subprocess.Popen(cmd_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    register_process(process)
                    stdout, stderr = process.communicate()
                    
                    if process.returncode == 0 or (os.path.exists(ping_xml_path) and os.path.getsize(ping_xml_path) > 0):
                        xml_file = str(ping_xml_path)
                    else:
                        raise Exception(f"Comando Ping manual falló con código {process.returncode}: {stderr[:500] if stderr else 'Sin error'}")
                else:
                    port_scanner = PortScanner(output_file=str(ping_xml_path))
                    # Ejecutar ping scan (-sn)
                    xml_file = port_scanner.scan(
                        target_range=target_str,
                        speed='icmp',
                        ot_ports=False, # No puertos en ping scan
                        it_ports=False,
                        output_file=str(ping_xml_path),
                        process_callback=register_process
                    )
                
                if xml_file and Path(xml_file).exists():
                    parser = NmapXMLParser(ping_xml_path)
                    parsed_data = parser.parse()
                    
                    # Actualizar discovered_ips con nuevos hallazgos
                    new_hosts_count = 0
                    for host_ip, host_data in parsed_data['hosts'].items():
                        if host_ip not in discovered_ips:
                            discovered_ips.add(host_ip)
                            new_hosts_count += 1
                        
                        # Guardar host en BD (aunque no tenga puertos)
                        try:
                            storage.save_host_result(
                                scan_id=scan_id,
                                host_ip=host_ip,
                                port=None,
                                protocol=None,
                                state=host_data.get('status', 'up'),
                                service_data={},
                                hostname=hostname,
                                host_data={'vendor': host_data.get('vendor')},
                                discovery_method='nmap_ping',
                                timestamp=host_data.get('endtime') or host_data.get('starttime')
                            )
                        except Exception as e:
                            print(f"[Scan {scan_id}] ⚠️ Error guardando host ping {host_ip}: {e}")
                    
                    print(f"[Scan {scan_id}] ✅ Fase 2 completada. Hallados {new_hosts_count} nuevos hosts. Total: {len(discovered_ips)}")
            except Exception as e:
                print(f"[Scan {scan_id}] ⚠️ Error en Fase 2 (Ping): {e}")

        if is_scan_cancelled(): return

        # ============================================================================
        # PASO 3: NMAP PORT SCAN (FASE 3)
        # ============================================================================
        if config.nmap:
            print(f"[Scan {scan_id}] 🔌 Iniciando Fase 3: Escaneo de Puertos...")
            
            # Determinar targets: usar IPs acumuladas (F1+F2) si hay, sino el rango
            current_targets = sorted(list(discovered_ips)) if discovered_ips else [config.target_range]
            target_str = ' '.join(current_targets)
            
            try:
                # Validar comando personalizado
                custom_cmd = config.custom_nmap_command
                placeholder = "El comando aparecerá aquí"
                
                if custom_cmd and custom_cmd.strip() and placeholder not in custom_cmd:
                    print(f"[Scan {scan_id}] 📡 Fase 3: Ejecutando comando personalizado: {custom_cmd}")
                    cmd_str = custom_cmd
                    if '-oX' not in cmd_str:
                        cmd_str += f" -oX {nmap_xml_path}"
                    
                    cmd_args = shlex.split(cmd_str)
                    process = subprocess.Popen(cmd_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    register_process(process)
                    stdout, stderr = process.communicate()
                    
                    if process.returncode == 0 or (os.path.exists(nmap_xml_path) and os.path.getsize(nmap_xml_path) > 0):
                        xml_file = str(nmap_xml_path)
                    else:
                        raise Exception(f"Comando Nmap manual falló con código {process.returncode}: {stderr[:500] if stderr else 'Sin error'}")
                else:
                    # Usar el archivo principal para el escaneo de puertos
                    port_scanner = PortScanner(output_file=str(nmap_xml_path))
                    
                    # Ejecutar escaneo de puertos
                    xml_file = port_scanner.scan(
                        target_range=target_str,
                        speed=config.nmap_speed,
                        ot_ports=config.nmap_ot_ports,
                        it_ports=config.nmap_it_ports,
                        custom_ports=config.custom_ports,
                        enable_versions=config.nmap_versions,
                        enable_vulns=config.nmap_vulns,
                        output_file=str(nmap_xml_path),
                        process_callback=register_process
                    )
                
                if is_scan_cancelled(): return
                
                if not xml_file or not Path(xml_file).exists():
                    raise Exception("Nmap no generó el archivo XML de salida (Fase 3)")
                
                print(f"[Scan {scan_id}] ✅ Fase 3 completada. Procesando resultados...")
                
                # Procesar resultados XML de la Fase 3
                parser = NmapXMLParser(nmap_xml_path)
                parsed_data = parser.parse()
                
                total_hosts = len(parsed_data['hosts'])
                hosts_processed = 0
                ports_processed = 0
                
                print(f"[Scan {scan_id}] 📊 Procesando {total_hosts} host(s)...")
                
                # Procesar cada host
                for host_ip, host_data in parsed_data['hosts'].items():
                    if is_scan_cancelled(): return
                    try:
                        
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
                                hostname=hostname,
                                host_data=host_additional_data,
                                discovery_method='nmap_ports',
                                timestamp=host_data.get('endtime') or host_data.get('starttime')
                            )
                            hosts_processed += 1
                            continue
                        
                        # Procesar puertos
                        for port_key, port_data in host_data['ports'].items():
                            if is_scan_cancelled(): return
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
                                hostname=hostname,
                                host_data=host_additional_data,
                                discovery_method='nmap_ports',
                                timestamp=host_data.get('endtime') or host_data.get('starttime')
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
                                if is_scan_cancelled(): return
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
                                if is_scan_cancelled(): return
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

        # ============================================================================
        # PASO 2.5: CAPTURAS ESPECÍFICAS (si Nmap no se ejecutó pero capturas sí)
        # ============================================================================
        if (config.screenshots or config.source_code) and WEB_PROTOCOLS_AVAILABLE:
            # Si Nmap no se ejecutó, necesitamos procesar los targets manualmente
            if not config.nmap:
                print(f"[Scan {scan_id}] 📸 Iniciando capturas específicas sin escaneo Nmap previo...")
                
                # Determinar targets
                targets_to_process = []
                if discovered_ips:
                    targets_to_process = sorted(list(discovered_ips))
                else:
                    try:
                        # Si es un rango simple o IP, intentar expandir
                        if '/' in config.target_range:
                            targets_to_process = [str(ip) for ip in ipaddress.ip_network(config.target_range.strip()).hosts()]
                        else:
                            targets_to_process = config.target_range.replace(',', ' ').split()
                    except Exception:
                        targets_to_process = [config.target_range]

                # Limitar a un número razonable si no hay descubrimiento previo para evitar bloqueos
                if len(targets_to_process) > 256:
                    print(f"[Scan {scan_id}] ⚠️ Demasiados targets ({len(targets_to_process)}) para capturas sin Nmap. Limitando a los primeros 256.")
                    targets_to_process = targets_to_process[:256]

                for target_str in targets_to_process:
                    try:
                        # Detectar si el target tiene puerto específico (IP:PORT)
                        target_parts = target_str.split(':')
                        host_ip = target_parts[0]
                        
                        target_ports = []
                        if len(target_parts) > 1 and target_parts[1].isdigit():
                            target_ports = [int(target_parts[1])]
                        else:
                            # Fallback: En modo específico sin puerto, probamos puertos web comunes
                            target_ports = [80, 443, 8080, 8443, 8000]
                        
                        # Registrar el host si no existe
                        storage.save_discovered_host(scan_id, host_ip, 'specific_capture')
                        
                        for port_num in target_ports:
                            protocol = 'tcp'
                            
                            # Screenshots
                            if config.screenshots and take_screenshot:
                                try:
                                    # take_screenshot ya debería manejar el timeout internamente
                                    screenshot = take_screenshot(host_ip, port_num, str(img_dir))
                                    if screenshot:
                                        print(f"[Scan {scan_id}] 📸 Screenshot capturado: {host_ip}:{port_num}")
                                        # Guardar host result mínimo para vincular el enrichment
                                        res_id = storage.save_host_result(
                                            scan_id=scan_id, host_ip=host_ip, port=port_num, 
                                            protocol=protocol, state='open', service_data={'name': 'http-alt' if port_num != 80 and port_num != 443 else 'http'},
                                            discovery_method='specific_capture'
                                        )
                                        storage.save_enrichment(
                                            scan_id=scan_id, host_ip=host_ip, port=port_num,
                                            protocol=protocol, enrichment_type='Screenshot',
                                            data=screenshot, file_path=str(img_dir / f"{host_ip}_{port_num}.png")
                                        )
                                except Exception as e:
                                    pass # Silencioso para no saturar si el puerto está cerrado
                            
                            # Source code
                            if config.source_code and get_source:
                                try:
                                    source = get_source(host_ip, port_num, str(source_dir))
                                    if source:
                                        print(f"[Scan {scan_id}] 📝 Source code capturado: {host_ip}:{port_num}")
                                        # Guardar host result si no se hizo en el paso anterior
                                        storage.save_host_result(
                                            scan_id=scan_id, host_ip=host_ip, port=port_num, 
                                            protocol=protocol, state='open', service_data={'name': 'http-alt'},
                                            discovery_method='specific_capture'
                                        )
                                        storage.save_enrichment(
                                            scan_id=scan_id, host_ip=host_ip, port=port_num,
                                            protocol=protocol, enrichment_type='Websource',
                                            data=source, file_path=str(source_dir / f"{host_ip}_{port_num}.txt")
                                        )
                                except Exception as e:
                                    pass

                    except Exception as e:
                        print(f"[Scan {scan_id}] ⚠️ Error en capturas para {target_str}: {e}")

        # ============================================================================
        # PASO 3: IOXIDRESOLVER (si está habilitado)
        # ============================================================================
        if hasattr(config, 'ioxid') and config.ioxid:
            print(f"[Scan {scan_id}] 📌 Iniciando escaneo IOXIDResolver...")
            try:
                ioxid_scanner = IOXIDResolverScanner()
                
                # Obtener hosts para IOXID
                conn = sqlite3.connect(str(storage.db_path))
                cursor = conn.cursor()
                ioxid_targets = [row[0] for row in cursor.execute(
                    "SELECT DISTINCT ip_address FROM hosts h JOIN scan_results sr ON h.id = sr.host_id WHERE sr.scan_id = ?",
                    (scan_id,)
                ).fetchall()]
                conn.close()
                
                # Si no hay hosts en la BD aún, usar los objetivos directos
                if not ioxid_targets:
                    if discovered_ips:
                        ioxid_targets = list(discovered_ips)
                    else:
                        try:
                            if '/' in config.target_range:
                                ioxid_targets = [str(ip) for ip in ipaddress.ip_network(config.target_range.strip()).hosts()]
                            else:
                                ioxid_targets = config.target_range.replace(',', ' ').split()
                        except:
                            ioxid_targets = [config.target_range]
                
                # Limitar targets para IOXID si son demasiados
                if len(ioxid_targets) > 512:
                    ioxid_targets = ioxid_targets[:512]

                if not ioxid_targets:
                    # Sin hosts descubiertos todavía (Nmap/Discovery deshabilitado o falló)
                    # Expandir rango manual para IOXID (máximo 256 IPs para seguridad)
                    try:
                        net = ipaddress.ip_network(config.target_range, strict=False)
                        if net.num_addresses <= 256:
                            ioxid_targets = [str(ip) for ip in net.hosts()]
                            print(f"[Scan {scan_id}] 🌐 Sin hosts previos. Expandiendo rango {config.target_range} ({len(ioxid_targets)} IPs)")
                        else:
                            # Solo permitir la primera /24 si es muy grande
                            first_24 = list(net.subnets(new_prefix=24))[0]
                            ioxid_targets = [str(ip) for ip in first_24.hosts()]
                            print(f"[Scan {scan_id}] ⚠️ Rango demasiado grande. Limitando a primera subred /24 ({len(ioxid_targets)} IPs)")
                    except Exception:
                        # Si es una sola IP
                        ioxid_targets = [config.target_range]

                print(f"[Scan {scan_id}] 📊 Escaneando interfaces en {len(ioxid_targets)} hosts...")
                for host_ip in ioxid_targets:
                    try:
                        interfaces = ioxid_scanner.get_interfaces(host_ip)
                        if interfaces:
                            # Si es un host nuevo (no descubierto por Nmap/HD), registrarlo
                            storage.save_discovered_host(scan_id, host_ip, discovery_method='ioxid')
                            storage.add_host_interfaces(host_ip, interfaces)
                            print(f"[Scan {scan_id}] ✅ IOXID {host_ip}: {len(interfaces)} interfaces")
                    except Exception as e:
                        pass
            except Exception as e:
                print(f"[Scan {scan_id}] ⚠️  Error en paso IOXIDResolver: {e}")

        # ============================================================================
        # PASO 4: ENRIQUECIMIENTO STANDALONE (si está habilitado y no se hizo en Paso 2)
        # ============================================================================
        if (config.screenshots or config.source_code) and WEB_PROTOCOLS_AVAILABLE:
            print(f"[Scan {scan_id}] 🌐 Iniciando fase de enriquecimiento standalone...")
            
            enrichment_targets = []
            
            # 1. Obtener todos los servicios web en el rango de este escaneo desde la BD
            try:
                conn = sqlite3.connect(str(storage.db_path))
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                query = """
                    SELECT h.ip_address, sr.port, sr.protocol, sr.service_name, sr.product
                    FROM hosts h
                    JOIN scan_results sr ON h.id = sr.host_id
                    WHERE sr.state = 'open' 
                      AND (sr.port IN (80, 443, 8080, 8443, 8000, 8081, 8888) 
                           OR sr.service_name LIKE '%http%')
                """
                all_web_services = cursor.execute(query).fetchall()
                conn.close()
                
                print(f"[Scan {scan_id}] 🔍 Encontrados {len(all_web_services)} servicios web totales en la BD")
                
                # Filtrar por rango
                # Normalizar target_range (puede ser CIDR, IP única o lista de IPs)
                targets_to_check = [t.strip() for t in config.target_range.replace(',', ' ').split() if t.strip()]
                
                for svc in all_web_services:
                    svc_ip_str = svc['ip_address']
                    try:
                        svc_ip = ipaddress.ip_address(svc_ip_str)
                        matches = False
                        
                        for t in targets_to_check:
                            try:
                                if '/' in t:
                                    # Es un rango CIDR
                                    if svc_ip in ipaddress.ip_network(t, strict=False):
                                        matches = True
                                        break
                                else:
                                    # Intentar como IP única
                                    if svc_ip == ipaddress.ip_address(t):
                                        matches = True
                                        break
                            except ValueError:
                                # Si no es IP ni CIDR, comparar literal
                                if svc_ip_str == t:
                                    matches = True
                                    break
                                    
                        if matches:
                            enrichment_targets.append(dict(svc))
                    except ValueError:
                        continue
                            
            except Exception as e:
                print(f"[Scan {scan_id}] ⚠️ Error consultando BD para enriquecimiento: {e}")

            if enrichment_targets:
                print(f"[Scan {scan_id}] 📸 Procesando {len(enrichment_targets)} servicios web para enriquecimiento...")
                
                # Optimizaciones: 
                # 1. Deduplicar objetivos (evitar procesar mismo IP:PORT varias veces)
                unique_targets = []
                seen_targets = set()
                for t in enrichment_targets:
                    key = (t['ip_address'], t['port'])
                    if key not in seen_targets:
                        unique_targets.append(t)
                        seen_targets.add(key)
                
                print(f"[Scan {scan_id}] 🎯 Objetivos únicos tras deduplicar: {len(unique_targets)}")
                
                # 2. Inicializar driver compartido si los screenshots están habilitados
                shared_driver = None
                if config.screenshots and take_screenshot:
                    try:
                        from selenium import webdriver
                        from selenium.webdriver.firefox.options import Options
                        from selenium.webdriver.firefox.service import Service
                        import os
                        
                        opts = Options()
                        opts.add_argument("--headless")
                        opts.add_argument("--no-sandbox")
                        opts.add_argument("--disable-dev-shm-usage")
                        opts.add_argument("--window-size=1920,1080")
                        
                        # Ubicación del Firefox de Kali
                        opts.binary_location = '/usr/bin/firefox-esr'
                        
                        # 1. Configuración de seguridad para root
                        os.environ["MOZ_DISABLE_CONTENT_SANDBOX"] = "1"
                        os.environ["HOME"] = "/tmp"
                        
                        # 2. LA CURA AL ERROR: Borramos el rastro del entorno gráfico del usuario kali
                        os.environ.pop("XAUTHORITY", None)
                        os.environ.pop("DISPLAY", None)
                        
                        # 3. Servicio usando el Geckodriver que descargamos
                        servicio = Service(executable_path='/usr/local/bin/geckodriver', log_path='/tmp/geckodriver.log')
                        
                        shared_driver = webdriver.Firefox(service=servicio, options=opts)
                        print(f"[Scan {scan_id}] 🚀 Driver de Firefox compartido iniciado.")
                    except Exception as e:
                        print(f"[Scan {scan_id}] ⚠️ No se pudo iniciar el driver compartido de Firefox: {e}")
                        if "geckodriver" in str(e).lower():
                            print(f"[Scan {scan_id}] 💡 Sugerencia: Instala geckodriver (sudo apt install firefox-geckodriver)")

                try:
                    # 2.5 Cachear enriquecimientos existentes para evitar duplicados entre escaneos
                    # Buscamos qué (ip, port, tipo) ya tienen enriquecimiento registrado en la BD para esta organización
                    existing_enrichments = set()
                    try:
                        conn = sqlite3.connect(str(storage.db_path))
                        cursor = conn.cursor()
                        # Solo consideramos enriquecimientos exitosos (que tengan file_path o data) en esta organización
                        cursor.execute("""
                            SELECT h.ip_address, sr.port, e.enrichment_type
                            FROM enrichments e
                            JOIN scan_results sr ON e.scan_result_id = sr.id
                            JOIN hosts h ON sr.host_id = h.id
                            JOIN scans s ON sr.scan_id = s.id
                            WHERE s.organization_name = ?
                        """, (config.organization.upper(),))
                        for row in cursor.fetchall():
                            existing_enrichments.add((row[0], row[1], row[2]))
                        conn.close()
                    except Exception as e:
                        print(f"[Scan {scan_id}] ⚠️ Error consultando enriquecimientos previos: {e}")

                    for svc in unique_targets:
                        host_ip = svc['ip_address']
                        port_num = svc['port']
                        proto = svc['protocol']
                        
                        # 3. Obtener Código Fuente
                        source_obtained = False
                        if config.source_code and get_source:
                            # Check duplicado cross-scan
                            if (host_ip, port_num, 'Websource') in existing_enrichments:
                                print(f"[Scan {scan_id}] ⏩ Código fuente ya capturado en otro escaneo para {host_ip}:{port_num}, saltando.")
                                source_obtained = True 
                            else:
                                try:
                                    source = get_source(host_ip, port_num, str(source_dir))
                                    if source:
                                        source_obtained = True
                                        # Registrar en el escaneo actual para que la UI lo vea
                                        storage.save_host_result(scan_id=scan_id, host_ip=host_ip, port=port_num, protocol=proto, state='open', service_data={'name': svc.get('service_name', ''), 'product': svc.get('product', '')}, discovery_method='enrichment')
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
                                    print(f"[Scan {scan_id}] ⚠️ Error obteniendo código de {host_ip}:{port_num}: {e}")
                        
                        # 4. Capturar Pantalla
                        if config.screenshots and take_screenshot:
                            # Check duplicado cross-scan
                            if (host_ip, port_num, 'Screenshot') in existing_enrichments:
                                print(f"[Scan {scan_id}] ⏩ Captura ya realizada en otro escaneo para {host_ip}:{port_num}, saltando.")
                                continue

                            if is_scan_cancelled(): 
                                print(f"[Scan {scan_id}] 🛑 Cancelando fase de enriquecimiento...")
                                break
                            
                            # Si source_code falló COMPLETAMENTE (ni siquiera status), saltamos
                            # Pero si get_source devolvió algo (aunque no sea 200), tiramos captura
                            if config.source_code and not source_obtained:
                                # Hacemos un último intento rápido de ver si el puerto responde a NADA 
                                # para no lanzar Firefox en balde
                                try:
                                    import socket
                                    with socket.create_connection((host_ip, port_num), timeout=1):
                                        pass
                                except:
                                    continue # Puerto cerrado o no responde

                            try:
                                screenshot = take_screenshot(host_ip, port_num, str(img_dir), driver=shared_driver)
                                if screenshot:
                                    # Registrar en el escaneo actual
                                    storage.save_host_result(scan_id=scan_id, host_ip=host_ip, port=port_num, protocol=proto, state='open', service_data={'name': svc.get('service_name', ''), 'product': svc.get('product', '')}, discovery_method='enrichment')
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
                                print(f"[Scan {scan_id}] ⚠️ Error capturando imagen de {host_ip}:{port_num}: {e}")
                finally:
                    if shared_driver:
                        try:
                            shared_driver.quit()
                            print(f"[Scan {scan_id}] 🛑 Driver de Firefox compartido cerrado.")
                        except:
                            pass
            else:
                if not config.nmap and not config.host_discovery:
                    msg = f"No se han encontrado activos o servicios web en el rango {config.target_range} para procesar. Se recomienda ejecutar acompañado de un escaneo Nmap o descubrimiento de hosts."
                    print(f"[Scan {scan_id}] ⚠️ {msg}")
                    try:
                        conn = sqlite3.connect(str(storage.db_path))
                        conn.execute("UPDATE scans SET error_message = ? WHERE id = ?", (msg, scan_id))
                        conn.commit()
                        conn.close()
                    except:
                        pass
        
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
    
    def is_scan_cancelled():
        """Comprueba si el escaneo ha sido cancelado en la base de datos."""
        try:
            conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
            cursor = conn.cursor()
            status = cursor.execute("SELECT status FROM scans WHERE id = ?", (scan_id,)).fetchone()[0]
            conn.close()
            return status != 'running'
        except:
            return False

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
            # Verificar si el escaneo ha sido cancelado por el usuario
            if is_scan_cancelled():
                print(f"[Scan {scan_id}] 🛑 Escaneo detenido/cancelado por el usuario (pasivo)")
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except:
                        process.kill()
                
                # Procesar lo que quede en el pcap antes de salir
                print(f"[Scan {scan_id}] 📦 Procesando datos finales antes de cerrar...")
                try:
                    scans_module.process_pcap_file(scan_id, str(pcap_file), organization, location)
                except:
                    pass
                break
                
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
            stats = storage.get_passive_stats(scan_id)
            hosts_count = stats['hosts_count']
            ports_count = stats['conversations_count'] # Usamos conversaciones como equivalente a "hallazgos"
            
            storage.complete_scan(scan_id, hosts_count=hosts_count, ports_count=ports_count)
            print(f"[Scan {scan_id}] ✅ ESCANEO PASIVO COMPLETADO")
            print(f"[Scan {scan_id}]    Hosts únicos involucrados: {hosts_count}")
            print(f"[Scan {scan_id}]    Conversaciones registradas: {ports_count}")
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
        # Obtener myip del escaneo para filtrar tráfico saliente del propio equipo
        conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        scan_info = cursor.execute("SELECT myip FROM scans WHERE id = ?", (scan_id,)).fetchone()
        conn.close()
        my_ip = scan_info['myip'] if scan_info and scan_info['myip'] else None
        if my_ip:
            print(f"[Scan {scan_id}] 🛡️ Filtrando tráfico saliente desde mi IP: {my_ip}")

        # Guardar conexiones en la BD (solo IPs privadas)
        conversations_to_save = []
        ip_timestamps = {} # IP -> latest timestamp
        
        for conv in connections:
            try:
                ip_src = conv['src_ip']
                ip_dst = conv['dst_ip']
                ts = conv.get('timestamp') or datetime.now()

                # DESCARTE: Si el origen es mi equipo, no guardar ni registrar como host
                if my_ip and ip_src == my_ip:
                    continue

                # Validar IPs y verificar que sean privadas
                try:
                    ip_src_obj = ipaddress.ip_address(ip_src)
                    ip_dst_obj = ipaddress.ip_address(ip_dst)
                except ValueError:
                    continue

                # Añadir a la lista para guardado masivo
                conversations_to_save.append(conv)
                
                # Coleccionar IPs únicas con su último timestamp visto
                if ip_src not in ip_timestamps or ts > ip_timestamps[ip_src]:
                    ip_timestamps[ip_src] = ts
                if ip_dst not in ip_timestamps or ts > ip_timestamps[ip_dst]:
                    ip_timestamps[ip_dst] = ts

            except Exception as e:
                print(f"[Scan {scan_id}] ⚠️  Error procesando conversación: {e}")
                continue
        
        # Guardar conversaciones masivamente
        if conversations_to_save:
            storage.save_passive_conversations_bulk(scan_id, conversations_to_save)
            
        # Registrar hosts descubiertos masivamente (con su timestamp real)
        if ip_timestamps:
            hosts_to_save = []
            for ip, ts in ip_timestamps.items():
                hosts_to_save.append({
                    'host_ip': ip,
                    'port': None,
                    'protocol': None,
                    'state': 'up',
                    'service_data': {},
                    'discovery_method': 'passive_capture',
                    'timestamp': ts # Propagar timestamp para first_seen/last_seen
                })
            storage.save_host_results_bulk(scan_id, hosts_to_save)
        
        # Actualizar los tiempos del escaneo (started_at / completed_at) con los reales del pcap
        if ip_timestamps:
            min_ts = min(ip_timestamps.values())
            max_ts = max(ip_timestamps.values())
            
            try:
                conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
                conn.execute("PRAGMA journal_mode=WAL")
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE scans 
                    SET started_at = ?, completed_at = ? 
                    WHERE id = ?
                """, (min_ts, max_ts, scan_id))
                conn.commit()
                conn.close()
                print(f"[Scan {scan_id}] 📅 Tiempos del escaneo actualizados: {min_ts} - {max_ts}")
            except Exception as e:
                print(f"[Scan {scan_id}] ⚠️  Error actualizando tiempos del escaneo: {e}")

        print(f"[Scan {scan_id}] ✅ Procesamiento de pcap completado")
        
    except Exception as e:
        print(f"[Scan {scan_id}] ❌ Error procesando pcap: {e}")
        import traceback
        traceback.print_exc()

@router.websocket("/ws/scan/{scan_id}")
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

def run_ioxid_scan_background(scan_id: int, config: ScanConfig, ws_id: str):
    """Ejecuta el escaneo de IOXIDResolver en background."""
    try:
        # 1. Marcar como running
        conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL")
        cursor = conn.cursor()
        cursor.execute("UPDATE scans SET status = 'running' WHERE id = ?", (scan_id,))
        conn.commit()
        conn.close()

        # 2. Obtener targets
        # Si no hay targets conocidos, usamos el target_range
        # Pero IOXID necesita IPs individuales.
        targets = []
        try:
            # Intentar parsear como red
            network = ipaddress.ip_network(config.target_range, strict=False)
            targets = [str(ip) for ip in network.hosts()]
            if not targets: # Caso /32
                targets = [str(network.network_address)]
        except ValueError:
            # Es una lista de IPs o herencia de descubrimiento anterior
            targets = [t.strip() for t in config.target_range.split(',') if t.strip()]

        print(f"[Scan {scan_id}] 🔍 Iniciando IOXIDResolver en {len(targets)} targets...")
        
        hosts_discovered = 0
        interfaces_found = 0

        for ip in targets:
            try:
                scanner = IOXIDResolverScanner(ip)
                interfaces = scanner.get_interfaces()
                
                if interfaces:
                    print(f"[Scan {scan_id}] ✅ Descubiertas interfaces para {ip}: {interfaces}")
                    # Guardar host en la base de datos si no existe
                    storage.save_discovered_host(scan_id, ip, discovery_method='ioxid')
                    
                    # Obtener host_id
                    conn = sqlite3.connect(str(storage.db_path))
                    cursor = conn.cursor()
                    host_id_row = cursor.execute("SELECT id FROM hosts WHERE ip_address = ?", (ip,)).fetchone()
                    conn.close()
                    
                    if host_id_row:
                        host_id = host_id_row[0]
                        storage.add_host_interfaces(host_id, interfaces)
                        interfaces_found += len(interfaces)
                    
                    hosts_discovered += 1
            except Exception as e:
                print(f"[Scan {scan_id}] ⚠️ Error escaneando {ip}: {e}")

        # 3. Finalizar
        storage.complete_scan(scan_id, hosts_count=hosts_discovered)
        print(f"[Scan {scan_id}] ✅ IOXIDResolver completado. Hosts con interfaces: {hosts_discovered}")

    except Exception as e:
        print(f"[Scan {scan_id}] ❌ ERROR en IOXIDResolver: {e}")
        storage.complete_scan(scan_id, error_message=str(e))
    finally:
        if str(scan_id) in running_processes:
            del running_processes[str(scan_id)]
        if str(scan_id) in running_scans:
            del running_scans[str(scan_id)]


