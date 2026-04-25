import sqlite3
import subprocess
import os
import ipaddress
import shlex
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Optional
from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect

from arsenal.core.scanners import (
    HostDiscovery,
    PortScanner,
    ServiceDetection,
    IOXIDResolverScanner
)
from arsenal.web.core.models import ScanConfig
from arsenal.web.core.deps import storage, running_scans, running_processes, running_scans_lock
from arsenal.web.core.websockets import manager
from arsenal.core.parsers.nmap_parser import NmapXMLParser
from arsenal.core.parsers.vulnerability_parser import VulnerabilityParser

router = APIRouter()

# Añadir get_interface_ip from core if needed
from arsenal.scripts.check_env import check_dependencies

# helper definition (was top of app.py)
import socket
import struct

try:
    import fcntl
except ImportError:
    fcntl = None

def get_interface_ip(ifname: str) -> str:
    if not ifname:
        return None

    try:
        if fcntl is None:
            return socket.gethostbyname(socket.gethostname())

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(), 0x8915, struct.pack('256s', ifname[:15].encode('utf-8'))
        )[20:24])
    except Exception:
        return None

def build_scan_phases(config: ScanConfig):
    """Build the phase list used by the runner and the live UI."""
    phases = []

    def add(key, label, detail=None):
        phases.append({
            "key": key,
            "label": label,
            "detail": detail,
            "sort_order": len(phases),
        })

    is_active = config.scan_mode == "active"

    if is_active and config.host_discovery:
        add("host_discovery", "Fase 1 - Descubrimiento ARP", "Buscando hosts activos")
    if is_active and config.nmap_icmp:
        add("ping_discovery", "Fase 2 - Ping Scan", "Confirmando hosts con Nmap -sn")
    if is_active and config.nmap:
        add("port_scan", "Fase 3 - Puertos y servicios", "Escaneando puertos y servicios")
    if (config.screenshots or config.source_code) and not (is_active and config.nmap):
        add("specific_capture", "Capturas especificas", "Probando servicios web indicados")
    if hasattr(config, "ioxid") and config.ioxid:
        add("ioxid", "IOXIDResolver", "Buscando interfaces DCOM")
    if (config.screenshots or config.source_code) and config.scan_mode != "specific" and is_active and config.nmap:
        add("web_enrichment", "Evidencias web", "Capturas y codigo fuente de servicios web")

    if not phases:
        add("scan", "Escaneo", "Ejecutando tareas seleccionadas")
    return phases

def set_phase(scan_id: int, phase_key: str, status: str = None, progress: int = None,
              detail: str = None, started: bool = False, completed: bool = False):
    try:
        storage.update_scan_phase(
            scan_id,
            phase_key,
            status=status,
            progress=progress,
            detail=detail,
            mark_started=started,
            mark_completed=completed,
        )
    except Exception as e:
        print(f"[Scan {scan_id}] Error actualizando fase {phase_key}: {e}")


def parse_specific_web_targets(target_range: str):
    """Parse a user supplied list of IP, IP:port or URL targets for EyeWitness."""
    targets = []
    seen = set()
    raw_items = [p.strip() for p in (target_range or "").replace("\n", ",").split(",")]
    for raw in raw_items:
        if not raw:
            continue
        item = raw
        for prefix in ("http://", "https://"):
            if item.lower().startswith(prefix):
                item = item[len(prefix):]
                break
        item = item.strip().strip("/")
        if "/" in item:
            continue

        host = item
        ports = []
        if ":" in item:
            host, port_text = item.rsplit(":", 1)
            if port_text.isdigit():
                ports = [int(port_text)]
        if not ports:
            ports = [80, 443, 8000, 8080, 8081, 8443, 8888, 9090, 10000]

        try:
            ipaddress.ip_address(host)
        except ValueError:
            continue

        for port in ports:
            key = (host, port)
            if key in seen:
                continue
            seen.add(key)
            targets.append({"ip_address": host, "port": port, "protocol": "tcp"})
    return targets

@router.get("/api/scans/list")
async def get_scans_list(organization: Optional[str] = None, location: Optional[str] = None):
    """Obtiene lista de escaneos para dropdowns."""
    try:
        conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = """
            SELECT id, organization_name, location, target_range, started_at, scan_mode, scan_type
            FROM scans
            WHERE COALESCE(scan_mode, 'active') != 'passive'
        """
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
            # sqlite3.Row no tiene método .get(), usar acceso directo con manejo de None
            target_range_val = scan["target_range"] if scan["target_range"] is not None else ""
            scan_mode_val = scan["scan_mode"] if scan["scan_mode"] is not None else "active"
            scan_type_val = scan["scan_type"] if scan["scan_type"] is not None else None
            
            target_display = target_range_val
            
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
            zombie_id = zombie['id']
            zombie_id_str = str(zombie_id)

            # NO marcar como zombie si el thread está realmente en ejecución
            with running_scans_lock:
                thread = running_scans.get(zombie_id_str)
            if thread and thread.is_alive():
                continue  # Saltar este escaneo, está realmente en ejecución

            # NO marcar como zombie si el proceso del escaneo está realmente en ejecución
            with running_scans_lock:
                process = running_processes.get(zombie_id_str)
            if process and process.poll() is None:
                continue  # Saltar este escaneo, está realmente en ejecución

            # Verificar si hay resultados
            hosts_count = cursor.execute("""
                SELECT COUNT(DISTINCT host_id) FROM scan_results WHERE scan_id = ?
            """, (zombie_id,)).fetchone()[0]

            ports_count = cursor.execute("""
                SELECT COUNT(*) FROM scan_results WHERE scan_id = ?
            """, (zombie_id,)).fetchone()[0]

            # Si hay resultados, marcar como completado, si no, como fallido
            if hosts_count > 0 or ports_count > 0:
                zombie_new_status = 'completed'
                error_message = None
            else:
                zombie_new_status = 'failed'
                error_message = "Escaneo zombie detectado y limpiado automáticamente."

            cursor.execute("""
                UPDATE scans
                SET status = ?, completed_at = ?, hosts_discovered = ?,
                    ports_found = ?, error_message = ?
                WHERE id = ?
            """, (zombie_new_status, datetime.now().isoformat(), hosts_count, ports_count,
                  error_message, zombie_id))
        
        conn.commit()
        print(f"🧹 Limpiados {len(zombies)} escaneo(s) zombie automáticamente")
    
    # Obtener escaneos
    query = "SELECT * FROM scans WHERE COALESCE(scan_mode, 'active') != 'passive'"
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
            if scan_id_str in running_scans:
                thread = running_scans[scan_id_str]
                if thread and thread.is_alive():
                    scan_dict['is_really_running'] = True
                    result.append(scan_dict)
                    continue
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
            from arsenal.core.protocols.web import take_screenshot, get_source, run_eyewitness_batch
            WEB_PROTOCOLS_AVAILABLE = True
        except ImportError:
            WEB_PROTOCOLS_AVAILABLE = False
            take_screenshot = None
            get_source = None
            run_eyewitness_batch = None
        
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

        phase_errors = []
        try:
            storage.initialize_scan_phases(scan_id, build_scan_phases(config))
        except Exception as e:
            print(f"[Scan {scan_id}] Error inicializando fases: {e}")
        
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
                with running_scans_lock:
                    running_processes[str(scan_id)] = proc

        # Dict IP -> {mac_address, vendor}. Se reutiliza entre fases para que
        # ping/puertos no pierdan la MAC si una fase anterior ya la vio.
        discovered_ips: dict = {}

        def _clean_host_meta_value(value):
            cleaned = str(value).strip() if value is not None else None
            return cleaned or None

        def merge_discovered_host_meta(host_ip: str, mac_address=None, vendor=None):
            host_meta = discovered_ips.setdefault(host_ip, {'mac_address': None, 'vendor': None})
            mac_address = _clean_host_meta_value(mac_address)
            vendor = _clean_host_meta_value(vendor)
            if mac_address:
                host_meta['mac_address'] = mac_address
            if vendor:
                host_meta['vendor'] = vendor
            return host_meta

        is_active_mode = config.scan_mode == "active"
        run_host_discovery = is_active_mode and config.host_discovery
        run_ping_discovery = is_active_mode and config.nmap_icmp
        run_port_scan = is_active_mode and config.nmap


        # ============================================================================
        # PASO 1: HOST DISCOVERY (si está habilitado)
        # ============================================================================
        if run_host_discovery:
            set_phase(scan_id, "host_discovery", status="running", progress=10, detail="Ejecutando descubrimiento ARP", started=True)
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
                    
                    # Extract IPs (+ MAC/vendor when present) using HostDiscovery utility
                    host_discovery = HostDiscovery(interface=config.interface)
                    if process.returncode == 0 or stdout:
                        discovered_ips = host_discovery.extract_hosts_from_output(stdout)
                    
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
                
                # Guardar hosts descubiertos en la BD (con MAC y vendor si los aportó arp-scan).
                # Diferenciamos la técnica para que la bitácora pueda indicar visibilidad
                # por capa: con MAC → ARP (L2); sin MAC → ICMP/ping (L3).
                set_phase(scan_id, "host_discovery", status="completed", progress=100, detail=f"{len(discovered_ips)} host(s) descubiertos", completed=True)

                for host_ip, host_meta in discovered_ips.items():
                    if is_scan_cancelled(): return
                    try:
                        method = 'arp_discovery' if host_meta.get('mac_address') else 'icmp_discovery'
                        storage.save_discovered_host(
                            scan_id=scan_id,
                            host_ip=host_ip,
                            discovery_method=method,
                            mac_address=host_meta.get('mac_address'),
                            vendor=host_meta.get('vendor'),
                        )
                    except Exception as e:
                        print(f"[Scan {scan_id}] ⚠️  Error guardando host {host_ip}: {e}")
            except Exception as e:
                print(f"[Scan {scan_id}] ⚠️  Error en host discovery: {e}")
                phase_errors.append(f"Descubrimiento ARP: {e}")
                set_phase(scan_id, "host_discovery", status="failed", progress=100, detail=str(e)[:500], completed=True)
                import traceback
                traceback.print_exc()
        
        # ============================================================================
        # PASO 2: NMAP PING DISCOVERY (FASE 2)
        # ============================================================================
        if run_ping_discovery:
            set_phase(scan_id, "ping_discovery", status="running", progress=10, detail="Ejecutando Nmap ping scan", started=True)
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
                        cmd_str += f" -oX {shlex.quote(str(ping_xml_path))}"
                    
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
                    accepted_ping_reasons = {"echo-reply", "timestamp-reply", "address-mask-reply", "arp-response", "user-set"}
                    for host_ip, host_data in parsed_data['hosts'].items():
                        reason = (host_data.get('reason') or '').lower()
                        if reason and reason not in accepted_ping_reasons:
                            print(f"[Scan {scan_id}] Ignorando host ping {host_ip}: reason={reason}")
                            continue
                        if host_ip not in discovered_ips:
                            new_hosts_count += 1
                        host_meta = merge_discovered_host_meta(
                            host_ip,
                            host_data.get('mac_address'),
                            host_data.get('vendor'),
                        )
                        
                        # Guardar host en BD (aunque no tenga puertos)
                        try:
                            # Intentar obtener hostname del parser
                            hostname = host_data.get('hostname') or (host_data.get('hostnames', [])[0] if host_data.get('hostnames') else None)
                            
                            storage.save_host_result(
                                scan_id=scan_id,
                                host_ip=host_ip,
                                port=None,
                                protocol=None,
                                state=host_data.get('status', 'up'),
                                service_data={},
                                hostname=hostname,
                                host_data={
                                    'mac_address': host_data.get('mac_address') or host_meta.get('mac_address'),
                                    'vendor': host_data.get('vendor') or host_meta.get('vendor'),
                                    'hostnames': host_data.get('hostnames', []),
                                    'os': host_data.get('os', {}),
                                    'host_scripts': host_data.get('host_scripts', {}),
                                },
                                discovery_method='nmap_ping',
                                timestamp=host_data.get('endtime') or host_data.get('starttime')
                            )
                        except Exception as e:
                            print(f"[Scan {scan_id}] ⚠️ Error guardando host ping {host_ip}: {e}")
                    
                    print(f"[Scan {scan_id}] ✅ Fase 2 completada. Hallados {new_hosts_count} nuevos hosts. Total: {len(discovered_ips)}")
                    set_phase(scan_id, "ping_discovery", status="completed", progress=100, detail=f"{new_hosts_count} host(s) nuevos. Total: {len(discovered_ips)}", completed=True)
            except Exception as e:
                print(f"[Scan {scan_id}] ⚠️ Error en Fase 2 (Ping): {e}")
                phase_errors.append(f"Ping Scan: {e}")
                set_phase(scan_id, "ping_discovery", status="failed", progress=100, detail=str(e)[:500], completed=True)

        if is_scan_cancelled(): return

        # ============================================================================
        # PASO 3: NMAP PORT SCAN (FASE 3)
        # ============================================================================
        if run_port_scan:
            set_phase(scan_id, "port_scan", status="running", progress=10, detail="Ejecutando Nmap contra los objetivos", started=True)
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
                        cmd_str += f" -oX {shlex.quote(str(nmap_xml_path))}"
                    
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
                set_phase(scan_id, "port_scan", status="running", progress=55, detail=f"Procesando {total_hosts} host(s)")
                
                print(f"[Scan {scan_id}] 📊 Procesando {total_hosts} host(s)...")
                
                # Procesar cada host
                for host_ip, host_data in parsed_data['hosts'].items():
                    if is_scan_cancelled(): return
                    try:
                        
                        # Obtener hostname
                        hostname = host_data.get('hostname') or None
                        was_previously_discovered = host_ip in discovered_ips
                        host_meta = merge_discovered_host_meta(
                            host_ip,
                            host_data.get('mac_address'),
                            host_data.get('vendor'),
                        )
                        
                        # Preparar datos adicionales del host
                        host_additional_data = {
                            'hostnames': host_data.get('hostnames', []),
                            'mac_address': host_data.get('mac_address') or host_meta.get('mac_address'),
                            'vendor': host_data.get('vendor') or host_meta.get('vendor'),
                            'os': host_data.get('os', {}),
                            'host_scripts': host_data.get('host_scripts', {})
                        }
                        
                        # Si no hay puertos abiertos, registrar el host de todas formas
                        if not host_data.get('ports'):
                            reason = (host_data.get('reason') or '').lower()
                            reliable_host_reasons = {"echo-reply", "timestamp-reply", "address-mask-reply", "arp-response", "user-set"}
                            if not was_previously_discovered and reason not in reliable_host_reasons:
                                hosts_processed += 1
                                continue
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
                            if total_hosts:
                                progress = 55 + int((hosts_processed / total_hosts) * 40)
                                set_phase(scan_id, "port_scan", status="running", progress=progress, detail=f"{hosts_processed}/{total_hosts} host(s), {ports_processed} puerto(s)")
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
                                # VulnerabilityParser ya devuelve claves que coinciden con
                                # la firma de save_vulnerability (vulnerability_id, vulnerability_name,
                                # severity, description, cve_id, cvss_score, script_source, script_output)
                                for vuln in vulnerabilities:
                                    storage.save_vulnerability(
                                        scan_id=scan_id,
                                        host_ip=host_ip,
                                        port=port_num,
                                        protocol=proto,
                                        vulnerability_data=vuln,
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
                        if total_hosts:
                            progress = 55 + int((hosts_processed / total_hosts) * 40)
                            set_phase(scan_id, "port_scan", status="running", progress=progress, detail=f"{hosts_processed}/{total_hosts} host(s), {ports_processed} puerto(s)")
                    except Exception as e:
                        print(f"[Scan {scan_id}] ⚠️  Error procesando host {host_ip}: {e}")
                        import traceback
                        traceback.print_exc()
                        continue
                
                print(f"[Scan {scan_id}] ✅ Procesados {hosts_processed} hosts y {ports_processed} puertos")
                set_phase(scan_id, "port_scan", status="completed", progress=100, detail=f"{hosts_processed} host(s), {ports_processed} puerto(s)", completed=True)
            except Exception as e:
                print(f"[Scan {scan_id}] ❌ Error en escaneo Nmap: {e}")
                phase_errors.append(f"Escaneo de puertos: {e}")
                set_phase(scan_id, "port_scan", status="failed", progress=100, detail=str(e)[:500], completed=True)
                import traceback
                traceback.print_exc()
                raise

        # ============================================================================
        # PASO 2.5: CAPTURAS ESPECÍFICAS (si Nmap no se ejecutó pero capturas sí)
        # ============================================================================
        if (config.screenshots or config.source_code) and WEB_PROTOCOLS_AVAILABLE:
            # Si Nmap no se ejecutó, necesitamos procesar los targets manualmente
            if not run_port_scan:
                set_phase(scan_id, "specific_capture", status="running", progress=10, detail="Preparando objetivos web", started=True)
                print(f"[Scan {scan_id}] 📸 Iniciando capturas específicas sin escaneo Nmap previo...")
                
                # Determinar targets
                targets_to_process = []
                explicit_web_targets = parse_specific_web_targets(config.target_range)
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
                
                # 1. Preparar objetivos para EyeWitness
                unique_eyewitness_targets = []
                seen_targets = set()
                if explicit_web_targets:
                    targets_to_process = []
                    for target in explicit_web_targets:
                        key = (target['ip_address'], int(target['port']))
                        if key not in seen_targets:
                            unique_eyewitness_targets.append(target)
                            seen_targets.add(key)
                
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
                            target_ports = [80, 443, 8000, 8080, 8081, 8443, 8888, 9090, 10000]
                        
                        for port_num in target_ports:
                            key = (host_ip, port_num)
                            if key not in seen_targets:
                                unique_eyewitness_targets.append({
                                    'ip_address': host_ip,
                                    'port': port_num,
                                    'protocol': 'tcp'
                                })
                                seen_targets.add(key)
                    except Exception:
                        continue

                if unique_eyewitness_targets:
                    set_phase(scan_id, "specific_capture", status="running", progress=45, detail=f"EyeWitness sobre {len(unique_eyewitness_targets)} objetivo(s)")
                    print(f"[Scan {scan_id}] 🎯 Ejecutando EyeWitness para {len(unique_eyewitness_targets)} objetivos específicos...")
                    try:
                        ew_results = run_eyewitness_batch(unique_eyewitness_targets, str(img_dir), str(source_dir))
                        
                        # 2. Guardar resultados en la BD
                        for (ip, port), data in ew_results.items():
                            svc_data = {'name': 'http-alt' if port not in [80, 443] else 'http'}
                            proto = 'tcp'

                            # Registrar el host y puerto si se encontró algo
                            if data.get("screenshot") or data.get("source"):
                                storage.save_host_result(
                                    scan_id=scan_id, host_ip=ip, port=port, 
                                    protocol=proto, state='open', service_data=svc_data,
                                    discovery_method='specific_capture'
                                )

                            # Guardar Screenshot
                            if data.get("screenshot"):
                                storage.save_enrichment(
                                    scan_id=scan_id, host_ip=ip, port=port,
                                    protocol=proto, enrichment_type='Screenshot',
                                    data=data["screenshot"], file_path=str(img_dir / f"{ip}_{port}.png")
                                )

                            # Guardar Código Fuente
                            if data.get("source"):
                                storage.save_enrichment(
                                    scan_id=scan_id, host_ip=ip, port=port,
                                    protocol=proto, enrichment_type='Websource',
                                    data=data["source"], file_path=str(source_dir / f"{ip}_{port}.txt")
                                )
                        print(f"[Scan {scan_id}] ✅ Fase de EyeWitness específica completada.")
                    except Exception as e:
                        print(f"[Scan {scan_id}] ⚠️ Error en EyeWitness específico: {e}")

        # ============================================================================
        # PASO 3: IOXIDRESOLVER (si está habilitado)
        # ============================================================================
        if (config.screenshots or config.source_code) and WEB_PROTOCOLS_AVAILABLE and not run_port_scan:
            try:
                phase = next((p for p in storage.get_scan_phases(scan_id) if p.get("phase_key") == "specific_capture"), None)
                if phase and phase.get("status") == "running":
                    set_phase(scan_id, "specific_capture", status="completed", progress=100, detail="EyeWitness finalizado", completed=True)
            except Exception:
                pass

        if hasattr(config, 'ioxid') and config.ioxid:
            print(f"[Scan {scan_id}] 📌 Iniciando escaneo IOXIDResolver...")
            try:
                ioxid_scanner = IOXIDResolverScanner()
                _ioxid_conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
                _ioxid_conn.execute("PRAGMA journal_mode=WAL")
                ioxid_targets = [row[0] for row in _ioxid_conn.execute(
                    "SELECT DISTINCT ip_address FROM hosts h JOIN scan_results sr ON h.id = sr.host_id WHERE sr.scan_id = ?",
                    (scan_id,)
                ).fetchall()]
                _ioxid_conn.close()
                
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
                            storage.add_host_interfaces(host_ip, interfaces, scan_id=scan_id)
                            print(f"[Scan {scan_id}] ✅ IOXID {host_ip}: {len(interfaces)} interfaces")
                    except Exception as e:
                        pass
            except Exception as e:
                print(f"[Scan {scan_id}] ⚠️  Error en paso IOXIDResolver: {e}")

        # ============================================================================
        # PASO 4: ENRIQUECIMIENTO STANDALONE (si está habilitado y no se hizo en Modo Específico)
        # ============================================================================
        if (config.screenshots or config.source_code) and WEB_PROTOCOLS_AVAILABLE and config.scan_mode != "specific":
            if run_port_scan:
                set_phase(scan_id, "web_enrichment", status="running", progress=15, detail="Buscando servicios web para evidencias", started=True)
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
                                # Limpiar puerto si existe en el target string para la comparación de IP
                                t_ip_only = t.split(':')[0]
                                
                                if '/' in t:
                                    # Es un rango CIDR
                                    if svc_ip in ipaddress.ip_network(t, strict=False):
                                        matches = True
                                        break
                                else:
                                    # Intentar como IP única
                                    if svc_ip == ipaddress.ip_address(t_ip_only):
                                        matches = True
                                        break
                            except ValueError:
                                # Comparación literal como fallback
                                if svc_ip_str == t or svc_ip_str == t_ip_only:
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
                
                # 1. Deduplicar y preparar objetivos para EyeWitness
                unique_eyewitness_targets = []
                seen_targets = set()
                for t in enrichment_targets:
                    key = (t['ip_address'], t['port'])
                    if key not in seen_targets:
                        unique_eyewitness_targets.append({
                            'ip_address': t['ip_address'],
                            'port': t['port'],
                            'protocol': t['protocol'],
                            'service_name': t.get('service_name', ''),
                            'product': t.get('product', '')
                        })
                        seen_targets.add(key)
                
                print(f"[Scan {scan_id}] 🎯 Objetivos únicos para EyeWitness: {len(unique_eyewitness_targets)}")
                
                # 2. Ejecutar EyeWitness en lote
                try:
                    ew_results = run_eyewitness_batch(unique_eyewitness_targets, str(img_dir), str(source_dir))
                    
                    # 3. Guardar resultados en la BD
                    for (ip, port), data in ew_results.items():
                        # Encontrar el target original para obtener metadata (service_name, etc.)
                        target_info = next((t for t in unique_eyewitness_targets if t['ip_address'] == ip and t['port'] == port), {})
                        proto = target_info.get('protocol', 'tcp')
                        svc_data = {'name': target_info.get('service_name', ''), 'product': target_info.get('product', '')}

                        # Guardar Screenshot si existe
                        if data.get("screenshot"):
                            storage.save_host_result(scan_id=scan_id, host_ip=ip, port=port, protocol=proto, state='open', service_data=svc_data, discovery_method='enrichment')
                            storage.save_enrichment(
                                scan_id=scan_id,
                                host_ip=ip,
                                port=port,
                                protocol=proto,
                                enrichment_type='Screenshot',
                                data=data["screenshot"],
                                file_path=str(img_dir / f"{ip}_{port}.png")
                            )

                        # Guardar Código Fuente si existe
                        if data.get("source"):
                            storage.save_host_result(scan_id=scan_id, host_ip=ip, port=port, protocol=proto, state='open', service_data=svc_data, discovery_method='enrichment')
                            storage.save_enrichment(
                                scan_id=scan_id,
                                host_ip=ip,
                                port=port,
                                protocol=proto,
                                enrichment_type='Websource',
                                data=data["source"],
                                file_path=str(source_dir / f"{ip}_{port}.txt")
                            )
                    
                    print(f"[Scan {scan_id}] ✅ Fase de EyeWitness completada.")
                except Exception as e:
                    print(f"[Scan {scan_id}] ⚠️  Error en fase EyeWitness: {e}")
            else:
                if not run_port_scan and not run_host_discovery:
                    msg = f"No se han encontrado activos o servicios web en el rango {config.target_range} para procesar. Se recomienda ejecutar acompañado de un escaneo Nmap o descubrimiento de hosts."
                    print(f"[Scan {scan_id}] ⚠️ {msg}")
                    try:
                        conn = sqlite3.connect(str(storage.db_path))
                        conn.execute("UPDATE scans SET error_message = ? WHERE id = ?", (msg, scan_id))
                        conn.commit()
                        conn.close()
                    except:
                        pass
        
        try:
            for phase in storage.get_scan_phases(scan_id):
                if phase.get("status") in ("pending", "running"):
                    set_phase(scan_id, phase.get("phase_key"), status="completed", progress=100, detail=phase.get("detail") or "Finalizado", completed=True)
        except Exception:
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
            error_summary = "; ".join(phase_errors)[:1000] if phase_errors else None
            storage.complete_scan(scan_id, hosts_count=hosts_count, ports_count=ports_count, error_message=error_summary)
            print(f"[Scan {scan_id}] {'ESCANEO COMPLETADO' if not error_summary else 'ESCANEO FINALIZADO CON ERRORES'}")
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
                error_summary = "; ".join(phase_errors)[:1000] if phase_errors else None
                storage.complete_scan(scan_id, hosts_count=hosts_count, ports_count=ports_count, error_message=error_summary)
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
        # Limpiar procesos de los diccionarios (thread-safe)
        with running_scans_lock:
            running_processes.pop(str(scan_id), None)
            running_scans.pop(str(scan_id), None)

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
                            "message": "Escaneo completado" if scan["status"] == "completed" else f"Escaneo falló: {scan['error_message'] or 'Error desconocido'}"
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
