"""
Sistema de almacenamiento de resultados de escaneos
con Base de Datos + JSONs versionados por escaneo
"""

import sqlite3
import json
import zipfile
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, List
import ipaddress


class ScanStorage:
    """Gestor de almacenamiento de resultados de escaneos."""
    
    def __init__(self, results_root: str = "results"):
        self.results_root = Path(results_root)
        # Asegurar que el directorio existe antes de crear la BD
        self.results_root.mkdir(parents=True, exist_ok=True)
        self.db_path = self.results_root / "scans.db"
        self._init_database()
    
    def _init_database(self):
        """Inicializa la base de datos con el esquema necesario."""
        # Asegurar que el directorio padre existe
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        # Habilitar WAL mode para mejor concurrencia
        conn.execute("PRAGMA journal_mode=WAL")
        # Habilitar foreign keys para que CASCADE funcione
        conn.execute("PRAGMA foreign_keys = ON")
        cursor = conn.cursor()
        
        # Tabla de organizaciones
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS organizations (
                name TEXT PRIMARY KEY,
                description TEXT,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Tabla de escaneos (metadatos)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_name TEXT NOT NULL,
                location TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                target_range TEXT NOT NULL,
                interface TEXT,
                nmap_command TEXT,
                started_at TIMESTAMP NOT NULL,
                completed_at TIMESTAMP,
                status TEXT NOT NULL DEFAULT 'running',
                hosts_discovered INTEGER DEFAULT 0,
                ports_found INTEGER DEFAULT 0,
                error_message TEXT,
                created_by TEXT,
                FOREIGN KEY (organization_name) REFERENCES organizations(name) ON DELETE CASCADE
            )
        """)
        
        # Tabla de hosts descubiertos
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL UNIQUE,
                hostname TEXT,
                hostnames_json TEXT,
                mac_address TEXT,
                vendor TEXT,
                subnet TEXT,
                is_private BOOLEAN,
                os_info_json TEXT,
                host_scripts_json TEXT,
                first_seen TIMESTAMP NOT NULL,
                last_seen TIMESTAMP NOT NULL
            )
        """)
        
        # Tabla de redes de la organización
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS networks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_name TEXT NOT NULL,
                system_name TEXT,
                network_name TEXT NOT NULL,
                network_range TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (organization_name) REFERENCES organizations(name) ON DELETE CASCADE
            )
        """)
        
        # Migración para system_name
        try:
            cursor.execute("ALTER TABLE networks ADD COLUMN system_name TEXT")
        except sqlite3.OperationalError:
            pass  # Columna ya existe

        
        # Agregar columnas nuevas si no existen (migración)
        for col in ['hostnames_json', 'mac_address', 'vendor', 'os_info_json', 'host_scripts_json']:
            try:
                cursor.execute(f"ALTER TABLE hosts ADD COLUMN {col} TEXT")
            except sqlite3.OperationalError:
                pass  # Columna ya existe
        
        # Tabla de resultados de escaneo
        # IMPORTANTE: port y protocol permiten NULL para representar hosts descubiertos sin puertos
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                host_id INTEGER NOT NULL,
                port INTEGER,
                protocol TEXT DEFAULT 'tcp',
                state TEXT NOT NULL,
                service_name TEXT,
                product TEXT,
                version TEXT,
                extrainfo TEXT,
                cpe TEXT,
                reason TEXT,
                reason_ttl TEXT,
                confidence INTEGER,
                scripts_json TEXT,
                discovered_at TIMESTAMP NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
                FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE RESTRICT,
                UNIQUE(scan_id, host_id, port, protocol)
            )
        """)
        
        # Agregar columna scripts_json si no existe (migración)
        try:
            cursor.execute("ALTER TABLE scan_results ADD COLUMN scripts_json TEXT")
        except sqlite3.OperationalError:
            pass  # Columna ya existe
        
        try:
            cursor.execute("ALTER TABLE scan_results ADD COLUMN reason_ttl TEXT")
        except sqlite3.OperationalError:
            pass  # Columna ya existe
        
        # Migración: Modificar port y protocol para permitir NULL
        # SQLite no soporta ALTER COLUMN, así que verificamos si necesitamos migrar
        try:
            # Verificar si ya existe un registro con port NULL (indica que ya se migró)
            has_null_port = cursor.execute("""
                SELECT COUNT(*) FROM scan_results WHERE port IS NULL
            """).fetchone()[0]
            
            # Verificar estructura actual
            cursor.execute("PRAGMA table_info(scan_results)")
            columns = cursor.fetchall()
            port_col = next((c for c in columns if c[1] == 'port'), None)
            protocol_col = next((c for c in columns if c[1] == 'protocol'), None)
            
            # Si port tiene NOT NULL, necesitamos migrar
            if port_col and port_col[3] == 1:  # NOT NULL constraint
                print("🔄 Migrando esquema scan_results para permitir NULL en port/protocol...")
                # Backup de datos
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS scan_results_backup AS 
                    SELECT * FROM scan_results
                """)
                # Eliminar tabla antigua
                cursor.execute("DROP TABLE scan_results")
                # Recrear con NULL permitido
                cursor.execute("""
                    CREATE TABLE scan_results (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id INTEGER NOT NULL,
                        host_id INTEGER NOT NULL,
                        port INTEGER,
                        protocol TEXT DEFAULT 'tcp',
                        state TEXT NOT NULL,
                        service_name TEXT,
                        product TEXT,
                        version TEXT,
                        extrainfo TEXT,
                        cpe TEXT,
                        reason TEXT,
                        reason_ttl TEXT,
                        confidence INTEGER,
                        scripts_json TEXT,
                        discovered_at TIMESTAMP NOT NULL,
                        FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
                        FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE RESTRICT,
                        UNIQUE(scan_id, host_id, port, protocol)
                    )
                """)
                # Restaurar datos
                cursor.execute("""
                    INSERT INTO scan_results 
                    SELECT * FROM scan_results_backup
                """)
                cursor.execute("DROP TABLE scan_results_backup")
                conn.commit()
                print("✅ Migración completada: port y protocol ahora permiten NULL")
        except Exception as e:
            print(f"⚠️  Error en migración de scan_results: {e}")
            conn.rollback()
        
        # Tabla de enriquecimientos
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS enrichments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_result_id INTEGER NOT NULL,
                enrichment_type TEXT NOT NULL,
                data TEXT,
                file_path TEXT,
                created_at TIMESTAMP NOT NULL,
                FOREIGN KEY (scan_result_id) REFERENCES scan_results(id) ON DELETE CASCADE
            )
        """)
        
        # Tabla de vulnerabilidades encontradas
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_result_id INTEGER NOT NULL,
                vulnerability_id TEXT,
                vulnerability_name TEXT,
                severity TEXT,
                description TEXT,
                cve_id TEXT,
                cvss_score REAL,
                script_source TEXT,
                script_output TEXT,
                discovered_at TIMESTAMP NOT NULL,
                FOREIGN KEY (scan_result_id) REFERENCES scan_results(id) ON DELETE CASCADE
            )
        """)
        
        # Índices para vulnerabilidades
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan_result 
            ON vulnerabilities(scan_result_id)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve 
            ON vulnerabilities(cve_id)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity 
            ON vulnerabilities(severity)
        """)
        
        # Agregar columnas de capacidades al escaneo si no existen
        try:
            cursor.execute("ALTER TABLE scans ADD COLUMN enable_version_detection BOOLEAN DEFAULT 0")
        except sqlite3.OperationalError:
            pass
        
        try:
            cursor.execute("ALTER TABLE scans ADD COLUMN enable_vulnerability_scan BOOLEAN DEFAULT 0")
        except sqlite3.OperationalError:
            pass
        
        try:
            cursor.execute("ALTER TABLE scans ADD COLUMN enable_screenshots BOOLEAN DEFAULT 0")
        except sqlite3.OperationalError:
            pass
        
        try:
            cursor.execute("ALTER TABLE scans ADD COLUMN enable_source_code BOOLEAN DEFAULT 0")
        except sqlite3.OperationalError:
            pass
        
        try:
            cursor.execute("ALTER TABLE scans ADD COLUMN scan_mode TEXT DEFAULT 'active'")
        except sqlite3.OperationalError:
            pass
        
        try:
            cursor.execute("ALTER TABLE scans ADD COLUMN pcap_file TEXT")
        except sqlite3.OperationalError:
            pass
        
        # Agregar columna discovery_method a scan_results si no existe
        try:
            cursor.execute("ALTER TABLE scan_results ADD COLUMN discovery_method TEXT")
        except sqlite3.OperationalError:
            pass
        
        # Índices para rendimiento
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_scans_org_location 
            ON scans(organization_name, location)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_scans_started 
            ON scans(started_at)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_hosts_ip 
            ON hosts(ip_address)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_scan_results_scan 
            ON scan_results(scan_id)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_scan_results_host 
            ON scan_results(host_id)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_scan_results_port 
            ON scan_results(port, protocol)
        """)
        
        conn.commit()
        conn.close()
    
    def create_organization(self, name: str, description: str = ""):
        """Crea o actualiza una organización."""
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL")
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO organizations (name, description)
            VALUES (?, ?)
        """, (name.upper(), description))
        conn.commit()
        conn.close()
    
    def start_scan(self, organization: str, location: str, scan_type: str,
                   target_range: str, interface: str = None, 
                   nmap_command: str = None, created_by: str = None,
                   enable_version_detection: bool = False,
                   enable_vulnerability_scan: bool = False,
                   enable_screenshots: bool = False,
                   enable_source_code: bool = False,
                   scan_mode: str = 'active',
                   pcap_file: str = None) -> int:
        """Inicia un nuevo escaneo y retorna su ID."""
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL")
        cursor = conn.cursor()
        
        # Asegurar que la organización existe
        self.create_organization(organization)
        
        # Crear registro de escaneo
        cursor.execute("""
            INSERT INTO scans 
            (organization_name, location, scan_type, target_range, 
             interface, nmap_command, started_at, status, created_by,
             enable_version_detection, enable_vulnerability_scan,
             enable_screenshots, enable_source_code, scan_mode, pcap_file)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?)
        """, (organization.upper(), location.upper(), scan_type, target_range,
              interface, nmap_command, datetime.now(), created_by,
              enable_version_detection, enable_vulnerability_scan,
              enable_screenshots, enable_source_code, scan_mode, pcap_file))
        
        scan_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        # Crear directorio para este escaneo con timestamp consistente
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        scan_dir = self._get_scan_directory(organization, location, scan_id, timestamp)
        scan_dir.mkdir(parents=True, exist_ok=True)
        (scan_dir / "evidence").mkdir(exist_ok=True)
        
        # Crear subdirectorios para evidencia (compatibilidad con estructura anterior)
        (scan_dir / "evidence" / "img").mkdir(exist_ok=True)
        (scan_dir / "evidence" / "source").mkdir(exist_ok=True)
        (scan_dir / "evidence" / "vuln").mkdir(exist_ok=True)
        
        # Crear subdirectorio para archivos pcap en escaneos pasivos
        if scan_mode == 'passive':
            (scan_dir / "pcap").mkdir(exist_ok=True)
        
        return scan_id
    
    def _get_scan_directory(self, organization: str, location: str, 
                           scan_id: int, timestamp: str = None) -> Path:
        """Obtiene el directorio para un escaneo específico."""
        if timestamp is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return (self.results_root / organization.upper() / 
                location.upper() / "scans" / f"scan_{scan_id:06d}_{timestamp}")
    
    def get_scan_directory(self, organization: str, location: str, scan_id: int) -> Path:
        """Obtiene el directorio de un escaneo existente."""
        # Buscar el directorio del escaneo
        scans_dir = self.results_root / organization.upper() / location.upper() / "scans"
        if scans_dir.exists():
            for scan_dir in scans_dir.iterdir():
                if scan_dir.is_dir() and f"scan_{scan_id:06d}" in scan_dir.name:
                    return scan_dir
        # Si no existe, crear uno nuevo (puede pasar si se llama antes de start_scan)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        scan_dir = self._get_scan_directory(organization, location, scan_id, timestamp)
        scan_dir.mkdir(parents=True, exist_ok=True)
        return scan_dir
    
    def save_discovered_host(self, scan_id: int, host_ip: str, 
                             discovery_method: str = 'host_discovery',
                             subnet: str = None):
        """
        Guarda un host descubierto por host discovery (sin puertos aún).
        IMPORTANTE: También crea un registro en scan_results con port=NULL para que
        el host aparezca en los resultados aunque no tenga puertos abiertos.
        Solo guarda direcciones IP privadas (filtra IPs públicas).
        """
        # Validar que es IP privada antes de proceder
        try:
            ip_obj = ipaddress.ip_address(host_ip)
            if not ip_obj.is_private:
                # IP pública, no guardar en la base de datos
                return False
        except ValueError:
            # IP inválida, no guardar
            return False
        
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys = ON")
        cursor = conn.cursor()
        
        # Validar que el escaneo existe
        scan_exists = cursor.execute("SELECT id FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not scan_exists:
            print(f"⚠️  El escaneo {scan_id} no existe")
            conn.close()
            return False
        
        # Determinar subred si no se proporciona (ya sabemos que es privada)
        is_private = True
        if not subnet:
            for private_net in [
                ipaddress.ip_network('10.0.0.0/8'),
                ipaddress.ip_network('172.16.0.0/12'),
                ipaddress.ip_network('192.168.0.0/16'),
                ipaddress.ip_network('169.254.0.0/16')
            ]:
                if ip_obj in private_net:
                    subnet = str(private_net)
                    break
            if not subnet:
                subnet = "Private IP (unknown subnet)"
        
        # Insertar o actualizar host
        cursor.execute("""
            INSERT INTO hosts (ip_address, hostname, subnet, is_private,
                             first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip_address) DO UPDATE SET
                last_seen = excluded.last_seen,
                subnet = COALESCE(excluded.subnet, subnet)
        """, (host_ip, None, subnet, is_private, datetime.now(), datetime.now()))
        
        # Obtener el host_id
        host_id = cursor.execute(
            "SELECT id FROM hosts WHERE ip_address = ?", (host_ip,)
        ).fetchone()[0]
        
        # Crear un registro en scan_results con port=NULL para que el host aparezca en resultados
        # Esto es importante para que hosts descubiertos sin puertos también se muestren
        try:
            # Verificar si ya existe un registro para este host en este escaneo sin puerto
            existing = cursor.execute("""
                SELECT id FROM scan_results 
                WHERE scan_id = ? AND host_id = ? AND port IS NULL
            """, (scan_id, host_id)).fetchone()
            
            if not existing:
                # Crear registro en scan_results con port=NULL
                cursor.execute("""
                    INSERT INTO scan_results
                    (scan_id, host_id, port, protocol, state, discovery_method, discovered_at)
                    VALUES (?, ?, NULL, NULL, 'up', ?, ?)
                """, (scan_id, host_id, discovery_method, datetime.now()))
        except sqlite3.IntegrityError as e:
            print(f"⚠️  Error de integridad al guardar scan_result para host descubierto: {e}")
            conn.rollback()
            conn.close()
            return False
        
        conn.commit()
        conn.close()
        return True
    
    def save_host_result(self, scan_id: int, host_ip: str, port: int,
                        protocol: str, state: str, service_data: Dict,
                        subnet: str = None, hostname: str = None,
                        host_data: Dict = None, discovery_method: str = 'nmap'):
        """
        Guarda el resultado de un puerto de un host.
        Solo guarda direcciones IP privadas (filtra IPs públicas).
        
        Relaciones establecidas:
        - hosts: Almacena información del host (IP, hostname, MAC, OS, etc.)
        - scan_results: Vincula host + puerto + escaneo (host_id -> hosts.id, scan_id -> scans.id)
        - Las versiones se almacenan en scan_results.version
        - Los scripts de Nmap se almacenan en scan_results.scripts_json
        """
        # Validar que es IP privada antes de proceder
        try:
            ip_obj = ipaddress.ip_address(host_ip)
            if not ip_obj.is_private:
                # IP pública, no guardar en la base de datos
                return False
            is_private = True
        except ValueError:
            # IP inválida, no guardar
            return False
        
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys = ON")
        cursor = conn.cursor()
        
        # Validar que el escaneo existe
        scan_exists = cursor.execute("SELECT id FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not scan_exists:
            print(f"⚠️  El escaneo {scan_id} no existe")
            conn.close()
            return False
        
        # Preparar datos adicionales del host
        hostnames_json = None
        mac_address = None
        vendor = None
        os_info_json = None
        host_scripts_json = None
        
        if host_data:
            if 'hostnames' in host_data:
                hostnames_json = json.dumps(host_data['hostnames'])
            mac_address = host_data.get('mac_address')
            vendor = host_data.get('vendor')
            if 'os' in host_data and host_data['os']:
                os_info_json = json.dumps(host_data['os'])
            if 'host_scripts' in host_data and host_data['host_scripts']:
                host_scripts_json = json.dumps(host_data['host_scripts'])
        
        cursor.execute("""
            INSERT INTO hosts (ip_address, hostname, hostnames_json, mac_address, vendor,
                             subnet, is_private, os_info_json, host_scripts_json,
                             first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip_address) DO UPDATE SET
                last_seen = excluded.last_seen,
                hostname = COALESCE(excluded.hostname, hostname),
                hostnames_json = COALESCE(excluded.hostnames_json, hostnames_json),
                mac_address = COALESCE(excluded.mac_address, mac_address),
                vendor = COALESCE(excluded.vendor, vendor),
                subnet = COALESCE(excluded.subnet, subnet),
                os_info_json = COALESCE(excluded.os_info_json, os_info_json),
                host_scripts_json = COALESCE(excluded.host_scripts_json, host_scripts_json)
        """, (host_ip, hostname, hostnames_json, mac_address, vendor, subnet, is_private,
              os_info_json, host_scripts_json, datetime.now(), datetime.now()))
        
        host_id = cursor.execute(
            "SELECT id FROM hosts WHERE ip_address = ?", (host_ip,)
        ).fetchone()[0]
        
        # Preparar scripts JSON
        scripts_json = None
        if 'scripts' in service_data and service_data['scripts']:
            scripts_json = json.dumps(service_data['scripts'])
        
        # Insertar resultado del escaneo
        # Si port es None o 0, guardamos el host sin puertos (port=NULL en la BD)
        # Esto permite que hosts descubiertos sin puertos también aparezcan en los resultados
        port_value = port if port and port > 0 else None
        protocol_value = protocol if port and port > 0 else None
        
        # Estado por defecto si no se proporciona
        state_value = state if state else 'up'
        
        try:
            cursor.execute("""
                INSERT OR REPLACE INTO scan_results
                (scan_id, host_id, port, protocol, state, service_name, product,
                 version, extrainfo, cpe, reason, reason_ttl, confidence, scripts_json, discovery_method, discovered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id, host_id, port_value, protocol_value, state_value,
                service_data.get('name') if port_value else None,
                service_data.get('product') if port_value else None,
                service_data.get('version') if port_value else None,
                service_data.get('extrainfo') if port_value else None,
                service_data.get('cpe') if port_value else None,
                service_data.get('reason') if port_value else None,
                service_data.get('reason_ttl') if port_value else None,
                service_data.get('conf') if port_value else None,
                scripts_json, discovery_method,
                datetime.now()
            ))
            conn.commit()
        except sqlite3.IntegrityError as e:
            print(f"⚠️  Error de integridad al guardar scan_result: {e}")
            conn.rollback()
            conn.close()
            return False
        
        conn.close()
        return True
    
    def _get_connection(self):
        """Obtiene una conexión a la base de datos con row_factory."""
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        # Habilitar WAL mode para mejor concurrencia
        conn.execute("PRAGMA journal_mode=WAL")
        return conn
    
    def save_vulnerability(self, scan_id: int, host_ip: str, port: int,
                          protocol: str, vulnerability_data: Dict):
        """
        Guarda una vulnerabilidad encontrada.
        
        Relación: vulnerabilities.scan_result_id -> scan_results.id
        La vulnerabilidad está vinculada a un puerto específico de un host en un escaneo.
        """
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys = ON")
        cursor = conn.cursor()
        
        # Obtener scan_result_id - validar que existe la relación
        result = cursor.execute("""
            SELECT sr.id FROM scan_results sr
            JOIN hosts h ON h.id = sr.host_id
            JOIN scans s ON s.id = sr.scan_id
            WHERE sr.scan_id = ? AND h.ip_address = ? 
              AND sr.port = ? AND sr.protocol = ?
        """, (scan_id, host_ip, port, protocol)).fetchone()
        
        if not result:
            print(f"⚠️  No se encontró scan_result para {host_ip}:{port}/{protocol} en scan {scan_id}")
            conn.close()
            return False
        
        scan_result_id = result[0]
        
        # Verificar que el scan_result existe antes de insertar
        cursor.execute("SELECT id FROM scan_results WHERE id = ?", (scan_result_id,))
        if not cursor.fetchone():
            print(f"⚠️  scan_result_id {scan_result_id} no existe")
            conn.close()
            return False
        
        try:
            cursor.execute("""
                INSERT INTO vulnerabilities
                (scan_result_id, vulnerability_id, vulnerability_name, severity,
                 description, cve_id, cvss_score, script_source, script_output, discovered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_result_id,
                vulnerability_data.get('vulnerability_id'),
                vulnerability_data.get('vulnerability_name'),
                vulnerability_data.get('severity'),
                vulnerability_data.get('description'),
                vulnerability_data.get('cve_id'),
                vulnerability_data.get('cvss_score'),
                vulnerability_data.get('script_source'),
                vulnerability_data.get('script_output'),
                datetime.now()
            ))
            conn.commit()
            return True
        except sqlite3.IntegrityError as e:
            print(f"⚠️  Error de integridad al guardar vulnerabilidad: {e}")
            conn.rollback()
            return False
        finally:
            conn.close()
    
    def save_enrichment(self, scan_id: int, host_ip: str, port: int,
                       protocol: str, enrichment_type: str, data: str,
                       file_path: str = None):
        """Guarda un enriquecimiento (screenshot, banner, etc.)."""
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL")
        cursor = conn.cursor()
        
        # Obtener scan_result_id
        result = cursor.execute("""
            SELECT sr.id FROM scan_results sr
            JOIN hosts h ON h.id = sr.host_id
            WHERE sr.scan_id = ? AND h.ip_address = ? 
              AND sr.port = ? AND sr.protocol = ?
        """, (scan_id, host_ip, port, protocol)).fetchone()
        
        if result:
            scan_result_id = result[0]
            cursor.execute("""
                INSERT INTO enrichments
                (scan_result_id, enrichment_type, data, file_path, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (scan_result_id, enrichment_type, data, file_path, datetime.now()))
            conn.commit()
        
        conn.close()
    
    def complete_scan(self, scan_id: int, hosts_count: int = None,
                     ports_count: int = None, error_message: str = None):
        """Marca un escaneo como completado."""
        conn = None
        try:
            conn = sqlite3.connect(str(self.db_path), timeout=30.0)
            conn.execute("PRAGMA journal_mode=WAL")
            cursor = conn.cursor()
            
            # Contar hosts y puertos si no se proporcionan
            if hosts_count is None:
                hosts_count = cursor.execute("""
                    SELECT COUNT(DISTINCT host_id) FROM scan_results WHERE scan_id = ?
                """, (scan_id,)).fetchone()[0]
            
            if ports_count is None:
                ports_count = cursor.execute("""
                    SELECT COUNT(*) FROM scan_results WHERE scan_id = ?
                """, (scan_id,)).fetchone()[0]
            
            status = 'failed' if error_message else 'completed'
            
            cursor.execute("""
                UPDATE scans
                SET status = ?, completed_at = ?, hosts_discovered = ?,
                    ports_found = ?, error_message = ?
                WHERE id = ?
            """, (status, datetime.now(), hosts_count, ports_count, 
                  error_message, scan_id))
            
            conn.commit()
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e):
                # Reintentar después de un breve delay
                import time
                time.sleep(0.5)
                if conn:
                    conn.close()
                # Reintentar una vez más
                conn = sqlite3.connect(str(self.db_path), timeout=30.0)
                conn.execute("PRAGMA journal_mode=WAL")
                cursor = conn.cursor()
                status = 'failed' if error_message else 'completed'
                cursor.execute("""
                    UPDATE scans
                    SET status = ?, completed_at = ?, hosts_discovered = ?,
                        ports_found = ?, error_message = ?
                    WHERE id = ?
                """, (status, datetime.now(), hosts_count, ports_count, 
                      error_message, scan_id))
                conn.commit()
            else:
                raise
        finally:
            if conn:
                conn.close()
    
    def delete_scan(self, scan_id: int) -> bool:
        """
        Elimina un escaneo y todos sus resultados.
        
        Gracias a ON DELETE CASCADE:
        - Al eliminar el scan, SQLite elimina automáticamente todos los scan_results
        - Al eliminar los scan_results, SQLite elimina automáticamente vulnerabilities y enrichments
        """
        import shutil
        
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys = ON")  # CRÍTICO: debe estar habilitado
        cursor = conn.cursor()
        
        # Obtener información del escaneo para eliminar el directorio
        scan = cursor.execute("""
            SELECT organization_name, location, id FROM scans WHERE id = ?
        """, (scan_id,)).fetchone()
        
        if not scan:
            conn.close()
            return False
        
        org_name, location, _ = scan
        
        # Obtener host_ids que solo pertenecen a este escaneo (para limpiar hosts huérfanos después)
        host_ids = cursor.execute("""
            SELECT DISTINCT host_id FROM scan_results WHERE scan_id = ?
        """, (scan_id,)).fetchall()
        host_ids = [h[0] for h in host_ids]
        
        # Eliminar el escaneo - CASCADE eliminará automáticamente:
        # 1. Todos los scan_results (por scan_results.scan_id -> scans.id ON DELETE CASCADE)
        # 2. Todas las vulnerabilities (por vulnerabilities.scan_result_id -> scan_results.id ON DELETE CASCADE)
        # 3. Todos los enrichments (por enrichments.scan_result_id -> scan_results.id ON DELETE CASCADE)
        cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        
        # Limpiar hosts huérfanos (que ya no tienen ningún scan_result)
        # Esto es necesario porque hosts no tiene CASCADE (un host puede tener múltiples escaneos)
        for host_id in host_ids:
            remaining_results = cursor.execute("""
                SELECT COUNT(*) FROM scan_results WHERE host_id = ?
            """, (host_id,)).fetchone()[0]
            if remaining_results == 0:
                cursor.execute("DELETE FROM hosts WHERE id = ?", (host_id,))
        
        # Eliminar directorio del escaneo
        scan_dir = self.get_scan_directory(org_name, location, scan_id)
        if scan_dir and scan_dir.exists():
            try:
                shutil.rmtree(scan_dir)
            except Exception as e:
                print(f"Error eliminando directorio {scan_dir}: {e}")
        
        conn.commit()
        conn.close()
        return True
    
    def delete_location(self, organization: str, location: str) -> int:
        """Elimina una ubicación y todos sus escaneos."""
        import shutil
        
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys = ON")
        cursor = conn.cursor()
        
        # Obtener todos los escaneos de esta ubicación
        scans = cursor.execute("""
            SELECT id FROM scans 
            WHERE organization_name = ? AND location = ?
        """, (organization.upper(), location.upper())).fetchall()
        
        deleted_count = len(scans)
        scan_ids = [s[0] for s in scans]
        
        # Obtener todos los host_ids de estos escaneos
        if scan_ids:
            placeholders = ','.join('?' * len(scan_ids))
            host_ids = cursor.execute(f"""
                SELECT DISTINCT host_id FROM scan_results 
                WHERE scan_id IN ({placeholders})
            """, scan_ids).fetchall()
            host_ids = [h[0] for h in host_ids]
        else:
            host_ids = []
        
        # Eliminar escaneos - CASCADE eliminará automáticamente:
        # 1. Todos los scan_results (por scan_results.scan_id -> scans.id ON DELETE CASCADE)
        # 2. Todas las vulnerabilities (por vulnerabilities.scan_result_id -> scan_results.id ON DELETE CASCADE)
        # 3. Todos los enrichments (por enrichments.scan_result_id -> scan_results.id ON DELETE CASCADE)
        cursor.execute("""
            DELETE FROM scans 
            WHERE organization_name = ? AND location = ?
        """, (organization.upper(), location.upper()))
        
        # Eliminar hosts huérfanos (que no tienen ningún scan_result)
        for host_id in host_ids:
            remaining_results = cursor.execute("""
                SELECT COUNT(*) FROM scan_results WHERE host_id = ?
            """, (host_id,)).fetchone()[0]
            if remaining_results == 0:
                cursor.execute("DELETE FROM hosts WHERE id = ?", (host_id,))
        
        # Eliminar directorio de la ubicación
        location_dir = self.results_root / organization.upper() / location.upper()
        if location_dir.exists():
            try:
                shutil.rmtree(location_dir)
            except Exception as e:
                print(f"Error eliminando directorio {location_dir}: {e}")
        
        conn.commit()
        conn.close()
        return deleted_count
    
    def get_networks(self, organization: str) -> List[Dict]:
        """Obtiene las redes registradas para una organización."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, organization_name, system_name, network_name, network_range, created_at
                FROM networks
                WHERE organization_name = ?
                ORDER BY system_name, network_name
            """, (organization,))
            
            return [dict(row) for row in cursor.fetchall()]

    def add_network(self, organization: str, network_name: str, network_range: str, system_name: str = None) -> int:
        """Añade una red a la organización."""
        # Validar rango
        try:
            ipaddress.ip_network(network_range, strict=False)
        except ValueError as e:
            raise ValueError(f"Rango de red inválido: {e}")
            
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO networks (organization_name, system_name, network_name, network_range)
                VALUES (?, ?, ?, ?)
            """, (organization, system_name, network_name, network_range))
            return cursor.lastrowid

    def delete_network(self, network_id: int) -> bool:
        """Elimina una red registrada."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM networks WHERE id = ?", (network_id,))
            return cursor.rowcount > 0

    def delete_organization(self, organization: str) -> dict:
        """Elimina una organización completa y todos sus datos."""
        import shutil
        
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys = ON")
        cursor = conn.cursor()
        
        # Contar escaneos y ubicaciones
        scans_count = cursor.execute("""
            SELECT COUNT(*) FROM scans WHERE organization_name = ?
        """, (organization.upper(),)).fetchone()[0]
        
        locations = cursor.execute("""
            SELECT DISTINCT location FROM scans WHERE organization_name = ?
        """, (organization.upper(),)).fetchall()
        locations_count = len(locations)
        
        # Obtener todos los scan_ids de esta organización
        scan_ids = cursor.execute("""
            SELECT id FROM scans WHERE organization_name = ?
        """, (organization.upper(),)).fetchall()
        scan_ids = [s[0] for s in scan_ids]
        
        # Obtener todos los host_ids de estos escaneos
        if scan_ids:
            placeholders = ','.join('?' * len(scan_ids))
            host_ids = cursor.execute(f"""
                SELECT DISTINCT host_id FROM scan_results 
                WHERE scan_id IN ({placeholders})
            """, scan_ids).fetchall()
            host_ids = [h[0] for h in host_ids]
        else:
            host_ids = []
        
        # Eliminar todos los escaneos - CASCADE eliminará automáticamente:
        # 1. Todos los scan_results (por scan_results.scan_id -> scans.id ON DELETE CASCADE)
        # 2. Todas las vulnerabilities (por vulnerabilities.scan_result_id -> scan_results.id ON DELETE CASCADE)
        # 3. Todos los enrichments (por enrichments.scan_result_id -> scan_results.id ON DELETE CASCADE)
        cursor.execute("DELETE FROM scans WHERE organization_name = ?", (organization.upper(),))
        
        # Eliminar hosts huérfanos (que no tienen ningún scan_result)
        # Primero eliminar los hosts asociados a los escaneos eliminados
        for host_id in host_ids:
            remaining_results = cursor.execute("""
                SELECT COUNT(*) FROM scan_results WHERE host_id = ?
            """, (host_id,)).fetchone()[0]
            if remaining_results == 0:
                cursor.execute("DELETE FROM hosts WHERE id = ?", (host_id,))
        
        # También eliminar cualquier otro host huérfano que pueda quedar
        cursor.execute("""
            DELETE FROM hosts 
            WHERE id NOT IN (SELECT DISTINCT host_id FROM scan_results WHERE host_id IS NOT NULL)
        """)
        
        # Eliminar la organización
        cursor.execute("DELETE FROM organizations WHERE name = ?", (organization.upper(),))
        
        # Eliminar directorio completo de la organización
        org_dir = self.results_root / organization.upper()
        if org_dir.exists():
            try:
                shutil.rmtree(org_dir)
            except Exception as e:
                print(f"Error eliminando directorio {org_dir}: {e}")
        
        conn.commit()
        conn.close()
        
        return {
            "scans_deleted": scans_count,
            "locations_deleted": locations_count
        }
    
    def delete_all_data(self) -> dict:
        """Elimina TODOS los datos de la base de datos y archivos. OPERACIÓN CRÍTICA."""
        import shutil
        
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys = ON")
        cursor = conn.cursor()
        
        # Contar antes de eliminar
        orgs_count = cursor.execute("SELECT COUNT(*) FROM organizations").fetchone()[0]
        scans_count = cursor.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        hosts_count = cursor.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
        results_count = cursor.execute("SELECT COUNT(*) FROM scan_results").fetchone()[0]
        vulns_count = cursor.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
        enrichments_count = cursor.execute("SELECT COUNT(*) FROM enrichments").fetchone()[0]
        
        # Eliminar todas las tablas (en orden para respetar foreign keys)
        cursor.execute("DELETE FROM vulnerabilities")
        cursor.execute("DELETE FROM enrichments")
        cursor.execute("DELETE FROM scan_results")
        cursor.execute("DELETE FROM scans")
        cursor.execute("DELETE FROM hosts")
        cursor.execute("DELETE FROM organizations")
        
        # Eliminar todo el directorio de resultados
        if self.results_root.exists():
            try:
                # Mantener solo el directorio base, eliminar todo su contenido
                for item in self.results_root.iterdir():
                    if item.is_dir():
                        shutil.rmtree(item)
                    elif item.is_file() and item.name != "scans.db":
                        item.unlink()
            except Exception as e:
                print(f"Error eliminando directorios: {e}")
        
        conn.commit()
        conn.close()
        
        return {
            "organizations_deleted": orgs_count,
            "scans_deleted": scans_count,
            "hosts_deleted": hosts_count,
            "results_deleted": results_count,
            "vulnerabilities_deleted": vulns_count,
            "enrichments_deleted": enrichments_count
        }
    
    def cleanup_orphaned_data(self) -> dict:
        """Limpia datos huérfanos de la base de datos."""
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys = ON")
        cursor = conn.cursor()
        
        # Eliminar scan_results huérfanos (sin scan_id válido)
        orphaned_results = cursor.execute("""
            DELETE FROM scan_results 
            WHERE scan_id NOT IN (SELECT id FROM scans)
        """).rowcount
        
        # Eliminar vulnerabilidades huérfanas (sin scan_result_id válido)
        orphaned_vulns = cursor.execute("""
            DELETE FROM vulnerabilities 
            WHERE scan_result_id NOT IN (SELECT id FROM scan_results)
        """).rowcount
        
        # Eliminar enrichments huérfanos (sin scan_result_id válido)
        orphaned_enrichments = cursor.execute("""
            DELETE FROM enrichments 
            WHERE scan_result_id NOT IN (SELECT id FROM scan_results)
        """).rowcount
        
        # Eliminar hosts huérfanos (sin scan_results)
        orphaned_hosts = cursor.execute("""
            DELETE FROM hosts 
            WHERE id NOT IN (SELECT DISTINCT host_id FROM scan_results WHERE host_id IS NOT NULL)
        """).rowcount
        
        conn.commit()
        conn.close()
        
        return {
            "orphaned_results_deleted": orphaned_results,
            "orphaned_hosts_deleted": orphaned_hosts,
            "orphaned_vulns_deleted": orphaned_vulns,
            "orphaned_enrichments_deleted": orphaned_enrichments
        }

