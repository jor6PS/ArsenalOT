"""
Sistema de almacenamiento de resultados de escaneos
con Base de Datos + JSONs versionados por escaneo
"""

import sqlite3
import json
import zipfile
import shutil
import tempfile
import traceback
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, List
import ipaddress


def is_internal_ip(ip_str: str) -> bool:
    """
    Returns True if the IP should be treated as internal/non-public.
    Correctly handles: private RFC-1918, loopback (127.x), link-local (169.254.x),
    IPv6 loopback (::1), ULA (fc00::/7), and other reserved ranges.
    Python's built-in ip_obj.is_private does NOT include loopback in Python < 3.11.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
            or ip_obj.is_multicast
        )
    except ValueError:
        return False


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
                myip TEXT,
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

        # Tabla de dispositivos críticos
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS critical_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_name TEXT NOT NULL,
                name TEXT NOT NULL,
                ips TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (organization_name) REFERENCES organizations(name) ON DELETE CASCADE
            )
        """)

        
        # Agregar columnas nuevas si no existen (migración)
        for col in ['hostnames_json', 'mac_address', 'vendor', 'os_info_json', 'host_scripts_json', 'interfaces_json']:
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
        
        try:
            cursor.execute("ALTER TABLE scans ADD COLUMN myip TEXT")
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
            CREATE INDEX IF NOT EXISTS idx_scan_results_scan_host
            ON scan_results(scan_id, host_id)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_scan_results_port 
            ON scan_results(port, protocol)
        """)
        
        # Tabla de metadatos de host por escaneo (AISLAMIENTO)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS host_scan_metadata (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                host_id INTEGER NOT NULL,
                hostname TEXT,
                mac_address TEXT,
                vendor TEXT,
                os_info_json TEXT,
                host_scripts_json TEXT,
                interfaces_json TEXT,
                hostnames_json TEXT,
                last_seen TIMESTAMP,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
                FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
                UNIQUE(scan_id, host_id)
            )
        """)

        # Migración para columnas nuevas en host_scan_metadata si ya existe la tabla
        for col in ['last_seen', 'hostnames_json']:
            try:
                cursor.execute(f"ALTER TABLE host_scan_metadata ADD COLUMN {col} TIMESTAMP" if col == 'last_seen' else f"ALTER TABLE host_scan_metadata ADD COLUMN {col} TEXT")
            except sqlite3.OperationalError:
                pass

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_host_scan_meta_scan 
            ON host_scan_metadata(scan_id)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_host_scan_meta_host 
            ON host_scan_metadata(host_id)
        """)
        
        # Tabla de conversaciones pasivas
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS passive_conversations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                src_ip TEXT NOT NULL,
                src_mac TEXT,
                src_port INTEGER,
                dst_ip TEXT NOT NULL,
                dst_mac TEXT,
                dst_port INTEGER,
                protocol TEXT,
                last_seen TIMESTAMP NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_passive_conv_scan 
            ON passive_conversations(scan_id)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_passive_conv_ips
            ON passive_conversations(src_ip, dst_ip)
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS pwndoc_audits (
                org_name   TEXT PRIMARY KEY,
                audit_id   TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.commit()
        conn.close()
    
    def create_organization(self, name: str, description: str = ""):
        """Crea o actualiza una organización y su bitácora Obsidian."""
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL")
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO organizations (name, description)
            VALUES (?, ?)
        """, (name.upper(), description))
        conn.commit()
        conn.close()

        # Inicializar estructura de bitácora para la org (idempotente)
        try:
            from arsenal.core.bitacora_manager import BitacoraManager
            mgr = BitacoraManager(self.results_root)
            mgr.create_org_bitacora(name.upper())
        except Exception:
            pass  # No bloquear el flujo si falla la bitácora

        # Crear auditoría en PwnDoc de forma silenciosa en hilo aparte
        import threading as _threading
        _threading.Thread(
            target=self._ensure_pwndoc_audit,
            args=(name.upper(),),
            daemon=True,
        ).start()

    def _ensure_pwndoc_audit(self, org_name: str):
        """Crea la auditoría PwnDoc para la org si no existe (silencioso)."""
        try:
            if self.get_pwndoc_audit_id(org_name):
                return  # ya existe
            from arsenal.core.pwndoc_client import PwnDocClient
            audit_id = PwnDocClient().ensure_audit(org_name)
            self.save_pwndoc_audit_id(org_name, audit_id)
        except Exception:
            pass  # PwnDoc puede no estar disponible

    def get_pwndoc_audit_id(self, org_name: str):
        """Devuelve el audit_id de PwnDoc para la org, o None si no existe."""
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                "SELECT audit_id FROM pwndoc_audits WHERE UPPER(org_name) = UPPER(?)",
                (org_name,)
            ).fetchone()
            return row["audit_id"] if row else None
        finally:
            conn.close()

    def save_pwndoc_audit_id(self, org_name: str, audit_id: str):
        """Guarda o actualiza el audit_id de PwnDoc para la org."""
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            conn.execute(
                """INSERT INTO pwndoc_audits (org_name, audit_id)
                   VALUES (UPPER(?), ?)
                   ON CONFLICT(org_name) DO UPDATE SET audit_id = excluded.audit_id""",
                (org_name, audit_id)
            )
            conn.commit()
        finally:
            conn.close()
    
    def start_scan(self, organization: str, location: str, scan_type: str,
                   target_range: str, interface: str = None, myip: str = None,
                   nmap_command: str = None, created_by: str = None,
                   enable_version_detection: bool = False,
                   enable_vulnerability_scan: bool = False,
                   enable_screenshots: bool = False,
                   enable_source_code: bool = False,
                   scan_mode: str = 'active',
                   pcap_file: str = None,
                   started_at: Optional[datetime] = None) -> int:
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
             interface, myip, nmap_command, started_at, status, created_by,
             enable_version_detection, enable_vulnerability_scan,
             enable_screenshots, enable_source_code, scan_mode, pcap_file)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?)
        """, (organization.upper(), location.upper(), scan_type, target_range,
              interface, myip, nmap_command, started_at or datetime.now(), created_by,
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

    def _get_matching_network(self, organization: str, ip_str: str) -> Optional[Dict]:
        """Busca si una IP pertenece a una red de la organización definida por el usuario.
        Devuelve un diccionario con info de la red si hay match, de lo contrario None."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            networks = self.get_networks(organization)
            for net in networks:
                try:
                    net_obj = ipaddress.ip_network(net['network_range'], strict=False)
                    if ip_obj in net_obj:
                        return {
                            'range': net['network_range'],
                            'name': net['network_name'],
                            'system': net.get('system_name')
                        }
                except ValueError:
                    continue
        except ValueError:
            pass
        return None

    def _get_effective_subnet(self, organization: str, ip_str: str, scan_target_range: str = None) -> str:
        """Determina la subred más específica para una IP.
        Prioriza target_range del escaneo > cálculo /24 estándar.
        La definición lógica de redes se traslada a la exportación a Neo4j."""
            
        # 1. Intentar usar el target_range del escaneo (si no es 0.0.0.0/0)
        if scan_target_range:
            try:
                # Si hay múltiples rangos separados por espacio/coma, probar cada uno
                ranges = scan_target_range.replace(',', ' ').split()
                for r in ranges:
                    if r == "0.0.0.0/0": continue # Ignorar rango universal para esta lógica
                    try:
                        target_net = ipaddress.ip_network(r, strict=False)
                        if ipaddress.ip_address(ip_str) in target_net:
                            return str(target_net)
                    except ValueError:
                        continue
            except Exception:
                pass
        
        # 2. Fallback: Rangos privados estándar (RFC1918)
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_private:
                for rfc1918 in [
                    ipaddress.ip_network('192.168.0.0/16'),
                    ipaddress.ip_network('172.16.0.0/12'),
                    ipaddress.ip_network('10.0.0.0/8'),
                    ipaddress.ip_network('169.254.0.0/16'),
                    ipaddress.ip_network('fc00::/7'),
                    ipaddress.ip_network('fe80::/10'),
                ]:
                    if ip_obj in rfc1918:
                        return str(rfc1918)
                
                # 3. Cálculo "natural" /24 como último recurso para IPs privadas no RFC1918 (o para mayor detalle)
                # Devolver el /24 del segmento como "rango por defecto calculado"
                return str(ipaddress.ip_network(f"{ip_str}/24", strict=False))
        except ValueError:
            pass
            
        return "Unknown"
    
    def save_discovered_host(self, scan_id: int, host_ip: str,
                             discovery_method: str = 'host_discovery',
                             subnet: str = None,
                             timestamp: Optional[datetime] = None,
                             mac_address: str = None,
                             vendor: str = None,
                             hostname: str = None):
        """
        Guarda un host descubierto por host discovery (sin puertos aún).
        Acepta MAC, vendor y hostname cuando están disponibles (p.ej. desde arp-scan).
        IMPORTANTE: También crea un registro en scan_results con port=NULL para que
        el host aparezca en los resultados aunque no tenga puertos abiertos.
        """
        if not host_ip:
            return False

        try:
            ipaddress.ip_address(host_ip)
            is_private = is_internal_ip(host_ip)
        except ValueError:
            return False

        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys = ON")
        cursor = conn.cursor()

        scan = cursor.execute(
            "SELECT id, organization_name, target_range FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        if not scan:
            print(f"⚠️  El escaneo {scan_id} no existe")
            conn.close()
            return False

        organization_name = scan[1]
        target_range = scan[2]
        subnet = self._get_effective_subnet(organization_name, host_ip, target_range)

        discovered_at = timestamp or datetime.now()

        # Insertar o actualizar host — MAC y vendor enriquecen el registro existente
        cursor.execute("""
            INSERT INTO hosts (ip_address, hostname, mac_address, vendor, subnet, is_private,
                             first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip_address) DO UPDATE SET
                last_seen = MAX(last_seen, excluded.last_seen),
                hostname  = COALESCE(excluded.hostname, hostname),
                mac_address = COALESCE(excluded.mac_address, mac_address),
                vendor    = COALESCE(excluded.vendor, vendor),
                subnet = CASE
                    WHEN subnet IS NULL OR subnet IN ('10.0.0.0/8', '192.168.0.0/16', '172.16.0.0/12', 'Unknown')
                    THEN excluded.subnet
                    ELSE subnet
                END
        """, (host_ip, hostname, mac_address, vendor, subnet, is_private, discovered_at, discovered_at))

        host_id = cursor.lastrowid
        if not host_id:
            cursor.execute("SELECT id FROM hosts WHERE ip_address = ?", (host_ip,))
            row = cursor.fetchone()
            if row:
                host_id = row[0]
            else:
                print(f"⚠️  No se pudo obtener el host_id para {host_ip} en save_discovered_host")
                conn.close()
                return False

        try:
            existing = cursor.execute("""
                SELECT id FROM scan_results
                WHERE scan_id = ? AND host_id = ? AND port IS NULL
            """, (scan_id, host_id)).fetchone()

            if not existing:
                cursor.execute("""
                    INSERT INTO scan_results
                    (scan_id, host_id, port, protocol, state, discovery_method, discovered_at)
                    VALUES (?, ?, NULL, NULL, 'up', ?, ?)
                """, (scan_id, host_id, discovery_method, discovered_at))

            # AISLAMIENTO: metadata por escaneo (incluye MAC/vendor del momento)
            cursor.execute("""
                INSERT INTO host_scan_metadata
                    (scan_id, host_id, hostname, mac_address, vendor, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id, host_id) DO UPDATE SET
                    hostname    = COALESCE(excluded.hostname, hostname),
                    mac_address = COALESCE(excluded.mac_address, mac_address),
                    vendor      = COALESCE(excluded.vendor, vendor),
                    last_seen   = COALESCE(excluded.last_seen, last_seen)
            """, (scan_id, host_id, hostname, mac_address, vendor, discovered_at))

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
                        host_data: Dict = None, discovery_method: str = 'nmap',
                        timestamp: Optional[datetime] = None):
        """
        Guarda el resultado de un puerto de un host.
        Solo guarda direcciones IP privadas (filtra IPs públicas).
        
        Relaciones establecidas:
        - hosts: Almacena información del host (IP, hostname, MAC, OS, etc.)
        - scan_results: Vincula host + puerto + escaneo (host_id -> hosts.id, scan_id -> scans.id)
        - Las versiones se almacenan en scan_results.version
        - Los scripts de Nmap se almacenan en scan_results.scripts_json
        """
        # Validar IP
        if not host_ip:
            return False
            
        # Normalizar puerto a entero
        try:
            if port is not None:
                if isinstance(port, str):
                    if '/' in port:
                        port = int(port.split('/')[0])
                    else:
                        port = int(port)
                else:
                    port = int(port)
        except (ValueError, TypeError):
            port = None
            
        is_private = is_internal_ip(host_ip)
        
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys = ON")
        cursor = conn.cursor()
        
        # Validar que el escaneo existe y traer organización
        scan = cursor.execute("SELECT id, organization_name, target_range FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not scan:
            print(f"⚠️  El escaneo {scan_id} no existe")
            conn.close()
            return False
            
        # Determinar subnet (Match exacto > Target Range > /24 Fallback)
        organization_name = scan[1]
        target_range = scan[2]
        subnet = self._get_effective_subnet(organization_name, host_ip, target_range)
        
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
        
        # Determinar timestamp
        discovered_at = timestamp or datetime.now()

        # Insertar o actualizar host
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
                subnet = CASE 
                    WHEN subnet IS NULL OR subnet IN ('10.0.0.0/8', '192.168.0.0/16', '172.16.0.0/12', 'Unknown') 
                    THEN excluded.subnet 
                    ELSE subnet 
                END,
                os_info_json = COALESCE(excluded.os_info_json, os_info_json),
                host_scripts_json = COALESCE(excluded.host_scripts_json, host_scripts_json)
        """, (host_ip, hostname, hostnames_json, mac_address, vendor, subnet, is_private,
              os_info_json, host_scripts_json, discovered_at, discovered_at))
        
        host_id = cursor.lastrowid
        if not host_id:
            cursor.execute("SELECT id FROM hosts WHERE ip_address = ?", (host_ip,))
            row = cursor.fetchone()
            if row:
                host_id = row[0]
            else:
                print(f"⚠️  No se pudo obtener el host_id para {host_ip}")
                conn.close()
                return False

        # Preparar scripts JSON
        scripts_json = None
        if 'scripts' in service_data and service_data['scripts']:
            scripts_json = json.dumps(service_data['scripts'])
        
        # Insertar resultado del escaneo
        # Si port es None o 0, guardamos el host sin puertos (port=NULL en la BD)
        # Esto permite que hosts descubiertos sin puertos también aparezcan en los resultados
        port_value = port if port is not None and port > 0 else None
        protocol_value = protocol if port_value is not None else None
        
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
                discovered_at
            ))

            # AISLAMIENTO: Guardar metadatos específicos de este escaneo
            cursor.execute("""
                INSERT INTO host_scan_metadata 
                (scan_id, host_id, hostname, hostnames_json, mac_address, vendor, os_info_json, 
                 host_scripts_json, interfaces_json, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id, host_id) DO UPDATE SET
                    hostname = COALESCE(excluded.hostname, hostname),
                    hostnames_json = COALESCE(excluded.hostnames_json, hostnames_json),
                    mac_address = COALESCE(excluded.mac_address, mac_address),
                    vendor = COALESCE(excluded.vendor, vendor),
                    os_info_json = COALESCE(excluded.os_info_json, os_info_json),
                    host_scripts_json = COALESCE(excluded.host_scripts_json, host_scripts_json),
                    interfaces_json = COALESCE(excluded.interfaces_json, interfaces_json),
                    last_seen = COALESCE(excluded.last_seen, last_seen)
            """, (scan_id, host_id, hostname, hostnames_json, mac_address, vendor, os_info_json, 
                  host_scripts_json, None, discovered_at))
            
            conn.commit()
        except sqlite3.IntegrityError as e:
            print(f"⚠️  Error de integridad al guardar scan_result: {e}")
            conn.rollback()
            conn.close()
            return False
        
        conn.close()
        return True

    def save_host_results_bulk(self, scan_id: int, results_list: List[Dict]):
        """
        Guarda múltiples resultados de escaneo de forma eficiente en una sola transacción.
        Cada elemento de results_list debe ser un diccionario compatible con save_host_result.
        """
        if not results_list:
            return True
            
        conn = sqlite3.connect(str(self.db_path), timeout=60.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys = ON")
        cursor = conn.cursor()
        
        try:
            # Validar scan
            scan = cursor.execute("SELECT organization_name, target_range FROM scans WHERE id = ?", (scan_id,)).fetchone()
            if not scan:
                conn.close()
                return False
            organization_name = scan[0]
            target_range = scan[1]
            
            for res in results_list:
                host_ip = res.get('host_ip')
                if not host_ip:
                    continue
                is_private = is_internal_ip(host_ip)
                
                # Normalizar puerto
                port = res.get('port')
                try:
                    if port is not None:
                        if isinstance(port, str):
                            if '/' in port: port = int(port.split('/')[0])
                            else: port = int(port)
                        else: port = int(port)
                except (ValueError, TypeError):
                    port = None
                
                protocol = res.get('protocol', 'tcp')
                state = res.get('state', 'up')
                service_data = res.get('service_data', {})
                hostname = res.get('hostname')
                host_data = res.get('host_data')
                discovery_method = res.get('discovery_method', 'imported')
                
                # Subnet (Match exacto > Target Range > /24 Fallback)
                subnet = self._get_effective_subnet(organization_name, host_ip, target_range)
                
                # Host Info
                hostnames_json = None
                mac_address = None
                vendor = None
                os_info_json = None
                host_scripts_json = None
                
                if host_data:
                    if 'hostnames' in host_data: hostnames_json = json.dumps(host_data['hostnames'])
                    mac_address = host_data.get('mac_address')
                    vendor = host_data.get('vendor')
                    if 'os' in host_data and host_data['os']: os_info_json = json.dumps(host_data['os'])
                    if 'host_scripts' in host_data and host_data['host_scripts']: host_scripts_json = json.dumps(host_data['host_scripts'])
                
                # Timestamp: Priorizar el timestamp real del descubrimiento si se proporciona
                discovered_at = res.get('discovered_at') or res.get('timestamp') or datetime.now()

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
                        subnet = CASE
                            WHEN subnet IS NULL OR subnet IN ('10.0.0.0/8', '192.168.0.0/16', '172.16.0.0/12', 'Unknown')
                            THEN excluded.subnet
                            ELSE subnet
                        END,
                        os_info_json = COALESCE(excluded.os_info_json, os_info_json),
                        host_scripts_json = COALESCE(excluded.host_scripts_json, host_scripts_json)
                """, (host_ip, hostname, hostnames_json, mac_address, vendor, subnet, is_private,
                      os_info_json, host_scripts_json, discovered_at, discovered_at))

                # Always resolve host_id via SELECT — cursor.lastrowid is unreliable for
                # the UPDATE branch of an UPSERT in some Python/SQLite combinations.
                cursor.execute("SELECT id FROM hosts WHERE ip_address = ?", (host_ip,))
                row = cursor.fetchone()
                if not row:
                    continue
                host_id = row[0]
                
                scripts_json = None
                if 'scripts' in service_data and service_data['scripts']:
                    scripts_json = json.dumps(service_data['scripts'])
                
                port_value = port if port is not None and port > 0 else None
                protocol_value = protocol if port_value is not None else None
                

                cursor.execute("""
                    INSERT OR REPLACE INTO scan_results
                    (scan_id, host_id, port, protocol, state, service_name, product,
                     version, extrainfo, cpe, reason, reason_ttl, confidence, scripts_json, discovery_method, discovered_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    scan_id, host_id, port_value, protocol_value, state,
                    service_data.get('name') if port_value else None,
                    service_data.get('product') if port_value else None,
                    service_data.get('version') if port_value else None,
                    service_data.get('extrainfo') if port_value else None,
                    service_data.get('cpe') if port_value else None,
                    service_data.get('reason') if port_value else None,
                    service_data.get('reason_ttl') if port_value else None,
                    service_data.get('conf') if port_value else None,
                    scripts_json, discovery_method, discovered_at
                ))

                # AISLAMIENTO: Guardar metadatos por escaneo en lote
                cursor.execute("""
                    INSERT INTO host_scan_metadata 
                    (scan_id, host_id, hostname, hostnames_json, mac_address, vendor, os_info_json, 
                     host_scripts_json, interfaces_json, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(scan_id, host_id) DO UPDATE SET
                        hostname = COALESCE(excluded.hostname, hostname),
                        hostnames_json = COALESCE(excluded.hostnames_json, hostnames_json),
                        mac_address = COALESCE(excluded.mac_address, mac_address),
                        vendor = COALESCE(excluded.vendor, vendor),
                        os_info_json = COALESCE(excluded.os_info_json, os_info_json),
                        host_scripts_json = COALESCE(excluded.host_scripts_json, host_scripts_json),
                        interfaces_json = COALESCE(excluded.interfaces_json, interfaces_json),
                        last_seen = COALESCE(excluded.last_seen, last_seen)
                """, (scan_id, host_id, hostname, hostnames_json, mac_address, vendor, os_info_json, 
                      host_scripts_json, None, discovered_at))
            
            conn.commit()
            return True
        except Exception as e:
            print(f"❌ Error en guardado por lotes: {e}")
            print(traceback.format_exc())
            conn.rollback()
            return False
        finally:
            conn.close()
    
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
                     ports_count: int = None, error_message: str = None,
                     completed_at: Optional[datetime] = None):
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
            """, (status, completed_at or datetime.now(), hosts_count, ports_count, 
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

        # Auto-crear nota de bitácora para escaneos completados con éxito
        if not error_message:
            self._auto_bitacora_note(scan_id)

    def _auto_bitacora_note(self, scan_id: int):
        """Crea/actualiza silenciosamente la nota de bitácora del vector de acceso."""
        try:
            conn = sqlite3.connect(str(self.db_path), timeout=10.0)
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT organization_name, location, started_at, myip FROM scans WHERE id = ?",
                (scan_id,)
            ).fetchone()
            if not row:
                conn.close()
                return
            org      = row['organization_name']
            location = row['location']
            myip     = row['myip']
            # Cuántas IPs distintas hay para este (org, location) en BD
            distinct_ips = conn.execute(
                """SELECT COUNT(DISTINCT CASE WHEN myip IS NULL OR myip = ''
                                              THEN '__NOIP__' ELSE myip END) AS n
                   FROM scans
                   WHERE UPPER(organization_name) = UPPER(?)
                     AND UPPER(location) = UPPER(?)
                     AND status = 'completed'""",
                (org, location)
            ).fetchone()['n']
            conn.close()

            from arsenal.core.bitacora_manager import BitacoraManager
            mgr        = BitacoraManager(self.results_root)
            first_date = str(row['started_at'] or '')[:10]
            # Migrar nota legacy SOLO si esta es la única IP para esta location
            if distinct_ips == 1:
                mgr._migrate_legacy_note(org, location, myip)
            mgr.create_location_note(org, location, first_date, myip)
            mgr.update_location_visibility(org, location, self.db_path, myip)
        except Exception:
            pass  # Nunca bloquear el flujo del escaneo

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
                WHERE UPPER(organization_name) = UPPER(?)
                ORDER BY system_name, network_name
            """, (organization,))
            
            return [dict(row) for row in cursor.fetchall()]

    def add_network(self, organization: str, network_name: str, network_range: str, system_name: str = None) -> int:
        """Añade una red a la organización."""
        # Validar y normalizar rango
        try:
            # Usar strict=False para permitir rangos con bits de host (ej. 192.168.1.1/24)
            # y obtener el objeto de red real (ej. 192.168.1.0/24)
            net_obj = ipaddress.ip_network(network_range, strict=False)
            normalized_range = str(net_obj)
        except ValueError as e:
            raise ValueError(f"Rango de red inválido: {e}")
            
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL")
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO networks (organization_name, network_name, network_range, system_name)
                VALUES (?, ?, ?, ?)
            """, (organization.upper(), network_name, normalized_range, system_name))
            
            network_id = cursor.lastrowid
            
            # Auto-asignación retroactiva
            # Buscar todos los hosts que hayan sido escaneados bajo esta organización
            # y que caigan matemáticamente en el nuevo rango. Actualizarles "subnet".
            cursor.execute("""
                SELECT DISTINCT h.id, h.ip_address
                FROM hosts h
                JOIN scan_results sr ON sr.host_id = h.id
                JOIN scans s ON sr.scan_id = s.id
                WHERE s.organization_name = ?
            """, (organization.upper(),))
            
            org_hosts = cursor.fetchall()
            
            for h_id, h_ip in org_hosts:
                try:
                    ip_obj = ipaddress.ip_address(h_ip)
                    if ip_obj in net_obj:
                        cursor.execute("UPDATE hosts SET subnet = ? WHERE id = ?", (normalized_range, h_id))
                except ValueError:
                    pass
            
            conn.commit()
            return network_id
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()

    def update_network(self, network_id: int, network_name: str, network_range: str, system_name: str = None) -> bool:
        """Actualiza una red existente."""
        try:
            # Usar strict=False para permitir rangos con bits de host (ej. 192.168.1.1/24)
            net_obj = ipaddress.ip_network(network_range, strict=False)
            normalized_range = str(net_obj)
        except ValueError as e:
            raise ValueError(f"Rango de red inválido: {e}")

        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE networks
                SET network_name = ?, network_range = ?, system_name = ?
                WHERE id = ?
            """, (network_name, normalized_range, system_name, network_id))
            
            rows = cursor.rowcount
            
            # Retroactive assignment si se actualizó
            if rows > 0:
                cursor.execute("SELECT organization_name FROM networks WHERE id = ?", (network_id,))
                org_row = cursor.fetchone()
                if org_row:
                    organization = org_row[0]
                    cursor.execute("""
                        SELECT DISTINCT h.id, h.ip_address
                        FROM hosts h
                        JOIN scan_results sr ON sr.host_id = h.id
                        JOIN scans s ON sr.scan_id = s.id
                        WHERE s.organization_name = ?
                    """, (organization,))
                    
                    org_hosts = cursor.fetchall()
                    for h_id, h_ip in org_hosts:
                        try:
                            ip_obj = ipaddress.ip_address(h_ip)
                            if ip_obj in net_obj:
                                cursor.execute("UPDATE hosts SET subnet = ? WHERE id = ?", (normalized_range, h_id))
                        except ValueError:
                            pass
            
            conn.commit()
            return rows > 0
        finally:
            conn.close()

    def delete_network(self, network_id: int) -> bool:
        """Elimina una red registrada."""
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        try:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM networks WHERE id = ?", (network_id,))
            rows = cursor.rowcount
            conn.commit()
            return rows > 0
        finally:
            conn.close()

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
        
        # 3. Limpieza en Neo4j (Best-effort)
        try:
            self._cleanup_neo4j_organization(organization)
        except Exception as e:
            print(f"⚠️ Error limpiando Neo4j para organización {organization}: {e}")
        
        return {
            "scans_deleted": scans_count,
            "locations_deleted": locations_count,
            "neo4j_cleanup": "success"
        }

    def _cleanup_neo4j_organization(self, organization: str):
        """Helper para borrar datos de una organización en Neo4j."""
        import os
        from py2neo import Graph
        
        neo4j_user = os.getenv("NEO4J_USERNAME", "neo4j")
        neo4j_pass = os.getenv("NEO4J_PASSWORD", "neo4j1")
        neo4j_host = os.getenv("NEO4J_HOST", "localhost")
        
        try:
            graph = Graph(f"bolt://{neo4j_host}:7687", auth=(neo4j_user, neo4j_pass))
            cypher = """
            MATCH (o:ORGANIZACION {name: $org})
            OPTIONAL MATCH (o)-[:SCAN_TYPE]->(s)
            OPTIONAL MATCH (s)-[:EXECUTED_FROM|DETECTED_HOST]->(h:HOST)
            OPTIONAL MATCH (h)-[:HAS_SERVICE]->(svc:SERVICE)
            DETACH DELETE o, s, h, svc
            """
            graph.run(cypher, org=organization.upper())
        except Exception as e:
            print(f"⚠️ No se pudo conectar a Neo4j para limpieza: {e}")
    
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
        
        # ELIMINAR TODO EN NEO4J (Best-effort)
        try:
            import os
            from py2neo import Graph
            neo4j_user = os.getenv("NEO4J_USERNAME", "neo4j")
            neo4j_pass = os.getenv("NEO4J_PASSWORD", "neo4j1")
            neo4j_host = os.getenv("NEO4J_HOST", "localhost")
            graph = Graph(f"bolt://{neo4j_host}:7687", auth=(neo4j_user, neo4j_pass))
            graph.run("MATCH (n) DETACH DELETE n")
        except Exception as e:
            print(f"⚠️ Error limpiando Neo4j en delete_all: {e}")
        
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

    # ------------------------------------------------------------------ #
    #  DISPOSITIVOS CRÍTICOS                                               #
    # ------------------------------------------------------------------ #

    def get_critical_devices(self, organization: str) -> List[dict]:
        """Devuelve los dispositivos críticos de una organización."""
        conn = self._get_connection()
        rows = conn.execute(
            """SELECT id, organization_name, name, ips, reason, created_at
               FROM critical_devices
               WHERE UPPER(organization_name) = UPPER(?)
               ORDER BY created_at DESC""",
            (organization,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def add_critical_device(self, organization: str, name: str,
                            ips: str, reason: str) -> int:
        """Añade un dispositivo crítico. Devuelve el id insertado."""
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute(
            "INSERT OR IGNORE INTO organizations (name, description) VALUES (?, '')",
            (organization.upper(),)
        )
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO critical_devices (organization_name, name, ips, reason)
               VALUES (?, ?, ?, ?)""",
            (organization.upper(), name, ips.strip(), reason)
        )
        new_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return new_id

    def update_critical_device(self, device_id: int, name: str, ips: str, reason: str) -> bool:
        """Actualiza un dispositivo crítico."""
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE critical_devices
                SET name = ?, ips = ?, reason = ?
                WHERE id = ?
            """, (name, ips.strip(), reason, device_id))
            rows = cursor.rowcount
            conn.commit()
            return rows > 0
        finally:
            conn.close()

    def delete_critical_device(self, device_id: int) -> bool:
        """Elimina un dispositivo crítico por id. Devuelve True si se borró."""
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL")
        rows = conn.execute(
            "DELETE FROM critical_devices WHERE id = ?", (device_id,)
        ).rowcount
        conn.commit()
        conn.close()
        return rows > 0

    def get_critical_ips_for_org(self, organization: str) -> set:
        """Devuelve un set de todas las IPs críticas de la organización."""
        devices = self.get_critical_devices(organization)
        ips = set()
        for d in devices:
            for ip in d["ips"].split(","):
                ip = ip.strip()
                if ip:
                    ips.add(ip)
        return ips

    def add_host_interfaces(self, ip_address: str, interfaces: List[str], scan_id: int = None):
        """Agrega o actualiza la lista de interfaces de red adicionales para un host."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            interfaces_json = json.dumps(interfaces)
            
            # Actualizar tabla maestra de hosts
            cursor.execute("""
                UPDATE hosts 
                SET interfaces_json = ?, last_seen = CURRENT_TIMESTAMP
                WHERE ip_address = ?
            """, (interfaces_json, ip_address))
            
            # Si se proporciona scan_id, actualizar también los metadatos aislados del escaneo
            if scan_id:
                # Primero asegurar que existe el registro de metadata
                cursor.execute("SELECT id FROM hosts WHERE ip_address = ?", (ip_address,))
                host_row = cursor.fetchone()
                if host_row:
                    host_id = host_row[0]
                    cursor.execute("""
                        INSERT INTO host_scan_metadata (scan_id, host_id, interfaces_json, last_seen)
                        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                        ON CONFLICT(scan_id, host_id) DO UPDATE SET
                            interfaces_json = excluded.interfaces_json,
                            last_seen = excluded.last_seen
                    """, (scan_id, host_id, interfaces_json))
            
            conn.commit()
        finally:
            conn.close()


    def save_passive_conversation(self, scan_id: int, src_ip: str, dst_ip: str,
                                 src_port: int = None, dst_port: int = None,
                                 protocol: str = None, src_mac: str = None,
                                 dst_mac: str = None):
        """Guarda una conversación entre dos hosts detectada de forma pasiva."""
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL")
        cursor = conn.cursor()
        
        try:
            # Obtener info del escaneo
            scan = cursor.execute("SELECT organization_name, target_range FROM scans WHERE id = ?", (scan_id,)).fetchone()
            if not scan:
                conn.close()
                return
            org_name, target_range = scan

            # Intentar actualizar si ya existe la conversación en este escaneo
            # (IPs y puertos en cualquier dirección para simplificar, o dirección específica)
            # Por ahora guardamos dirección específica src -> dst
            now = datetime.now()
            cursor.execute("""
                INSERT INTO passive_conversations 
                (scan_id, src_ip, src_mac, src_port, dst_ip, dst_mac, dst_port, protocol, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (scan_id, src_ip, src_mac, src_port, dst_ip, dst_mac, dst_port, protocol, now))
            
            # AISLAMIENTO: Poblar metadata para ambos hosts
            for ip, mac in [(src_ip, src_mac), (dst_ip, dst_mac)]:
                if not ip: continue
                # Calcular subnet
                subnet = self._get_effective_subnet(org_name, ip, target_range)
                
                # Asegurar host global
                cursor.execute("""
                    INSERT INTO hosts (ip_address, first_seen, last_seen, is_private, subnet)
                    VALUES (?, ?, ?, 1, ?)
                    ON CONFLICT(ip_address) DO UPDATE SET 
                        last_seen = MAX(last_seen, excluded.last_seen),
                        subnet = CASE 
                            WHEN subnet IS NULL OR subnet IN ('10.0.0.0/8', '192.168.0.0/16', '172.16.0.0/12', 'Unknown') 
                            THEN excluded.subnet 
                            ELSE subnet 
                        END
                """, (ip, now, now, subnet))
                h_id = cursor.execute("SELECT id FROM hosts WHERE ip_address = ?", (ip,)).fetchone()[0]
                # Poblar metadata scan
                cursor.execute("""
                    INSERT INTO host_scan_metadata (scan_id, host_id, mac_address, last_seen)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(scan_id, host_id) DO UPDATE SET
                        mac_address = COALESCE(excluded.mac_address, mac_address),
                        last_seen = COALESCE(excluded.last_seen, last_seen)
                """, (scan_id, h_id, mac, now))

            conn.commit()
        except Exception as e:
            print(f"⚠️  Error guardando conversación pasiva: {e}")
            conn.rollback()
        finally:
            conn.close()

    def save_passive_conversations_bulk(self, scan_id: int, conversations: List[Dict]):
        """Guarda múltiples conversaciones pasivas de forma eficiente."""
        if not conversations:
            return True
            
        conn = sqlite3.connect(str(self.db_path), timeout=60.0)
        conn.execute("PRAGMA journal_mode=WAL")
        cursor = conn.cursor()
        
        try:
            # Obtener info del escaneo
            scan = cursor.execute("SELECT organization_name, target_range FROM scans WHERE id = ?", (scan_id,)).fetchone()
            if not scan:
                conn.close()
                return False
            org_name, target_range = scan

            now = datetime.now()
            # Preparar datos para executemany
            data = []
            for c in conversations:
                # Usar el timestamp real si viene en el objeto, si no usar 'now'
                c_timestamp = c.get('timestamp') or c.get('last_seen') or now
                data.append((
                    scan_id, c.get('src_ip'), c.get('src_mac'), c.get('src_port'),
                    c.get('dst_ip'), c.get('dst_mac'), c.get('dst_port'),
                    c.get('protocol'), c_timestamp
                ))
            
            cursor.executemany("""
                INSERT INTO passive_conversations 
                (scan_id, src_ip, src_mac, src_port, dst_ip, dst_mac, dst_port, protocol, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, data)

            # AISLAMIENTO: Poblar host_scan_metadata para hosts detectados pasivamente
            # Extraer IPs únicas y sus MACs de este lote
            unique_hosts = {} # ip -> {mac, last_seen}
            for c in conversations:
                c_now = c.get('timestamp') or c.get('last_seen') or now
                # Source
                sip = c.get('src_ip')
                smac = c.get('src_mac')
                if sip:
                    if sip not in unique_hosts or c_now > unique_hosts[sip]['last_seen']:
                        unique_hosts[sip] = {'mac': smac, 'last_seen': c_now}
                # Destination
                dip = c.get('dst_ip')
                dmac = c.get('dst_mac')
                if dip:
                    if dip not in unique_hosts or c_now > unique_hosts[dip]['last_seen']:
                        unique_hosts[dip] = {'mac': dmac, 'last_seen': c_now}

            for ip, info in unique_hosts.items():
                # Primero asegurar que el host existe en la tabla global para tener un host_id
                # (save_passive_conversation usualmente no crea el host si no existe, 
                # pero para aislamiento necesitamos que exista el host_id)
                # NOTA: save_discovered_host ya hace esto de forma segura.
                # Para simplificar y ser eficiente, usamos una query directa.
                subnet = self._get_effective_subnet(org_name, ip, target_range)
                cursor.execute("""
                    INSERT INTO hosts (ip_address, first_seen, last_seen, is_private, subnet)
                    VALUES (?, ?, ?, 1, ?)
                    ON CONFLICT(ip_address) DO UPDATE SET 
                        last_seen = MAX(last_seen, excluded.last_seen),
                        subnet = CASE 
                            WHEN subnet IS NULL OR subnet IN ('10.0.0.0/8', '192.168.0.0/16', '172.16.0.0/12', 'Unknown') 
                            THEN excluded.subnet 
                            ELSE subnet 
                        END
                """, (ip, info['last_seen'], info['last_seen'], subnet))
                
                h_id = cursor.execute("SELECT id FROM hosts WHERE ip_address = ?", (ip,)).fetchone()[0]
                
                cursor.execute("""
                    INSERT INTO host_scan_metadata (scan_id, host_id, mac_address, last_seen)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(scan_id, host_id) DO UPDATE SET
                        mac_address = COALESCE(excluded.mac_address, mac_address),
                        last_seen = COALESCE(excluded.last_seen, last_seen)
                """, (scan_id, h_id, info['mac'], info['last_seen']))

            conn.commit()
            return True
        except Exception as e:
            print(f"⚠️ Error en guardado masivo de conversaciones: {e}")
            conn.rollback()
            return False
        finally:
            conn.close()

    def get_passive_results(self, scan_id: int = None, organization: str = None, 
                           location: str = None) -> List[Dict]:
        """Obtiene resultados de conversaciones pasivas filtrados."""
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = """
            SELECT 
                pc.id, pc.scan_id,
                pc.src_ip, pc.src_mac, pc.src_port,
                pc.dst_ip, pc.dst_mac, pc.dst_port,
                pc.protocol, pc.last_seen,
                s.organization_name, s.location
            FROM passive_conversations pc
            JOIN scans s ON pc.scan_id = s.id
            WHERE 1=1
        """
        params = []
        if scan_id:
            query += " AND pc.scan_id = ?"
            params.append(scan_id)
        if organization:
            query += " AND UPPER(s.organization_name) = UPPER(?)"
            params.append(organization)
        if location:
            query += " AND UPPER(s.location) = UPPER(?)"
            params.append(location)

        query += " ORDER BY pc.last_seen DESC"
        
        try:
            rows = cursor.execute(query, params).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def get_passive_stats(self, scan_id: int) -> Dict[str, int]:
        """Obtiene estadísticas de un escaneo pasivo."""
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        cursor = conn.cursor()
        
        try:
            # Hosts únicos (origen o destino)
            hosts_query = """
                SELECT COUNT(DISTINCT ip) FROM (
                    SELECT src_ip as ip FROM passive_conversations WHERE scan_id = ?
                    UNION
                    SELECT dst_ip as ip FROM passive_conversations WHERE scan_id = ?
                )
            """
            hosts_count = cursor.execute(hosts_query, (scan_id, scan_id)).fetchone()[0]
            
            # Número de conversaciones
            conv_count = cursor.execute(
                "SELECT COUNT(*) FROM passive_conversations WHERE scan_id = ?", (scan_id,)
            ).fetchone()[0]
            
            return {
                "hosts_count": hosts_count,
                "conversations_count": conv_count
            }
        finally:
            conn.close()
