"""
Base de datos SQLite para almacenar organizaciones y metadatos
"""
import sqlite3
import os
import logging
from typing import Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class Database:
    """Gestor de base de datos SQLite"""
    
    def __init__(self, db_path: str = 'arsenalot.db'):
        self.db_path = db_path
        self.init_database()
    
    def get_connection(self):
        """Obtener conexión a la base de datos"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def init_database(self):
        """Inicializar tablas de la base de datos"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Tabla de organizaciones
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS organizations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Tabla de escaneos
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_id INTEGER NOT NULL,
                location TEXT NOT NULL,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                progress INTEGER DEFAULT 0,
                hosts_found INTEGER DEFAULT 0,
                ports_found INTEGER DEFAULT 0,
                started_at TIMESTAMP,
                completed_at TIMESTAMP,
                error_message TEXT,
                FOREIGN KEY (organization_id) REFERENCES organizations(id)
            )
        ''')
        
        # Tabla de resultados (metadatos)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                organization_name TEXT NOT NULL,
                location TEXT NOT NULL,
                json_path TEXT NOT NULL,
                evidence_path TEXT,
                neo4j_imported BOOLEAN DEFAULT 0,
                imported_at TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info("Base de datos inicializada correctamente")
    
    def create_organization(self, name: str, description: Optional[str] = None) -> Dict:
        """Crear una nueva organización"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO organizations (name, description)
                VALUES (?, ?)
            ''', (name.upper(), description))
            
            org_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            # Crear estructura de directorios
            org_path = os.path.join('results', name.upper())
            os.makedirs(org_path, exist_ok=True)
            
            # Crear subdirectorios estándar
            subdirs = ['scans', 'evidence', 'reports', 'exports']
            for subdir in subdirs:
                os.makedirs(os.path.join(org_path, subdir), exist_ok=True)
            
            # Crear archivo README con información de la organización
            readme_path = os.path.join(org_path, 'README.md')
            with open(readme_path, 'w', encoding='utf-8') as f:
                f.write(f"# Organización: {name.upper()}\n\n")
                f.write(f"**Creada:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                if description:
                    f.write(f"**Descripción:** {description}\n\n")
                f.write("## Estructura de Directorios\n\n")
                f.write("- `scans/`: Resultados de escaneos organizados por ubicación\n")
                f.write("- `evidence/`: Evidencias y archivos XML de Nmap\n")
                f.write("- `reports/`: Reportes generados\n")
                f.write("- `exports/`: Archivos exportados\n")
            
            logger.info(f"Organización creada: {name} en {org_path}")
            return {
                'success': True,
                'id': org_id,
                'name': name.upper(),
                'path': org_path
            }
        except sqlite3.IntegrityError:
            return {
                'success': False,
                'error': 'La organización ya existe'
            }
        except Exception as e:
            logger.error(f"Error creando organización: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def sync_with_filesystem(self):
        """Sincronizar organizaciones del sistema de archivos con la base de datos"""
        try:
            results_dir = 'results'
            if not os.path.exists(results_dir):
                os.makedirs(results_dir, exist_ok=True)
                return
            
            # Obtener organizaciones del sistema de archivos
            fs_orgs = set()
            for item in os.listdir(results_dir):
                item_path = os.path.join(results_dir, item)
                if os.path.isdir(item_path):
                    fs_orgs.add(item.upper())
            
            # Obtener organizaciones de la base de datos
            db_orgs = {org['name'] for org in self.get_organizations()}
            
            # Agregar organizaciones que existen en el sistema de archivos pero no en la BD
            for org_name in fs_orgs:
                if org_name not in db_orgs:
                    logger.info(f"Sincronizando organización desde sistema de archivos: {org_name}")
                    self.create_organization(org_name, f"Organización sincronizada desde sistema de archivos")
        except Exception as e:
            logger.error(f"Error sincronizando con sistema de archivos: {e}")
    
    def get_organizations(self) -> List[Dict]:
        """Obtener todas las organizaciones"""
        try:
            # Sincronizar antes de obtener
            self.sync_with_filesystem()
            
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, name, description, created_at, updated_at
                FROM organizations
                ORDER BY name
            ''')
            
            rows = cursor.fetchall()
            conn.close()
            
            return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Error obteniendo organizaciones: {e}")
            return []
    
    def get_organization(self, name: str) -> Optional[Dict]:
        """Obtener una organización por nombre"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, name, description, created_at, updated_at
                FROM organizations
                WHERE name = ?
            ''', (name.upper(),))
            
            row = cursor.fetchone()
            conn.close()
            
            return dict(row) if row else None
        except Exception as e:
            logger.error(f"Error obteniendo organización: {e}")
            return None
    
    def create_scan(self, organization_name: str, location: str, target: str, 
                   scan_type: str) -> Optional[int]:
        """Crear un nuevo escaneo"""
        try:
            org = self.get_organization(organization_name)
            if not org:
                logger.error(f"Organización no encontrada: {organization_name}")
                return None
            
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO scans (organization_id, location, target, scan_type, started_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (org['id'], location.upper(), target, scan_type, datetime.now()))
            
            scan_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            return scan_id
        except Exception as e:
            logger.error(f"Error creando escaneo: {e}")
            return None
    
    def update_scan(self, scan_id: int, **kwargs):
        """Actualizar un escaneo"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            updates = []
            values = []
            
            for key, value in kwargs.items():
                if key in ['status', 'progress', 'hosts_found', 'ports_found', 'error_message']:
                    updates.append(f"{key} = ?")
                    values.append(value)
            
            if 'status' in kwargs and kwargs['status'] == 'completed':
                updates.append("completed_at = ?")
                values.append(datetime.now())
            
            if updates:
                values.append(scan_id)
                query = f"UPDATE scans SET {', '.join(updates)} WHERE id = ?"
                cursor.execute(query, values)
                conn.commit()
            
            conn.close()
        except Exception as e:
            logger.error(f"Error actualizando escaneo: {e}")
    
    def get_scans(self, organization_name: Optional[str] = None) -> List[Dict]:
        """Obtener escaneos"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            if organization_name:
                org = self.get_organization(organization_name)
                if not org:
                    return []
                
                cursor.execute('''
                    SELECT s.*, o.name as org_name
                    FROM scans s
                    JOIN organizations o ON s.organization_id = o.id
                    WHERE s.organization_id = ?
                    ORDER BY s.started_at DESC
                ''', (org['id'],))
            else:
                cursor.execute('''
                    SELECT s.*, o.name as org_name
                    FROM scans s
                    JOIN organizations o ON s.organization_id = o.id
                    ORDER BY s.started_at DESC
                ''')
            
            rows = cursor.fetchall()
            conn.close()
            
            return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Error obteniendo escaneos: {e}")
            return []

