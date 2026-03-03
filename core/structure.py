"""
Gestor de estructura de directorios para organizaciones
"""
import os
import json
import logging
from datetime import datetime
from typing import Dict, Optional

logger = logging.getLogger(__name__)

class OrganizationStructure:
    """Gestiona la estructura de directorios y archivos de una organización"""
    
    @staticmethod
    def create_organization_structure(org_name: str, description: Optional[str] = None) -> Dict:
        """
        Crear estructura completa de directorios para una organización
        
        Estructura:
        results/
        └── ORG_NAME/
            ├── README.md
            ├── metadata.json
            ├── scans/
            │   └── LOCATION/
            │       ├── scan_result.json
            │       └── evidence/
            │           └── nmap_scan_TIMESTAMP.xml
            ├── evidence/
            ├── reports/
            └── exports/
        """
        org_path = os.path.join('results', org_name.upper())
        
        try:
            # Directorio principal
            os.makedirs(org_path, exist_ok=True)
            
            # Subdirectorios
            subdirs = {
                'scans': 'Escaneos organizados por ubicación',
                'evidence': 'Evidencias y archivos XML de Nmap',
                'reports': 'Reportes generados',
                'exports': 'Archivos exportados'
            }
            
            for subdir, desc in subdirs.items():
                os.makedirs(os.path.join(org_path, subdir), exist_ok=True)
            
            # Archivo README
            readme_content = f"""# Organización: {org_name.upper()}

**Creada:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

{f'**Descripción:** {description}' if description else ''}

## Estructura de Directorios

- `scans/`: Resultados de escaneos organizados por ubicación (Punto de Escaneo)
  - Cada ubicación tiene su propia carpeta
  - Contiene `scan_result.json` con los resultados
  - Subcarpeta `evidence/` con archivos XML de Nmap
  
- `evidence/`: Evidencias adicionales y archivos de respaldo

- `reports/`: Reportes generados en diferentes formatos

- `exports/`: Archivos exportados para compartir o respaldar

## Formato de Resultados

Los resultados se almacenan en `scans/LOCATION/scan_result.json` con la siguiente estructura:

```json
{{
  "ORG_NAME": {{
    "LOCATION": {{
      "SUBNET": {{
        "IP": {{
          "PORT": {{
            "service": "...",
            "version": "...",
            "state": "...",
            ...
          }}
        }}
      }}
    }}
  }}
}}
```

## Metadatos

La información de la organización se almacena en `metadata.json`.
"""
            
            with open(os.path.join(org_path, 'README.md'), 'w', encoding='utf-8') as f:
                f.write(readme_content)
            
            # Archivo de metadatos mejorado
            metadata = {
                'name': org_name.upper(),
                'description': description,
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat(),
                'structure_version': '2.0',
                'locations': [],
                'statistics': {
                    'total_scans': 0,
                    'total_hosts': 0,
                    'total_ports': 0,
                    'total_evidence_files': 0
                },
                'export_info': {
                    'last_export': None,
                    'export_count': 0
                }
            }
            
            with open(os.path.join(org_path, 'metadata.json'), 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Estructura creada para organización: {org_name}")
            return {
                'success': True,
                'path': org_path,
                'structure': {
                    'scans': os.path.join(org_path, 'scans'),
                    'evidence': os.path.join(org_path, 'evidence'),
                    'reports': os.path.join(org_path, 'reports'),
                    'exports': os.path.join(org_path, 'exports')
                }
            }
        except Exception as e:
            logger.error(f"Error creando estructura para {org_name}: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    @staticmethod
    def get_scan_path(org_name: str, location: str) -> str:
        """Obtener ruta del escaneo para una organización y ubicación"""
        return os.path.join('results', org_name.upper(), 'scans', location.upper())
    
    @staticmethod
    def get_evidence_path(org_name: str, location: str) -> str:
        """Obtener ruta de evidencias para un escaneo"""
        return os.path.join('results', org_name.upper(), 'scans', location.upper(), 'evidence')
    
    @staticmethod
    def get_result_file_path(org_name: str, location: str) -> str:
        """Obtener ruta del archivo de resultados"""
        return os.path.join('results', org_name.upper(), 'scans', location.upper(), 'scan_result.json')
    
    @staticmethod
    def ensure_location_structure(org_name: str, location: str):
        """Asegurar que existe la estructura para una ubicación"""
        scan_path = OrganizationStructure.get_scan_path(org_name, location)
        evidence_path = OrganizationStructure.get_evidence_path(org_name, location)
        
        os.makedirs(scan_path, exist_ok=True)
        os.makedirs(evidence_path, exist_ok=True)
        
        return {
            'scan_path': scan_path,
            'evidence_path': evidence_path,
            'result_file': OrganizationStructure.get_result_file_path(org_name, location)
        }

