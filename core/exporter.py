"""
Módulo de exportación de evidencias y resultados de pentesting
Proporciona funcionalidades robustas para exportar todas las evidencias de forma organizada
"""
import os
import json
import shutil
import zipfile
import hashlib
import logging
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class EvidenceExporter:
    """Exportador de evidencias y resultados de pentesting"""
    
    def __init__(self):
        self.results_base = 'results'
    
    def calculate_file_hash(self, file_path: str) -> str:
        """Calcular hash SHA256 de un archivo"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"Error calculando hash de {file_path}: {e}")
            return ""
    
    def create_export_manifest(self, org_name: str, location: Optional[str] = None) -> Dict:
        """Crear manifiesto de exportación con metadatos completos"""
        manifest = {
            'export_info': {
                'exported_at': datetime.now().isoformat(),
                'export_version': '2.0',
                'exporter': 'ArsenalOT ScanHound'
            },
            'organization': org_name.upper(),
            'location': location.upper() if location else 'ALL',
            'files': [],
            'statistics': {
                'total_files': 0,
                'total_size': 0,
                'evidence_files': 0,
                'result_files': 0,
                'report_files': 0
            }
        }
        
        org_path = os.path.join(self.results_base, org_name.upper())
        if not os.path.exists(org_path):
            return manifest
        
        # Recopilar todos los archivos
        files_collected = []
        
        if location:
            # Exportar solo una ubicación específica
            location_path = os.path.join(org_path, 'scans', location.upper())
            if os.path.exists(location_path):
                files_collected.extend(self._collect_location_files(location_path, org_name, location))
        else:
            # Exportar toda la organización
            scans_path = os.path.join(org_path, 'scans')
            if os.path.exists(scans_path):
                for loc_dir in os.listdir(scans_path):
                    loc_path = os.path.join(scans_path, loc_dir)
                    if os.path.isdir(loc_path):
                        files_collected.extend(self._collect_location_files(loc_path, org_name, loc_dir))
            
            # Incluir evidencias generales, reportes y exports
            for subdir in ['evidence', 'reports', 'exports']:
                subdir_path = os.path.join(org_path, subdir)
                if os.path.exists(subdir_path):
                    files_collected.extend(self._collect_directory_files(subdir_path, subdir))
        
        # Procesar archivos y crear manifiesto
        total_size = 0
        evidence_count = 0
        result_count = 0
        report_count = 0
        
        for file_info in files_collected:
            file_path = file_info['full_path']
            if os.path.exists(file_path):
                file_size = os.path.getsize(file_path)
                file_hash = self.calculate_file_hash(file_path)
                
                file_entry = {
                    'path': file_info['relative_path'],
                    'size': file_size,
                    'sha256': file_hash,
                    'modified': datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat(),
                    'type': file_info.get('type', 'unknown')
                }
                
                manifest['files'].append(file_entry)
                total_size += file_size
                
                if file_info.get('type') == 'evidence':
                    evidence_count += 1
                elif file_info.get('type') == 'result':
                    result_count += 1
                elif file_info.get('type') == 'report':
                    report_count += 1
        
        manifest['statistics'] = {
            'total_files': len(manifest['files']),
            'total_size': total_size,
            'total_size_mb': round(total_size / (1024 * 1024), 2),
            'evidence_files': evidence_count,
            'result_files': result_count,
            'report_files': report_count
        }
        
        return manifest
    
    def _collect_location_files(self, location_path: str, org_name: str, location: str) -> List[Dict]:
        """Recopilar archivos de una ubicación específica"""
        files = []
        base_path = os.path.join(self.results_base, org_name.upper(), 'scans', location.upper())
        
        # Archivo de resultados principal
        result_file = os.path.join(location_path, 'scan_result.json')
        if os.path.exists(result_file):
            files.append({
                'full_path': result_file,
                'relative_path': f'scans/{location.upper()}/scan_result.json',
                'type': 'result'
            })
        
        # Evidencias XML de Nmap
        evidence_path = os.path.join(location_path, 'evidence')
        if os.path.exists(evidence_path):
            for file_name in os.listdir(evidence_path):
                file_path = os.path.join(evidence_path, file_name)
                if os.path.isfile(file_path):
                    files.append({
                        'full_path': file_path,
                        'relative_path': f'scans/{location.upper()}/evidence/{file_name}',
                        'type': 'evidence'
                    })
        
        # Metadatos de evidencias
        evidence_metadata = os.path.join(evidence_path, 'evidence_metadata.json')
        if os.path.exists(evidence_metadata):
            files.append({
                'full_path': evidence_metadata,
                'relative_path': f'scans/{location.upper()}/evidence/evidence_metadata.json',
                'type': 'metadata'
            })
        
        # Otros archivos en la ubicación (img, source, vuln, etc.)
        for subdir in ['img', 'source', 'vuln']:
            subdir_path = os.path.join(location_path, subdir)
            if os.path.exists(subdir_path):
                for file_name in os.listdir(subdir_path):
                    file_path = os.path.join(subdir_path, file_name)
                    if os.path.isfile(file_path):
                        files.append({
                            'full_path': file_path,
                            'relative_path': f'scans/{location.upper()}/{subdir}/{file_name}',
                            'type': 'evidence'
                        })
        
        return files
    
    def _collect_directory_files(self, directory_path: str, relative_base: str) -> List[Dict]:
        """Recopilar archivos de un directorio recursivamente"""
        files = []
        base_path = os.path.join(self.results_base, '')
        
        for root, dirs, filenames in os.walk(directory_path):
            for filename in filenames:
                full_path = os.path.join(root, filename)
                rel_path = os.path.relpath(full_path, self.results_base)
                
                file_type = 'other'
                if 'evidence' in rel_path.lower():
                    file_type = 'evidence'
                elif 'report' in rel_path.lower():
                    file_type = 'report'
                elif filename.endswith('.json'):
                    file_type = 'metadata'
                
                files.append({
                    'full_path': full_path,
                    'relative_path': rel_path,
                    'type': file_type
                })
        
        return files
    
    def export_to_zip(self, org_name: str, location: Optional[str] = None, 
                      output_path: Optional[str] = None, include_metadata: bool = True) -> Dict:
        """
        Exportar evidencias y resultados a un archivo ZIP
        
        Args:
            org_name: Nombre de la organización
            location: Ubicación específica (None para toda la organización)
            output_path: Ruta del archivo ZIP de salida (None para auto-generar)
            include_metadata: Incluir manifiesto y metadatos en el ZIP
        
        Returns:
            Dict con información de la exportación
        """
        try:
            # Crear manifiesto
            manifest = self.create_export_manifest(org_name, location)
            
            if not manifest['files']:
                return {
                    'success': False,
                    'error': 'No se encontraron archivos para exportar'
                }
            
            # Generar nombre de archivo si no se proporciona
            if not output_path:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                if location:
                    filename = f"export_{org_name.upper()}_{location.upper()}_{timestamp}.zip"
                else:
                    filename = f"export_{org_name.upper()}_ALL_{timestamp}.zip"
                
                exports_dir = os.path.join(self.results_base, org_name.upper(), 'exports')
                os.makedirs(exports_dir, exist_ok=True)
                output_path = os.path.join(exports_dir, filename)
            
            # Crear archivo ZIP
            zip_size = 0
            files_added = 0
            
            with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                # Añadir manifiesto
                if include_metadata:
                    manifest_json = json.dumps(manifest, indent=2, ensure_ascii=False)
                    zipf.writestr('MANIFEST.json', manifest_json)
                
                # Añadir archivos
                for file_info in manifest['files']:
                    file_path = file_info['full_path']
                    if os.path.exists(file_path):
                        try:
                            # Mantener estructura de directorios relativa
                            arcname = file_info['relative_path']
                            zipf.write(file_path, arcname)
                            files_added += 1
                            zip_size += os.path.getsize(file_path)
                        except Exception as e:
                            logger.warning(f"Error añadiendo {file_path} al ZIP: {e}")
                
                # Añadir README de la organización si existe
                org_readme = os.path.join(self.results_base, org_name.upper(), 'README.md')
                if os.path.exists(org_readme):
                    zipf.write(org_readme, 'README.md')
                
                # Añadir metadata.json de la organización si existe
                org_metadata = os.path.join(self.results_base, org_name.upper(), 'metadata.json')
                if os.path.exists(org_metadata) and include_metadata:
                    zipf.write(org_metadata, 'metadata.json')
            
            final_size = os.path.getsize(output_path)
            
            return {
                'success': True,
                'output_path': output_path,
                'filename': os.path.basename(output_path),
                'size': final_size,
                'size_mb': round(final_size / (1024 * 1024), 2),
                'files_count': files_added,
                'manifest': manifest,
                'compression_ratio': round((1 - final_size / zip_size) * 100, 2) if zip_size > 0 else 0
            }
        
        except Exception as e:
            logger.error(f"Error exportando a ZIP: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def export_to_directory(self, org_name: str, output_dir: str, 
                           location: Optional[str] = None) -> Dict:
        """
        Exportar evidencias a un directorio (útil para copias de seguridad)
        
        Args:
            org_name: Nombre de la organización
            output_dir: Directorio de destino
            location: Ubicación específica (None para toda la organización)
        
        Returns:
            Dict con información de la exportación
        """
        try:
            manifest = self.create_export_manifest(org_name, location)
            
            if not manifest['files']:
                return {
                    'success': False,
                    'error': 'No se encontraron archivos para exportar'
                }
            
            # Crear directorio de salida
            export_base = os.path.join(output_dir, org_name.upper())
            if location:
                export_base = os.path.join(export_base, location.upper())
            
            os.makedirs(export_base, exist_ok=True)
            
            # Copiar archivos manteniendo estructura
            files_copied = 0
            total_size = 0
            
            for file_info in manifest['files']:
                source_path = file_info['full_path']
                if os.path.exists(source_path):
                    dest_path = os.path.join(export_base, file_info['relative_path'])
                    dest_dir = os.path.dirname(dest_path)
                    os.makedirs(dest_dir, exist_ok=True)
                    
                    try:
                        shutil.copy2(source_path, dest_path)
                        files_copied += 1
                        total_size += os.path.getsize(source_path)
                    except Exception as e:
                        logger.warning(f"Error copiando {source_path}: {e}")
            
            # Guardar manifiesto
            manifest_path = os.path.join(export_base, 'MANIFEST.json')
            with open(manifest_path, 'w', encoding='utf-8') as f:
                json.dump(manifest, f, indent=2, ensure_ascii=False)
            
            return {
                'success': True,
                'output_dir': export_base,
                'files_count': files_copied,
                'total_size': total_size,
                'total_size_mb': round(total_size / (1024 * 1024), 2),
                'manifest': manifest
            }
        
        except Exception as e:
            logger.error(f"Error exportando a directorio: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def verify_export_integrity(self, zip_path: str) -> Dict:
        """Verificar integridad de un archivo ZIP exportado"""
        try:
            if not os.path.exists(zip_path):
                return {
                    'valid': False,
                    'error': 'Archivo no encontrado'
                }
            
            with zipfile.ZipFile(zip_path, 'r') as zipf:
                # Verificar que el ZIP no esté corrupto
                bad_file = zipf.testzip()
                if bad_file:
                    return {
                        'valid': False,
                        'error': f'Archivo corrupto: {bad_file}'
                    }
                
                # Verificar que existe el manifiesto
                if 'MANIFEST.json' not in zipf.namelist():
                    return {
                        'valid': False,
                        'error': 'Manifiesto no encontrado en el ZIP'
                    }
                
                # Leer y verificar manifiesto
                manifest_data = zipf.read('MANIFEST.json')
                manifest = json.loads(manifest_data.decode('utf-8'))
                
                # Verificar hashes de archivos
                verified_files = 0
                failed_files = []
                
                for file_info in manifest.get('files', []):
                    if file_info['relative_path'] in zipf.namelist():
                        file_data = zipf.read(file_info['relative_path'])
                        calculated_hash = hashlib.sha256(file_data).hexdigest()
                        
                        if calculated_hash == file_info.get('sha256', ''):
                            verified_files += 1
                        else:
                            failed_files.append(file_info['relative_path'])
                
                return {
                    'valid': True,
                    'total_files': len(manifest.get('files', [])),
                    'verified_files': verified_files,
                    'failed_files': failed_files,
                    'manifest': manifest
                }
        
        except Exception as e:
            logger.error(f"Error verificando integridad: {e}")
            return {
                'valid': False,
                'error': str(e)
            }

