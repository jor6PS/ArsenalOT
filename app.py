"""
ArsenalOT - Aplicación Web para Pentesting IT/OT
Endpoints adicionales para artefactos y estimaciones
"""
from flask import Flask, request, jsonify, send_file, render_template
from datetime import datetime
import os
import json
import logging

# Estos endpoints se añaden al app.py principal
# Asegúrate de que app.py tenga todos los imports necesarios

# Importar scanner para el endpoint de escaneo
from core.scanner import NetworkScanner

logger = logging.getLogger(__name__)

# Adding new endpoints for viewing artifacts
@app.route('/api/artifacts/list', methods=['GET'])
def list_artifacts():
    """Listar todos los artefactos (screenshots, sources, vulns) de una organización/location"""
    try:
        org = request.args.get('org')
        location = request.args.get('location')
        
        if not org or not location:
            return jsonify({'error': 'Se requieren org y location'}), 400
        
        artifacts = {
            'screenshots': [],
            'sources': [],
            'vulnerabilities': []
        }
        
        base_path = os.path.join('results', org.upper(), 'scans', location.upper())
        
        # Listar screenshots
        img_path = os.path.join(base_path, 'img')
        if os.path.exists(img_path):
            for filename in os.listdir(img_path):
                if filename.endswith(('.png', '.jpg', '.jpeg')):
                    file_path = os.path.join(img_path, filename)
                    file_stat = os.stat(file_path)
                    # Extraer host y port del nombre (formato: host_port.png)
                    name_parts = filename.replace('.png', '').replace('.jpg', '').replace('.jpeg', '').split('_')
                    host = '_'.join(name_parts[:-1]) if len(name_parts) > 1 else name_parts[0]
                    port = name_parts[-1] if len(name_parts) > 1 else 'unknown'
                    
                    artifacts['screenshots'].append({
                        'filename': filename,
                        'host': host,
                        'port': port,
                        'size': file_stat.st_size,
                        'modified': datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
                        'url': f'/api/artifacts/view/screenshot?org={org}&location={location}&file={filename}'
                    })
        
        # Listar sources
        source_path = os.path.join(base_path, 'source')
        if os.path.exists(source_path):
            for filename in os.listdir(source_path):
                if filename.endswith('.txt'):
                    file_path = os.path.join(source_path, filename)
                    file_stat = os.stat(file_path)
                    name_parts = filename.replace('.txt', '').split('_')
                    host = '_'.join(name_parts[:-1]) if len(name_parts) > 1 else name_parts[0]
                    port = name_parts[-1] if len(name_parts) > 1 else 'unknown'
                    
                    artifacts['sources'].append({
                        'filename': filename,
                        'host': host,
                        'port': port,
                        'size': file_stat.st_size,
                        'modified': datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
                        'url': f'/api/artifacts/view/source?org={org}&location={location}&file={filename}'
                    })
        
        # Listar vulnerabilidades
        vuln_path = os.path.join(base_path, 'vuln')
        if os.path.exists(vuln_path):
            for filename in os.listdir(vuln_path):
                if filename.endswith('.txt'):
                    file_path = os.path.join(vuln_path, filename)
                    file_stat = os.stat(file_path)
                    name_parts = filename.replace('.txt', '').split('_')
                    host = '_'.join(name_parts[:-1]) if len(name_parts) > 1 else name_parts[0]
                    port = name_parts[-1] if len(name_parts) > 1 else 'unknown'
                    
                    artifacts['vulnerabilities'].append({
                        'filename': filename,
                        'host': host,
                        'port': port,
                        'size': file_stat.st_size,
                        'modified': datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
                        'url': f'/api/artifacts/view/vuln?org={org}&location={location}&file={filename}'
                    })
        
        return jsonify(artifacts)
    except Exception as e:
        logger.error(f"Error listando artefactos: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/artifacts/view/screenshot', methods=['GET'])
def view_screenshot():
    """Ver una captura de pantalla"""
    try:
        org = request.args.get('org')
        location = request.args.get('location')
        filename = request.args.get('file')
        
        if not all([org, location, filename]):
            return jsonify({'error': 'Parámetros incompletos'}), 400
        
        file_path = os.path.join('results', org.upper(), 'scans', location.upper(), 'img', filename)
        
        if not os.path.exists(file_path) or '..' in filename:
            return jsonify({'error': 'Archivo no encontrado'}), 404
        
        return send_file(file_path, mimetype='image/png')
    except Exception as e:
        logger.error(f"Error sirviendo screenshot: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/artifacts/view/source', methods=['GET'])
def view_source():
    """Ver código fuente HTML"""
    try:
        org = request.args.get('org')
        location = request.args.get('location')
        filename = request.args.get('file')
        
        if not all([org, location, filename]):
            return jsonify({'error': 'Parámetros incompletos'}), 400
        
        file_path = os.path.join('results', org.upper(), 'scans', location.upper(), 'source', filename)
        
        if not os.path.exists(file_path) or '..' in filename:
            return jsonify({'error': 'Archivo no encontrado'}), 404
        
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        return jsonify({
            'content': content,
            'filename': filename,
            'size': len(content)
        })
    except Exception as e:
        logger.error(f"Error leyendo source: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/artifacts/view/vuln', methods=['GET'])
def view_vuln():
    """Ver información de vulnerabilidades"""
    try:
        org = request.args.get('org')
        location = request.args.get('location')
        filename = request.args.get('file')
        
        if not all([org, location, filename]):
            return jsonify({'error': 'Parámetros incompletos'}), 400
        
        file_path = os.path.join('results', org.upper(), 'scans', location.upper(), 'vuln', filename)
        
        if not os.path.exists(file_path) or '..' in filename:
            return jsonify({'error': 'Archivo no encontrado'}), 404
        
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        return jsonify({
            'content': content,
            'filename': filename,
            'size': len(content)
        })
    except Exception as e:
        logger.error(f"Error leyendo vulnerabilidades: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/estimate', methods=['GET'])
def estimate_scan():
    """Estimar duración de un escaneo considerando opciones seleccionadas"""
    try:
        rango = request.args.get('rango')
        scan_type = request.args.get('scan_type')
        hostdiscovery = request.args.get('hostdiscovery', 'false').lower() == 'true'
        
        # Opciones configurables
        enable_ot = request.args.get('enable_ot', 'false').lower() == 'true'
        enable_versions = request.args.get('enable_versions', 'true').lower() == 'true'
        enable_screenshots = request.args.get('enable_screenshots', 'false').lower() == 'true'
        enable_source = request.args.get('enable_source', 'false').lower() == 'true'
        enable_vulns = request.args.get('enable_vulns', 'false').lower() == 'true'
        
        if not rango or not scan_type:
            return jsonify({'error': 'Se requieren rango y scan_type'}), 400
        
        scanner = NetworkScanner()
        estimate = scanner.estimate_scan_duration(
            rango, scan_type, hostdiscovery,
            enable_ot=enable_ot,
            enable_versions=enable_versions,
            enable_screenshots=enable_screenshots,
            enable_source=enable_source,
            enable_vulns=enable_vulns
        )
        
        return jsonify(estimate)
    except Exception as e:
        logger.error(f"Error estimando escaneo: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/neo4j/query', methods=['POST'])
def execute_neo4j_query():
    """Ejecutar una consulta de Neo4j y devolver resultados"""
    try:
        from py2neo import Graph
        import json
        
        data = request.get_json()
        query = data.get('query')
        parameters = data.get('parameters', {})
        org = data.get('org')
        
        if not query:
            return jsonify({'error': 'Se requiere una consulta'}), 400
        
        # Obtener información de conexión de Neo4j
        # Por defecto, usar localhost:7687 con usuario/contraseña neo4j
        bolt_url = data.get('bolt_url', 'bolt://localhost:7687')
        username = data.get('username', 'neo4j')
        password = data.get('password', 'neo4j')
        
        # Reemplazar parámetros en la consulta si hay organización
        if org:
            # Reemplazar $neodash_org_org con la organización actual
            query = query.replace('$neodash_org_org', f"'{org.upper()}'")
            if 'neodash_org_org' in parameters:
                parameters['neodash_org_org'] = org.upper()
        
        # Conectar a Neo4j
        graph = Graph(bolt_url, auth=(username, password))
        
        # Ejecutar consulta
        result = graph.run(query, parameters)
        
        # Procesar resultados
        records = []
        for record in result:
            record_dict = {}
            for key in record.keys():
                value = record[key]
                # Convertir nodos y relaciones a diccionarios
                if hasattr(value, '__class__'):
                    if value.__class__.__name__ == 'Node':
                        record_dict[key] = {
                            'type': 'node',
                            'labels': list(value.labels),
                            'properties': dict(value)
                        }
                    elif value.__class__.__name__ == 'Relationship':
                        record_dict[key] = {
                            'type': 'relationship',
                            'type_name': value.type,
                            'properties': dict(value)
                        }
                    elif value.__class__.__name__ == 'Path':
                        # Para grafos, devolver estructura especial
                        record_dict[key] = {
                            'type': 'path',
                            'nodes': [{'labels': list(n.labels), 'properties': dict(n)} for n in value.nodes],
                            'relationships': [{'type': r.type, 'properties': dict(r)} for r in value.relationships]
                        }
                    else:
                        record_dict[key] = value
                else:
                    record_dict[key] = value
            records.append(record_dict)
        
        return jsonify({
            'success': True,
            'records': records,
            'count': len(records)
        })
        
    except Exception as e:
        logger.error(f"Error ejecutando consulta Neo4j: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/dashboard/config', methods=['GET'])
def get_dashboard_config():
    """Obtener configuración del dashboard.json"""
    try:
        dashboard_path = 'dashboard.json'
        if not os.path.exists(dashboard_path):
            return jsonify({'error': 'dashboard.json no encontrado'}), 404
        
        with open(dashboard_path, 'r', encoding='utf-8') as f:
            dashboard_config = json.load(f)
        
        return jsonify(dashboard_config)
    except Exception as e:
        logger.error(f"Error leyendo dashboard.json: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/pentesting/<org>/reconocimiento/dashboard')
def dashboard_page(org):
    """Página del dashboard con consultas de Neo4j"""
    return render_template('dashboard.html', org=org)

@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """Iniciar un nuevo escaneo con opciones configurables"""
    try:
        data = request.get_json()
        
        # Validar datos requeridos
        required_fields = ['rango', 'org', 'desde', 'scan_type']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Campo requerido faltante: {field}'}), 400
        
        # Extraer opciones de escaneo
        rango = data['rango']
        org = data['org']
        desde = data['desde']
        scan_type = data['scan_type']
        hostdiscovery = data.get('hostdiscovery', False)
        interfaz = data.get('interfaz', 'eth0')
        custom_args = data.get('custom_args', '')
        
        # Opciones configurables
        enable_ot = data.get('enable_ot', False)
        enable_versions = data.get('enable_versions', True)
        enable_screenshots = data.get('enable_screenshots', False)
        enable_source = data.get('enable_source', False)
        enable_vulns = data.get('enable_vulns', False)
        
        # Crear scanner y ejecutar escaneo
        scanner = NetworkScanner()
        
        # Nota: Este endpoint asume que hay un sistema de ejecución en background
        # Si no existe, necesitarás implementarlo o usar threading
        # Por ahora, ejecutamos el escaneo directamente (bloqueante)
        # En producción, deberías usar threading o celery
        
        result = scanner.scan(
            rango=rango,
            org=org,
            desde=desde,
            scan_type=scan_type,
            hostdiscovery=hostdiscovery,
            interfaz=interfaz,
            custom_args=custom_args,
            enable_ot=enable_ot,
            enable_versions=enable_versions,
            enable_screenshots=enable_screenshots,
            enable_source=enable_source,
            enable_vulns=enable_vulns
        )
        
        if result.get('success'):
            return jsonify({
                'success': True,
                'scan_id': f"{org}_{desde}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                'message': 'Escaneo iniciado correctamente',
                'result': result
            })
        else:
            return jsonify({
                'success': False,
                'error': result.get('error', 'Error desconocido')
            }), 500
            
    except Exception as e:
        logger.error(f"Error iniciando escaneo: {e}")
        return jsonify({'error': str(e)}), 500
