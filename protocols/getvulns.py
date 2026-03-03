#!/usr/bin/env python3
# getvulns.py

import os
import logging

logger = logging.getLogger(__name__)

def get_vulns(host, port, vulns, folder_vuln_path):
    """Guarda información de vulnerabilidades en un archivo."""
    try:
        os.makedirs(folder_vuln_path, exist_ok=True)
        vulns_file = os.path.join(folder_vuln_path, f"{host}_{port}.txt")
        with open(vulns_file, 'w', encoding='utf-8') as f:
            f.write(str(vulns))
        logger.info(f"Vulnerabilidades guardadas para {host}:{port}")
        return vulns
    except PermissionError as e:
        logger.error(f"Error de permisos al guardar vulnerabilidades para {host}:{port}: {e}")
        return "Error: No se pudieron capturar las vulnerabilidades (permisos)"
    except Exception as e:
        logger.error(f"Error al guardar vulnerabilidades para {host}:{port}: {e}")
        return "Error: No se pudieron capturar las vulnerabilidades"
