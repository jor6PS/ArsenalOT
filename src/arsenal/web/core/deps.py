from arsenal.core.storage import ScanStorage
import threading
import subprocess
from typing import Dict

# Instancia global de acceso a la base de datos
storage = ScanStorage()

# Diccionarios globales para control de procesos asíncronos
running_scans: Dict[str, threading.Thread] = {}
running_processes: Dict[str, subprocess.Popen] = {}
