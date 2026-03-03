import subprocess
import re
import socket
import ipaddress
import concurrent.futures
import platform
import logging

logger = logging.getLogger(__name__)

def obtener_ip_local():
    """Obtiene la IP local de la máquina."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('10.254.254.254', 1))
            return s.getsockname()[0]
    except Exception as e:
        logger.warning(f"No se pudo obtener IP local automáticamente: {e}")
        return '127.0.0.1'

def escanear_arp_scan(interfaz, rango):
    """Ejecuta un escaneo ARP en la interfaz y rango especificado.
    Solo funciona en Linux con arp-scan instalado."""
    if platform.system() != 'Linux':
        logger.warning("ARP scan solo está disponible en Linux")
        return ""
    
    comando = ["arp-scan", "--interface", interfaz, rango]
    # Intentar con sudo primero, luego sin sudo
    for cmd_prefix in [["sudo"], []]:
        try:
            full_cmd = cmd_prefix + comando
            result = subprocess.check_output(
                full_cmd, 
                stderr=subprocess.STDOUT, 
                text=True,
                timeout=60
            )
            return result
        except subprocess.CalledProcessError as e:
            if cmd_prefix:  # Si falló con sudo, intentar sin sudo
                continue
            logger.warning(f"Error ejecutando arp-scan: {e.output if hasattr(e, 'output') else str(e)}")
            return e.output if hasattr(e, 'output') else ""
        except FileNotFoundError:
            logger.warning("arp-scan no está instalado. Instálalo con: sudo apt-get install arp-scan")
            return ""
        except subprocess.TimeoutExpired:
            logger.warning("arp-scan excedió el tiempo de espera")
            return ""
        except Exception as e:
            logger.error(f"Error inesperado en arp-scan: {e}")
            return ""
    
    return ""

def escanear_ping_concurrente(rango, num_threads=10):
    """Escanea una red mediante ping de forma concurrente.
    Compatible con Windows y Linux."""
    def ping_ip(ip):
        try:
            system = platform.system()
            if system == 'Windows':
                # Windows usa -n en lugar de -c y -w en lugar de -W
                output = subprocess.check_output(
                    ['ping', '-n', '1', '-w', '1000', str(ip)], 
                    stderr=subprocess.STDOUT, 
                    text=True,
                    timeout=2
                )
                # Windows muestra "TTL" en la salida cuando hay respuesta
                return str(ip) if "TTL=" in output or "TTL =" in output else None
            else:
                # Linux/Unix
                output = subprocess.check_output(
                    ['ping', '-c', '1', '-W', '1', str(ip)], 
                    stderr=subprocess.STDOUT, 
                    text=True,
                    timeout=2
                )
                return str(ip) if "1 packets transmitted, 1 received, 0% packet loss" in output else None
        except subprocess.CalledProcessError:
            return None
        except subprocess.TimeoutExpired:
            return None
        except Exception as e:
            logger.debug(f"Error al hacer ping a {ip}: {e}")
            return None
    
    try:
        network = ipaddress.IPv4Network(rango, strict=False)
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            return {ip for ip in executor.map(ping_ip, network.hosts()) if ip}
    except ValueError as e:
        logger.error(f"Rango de red inválido {rango}: {e}")
        return set()
    except Exception as e:
        logger.error(f"Error inesperado en ping concurrente: {e}")
        return set()

def extraer_ips(output):
    """Extrae direcciones IP de una cadena de salida."""
    if not output:
        return set()
    return set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', output))
