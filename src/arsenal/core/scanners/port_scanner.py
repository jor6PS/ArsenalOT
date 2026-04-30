"""
Módulo mejorado de escaneo de puertos con integración Nmap y técnicas avanzadas.

Incluye:
- Integración con Nmap (múltiples técnicas de escaneo)
- Escaneo de puertos OT (Operational Technology) - Sistemas industriales/SCADA
- Escaneo de puertos IT comunes - Servicios informáticos estándar
- Detección de versiones de servicios
- Escaneo de vulnerabilidades con NSE scripts
- Optimización según velocidad requerida
- Mejoras en técnicas de escaneo (multithreading, stealth scanning)
"""

import subprocess
import tempfile
import os
import socket
import threading
from typing import List, Optional, Dict, Set
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


# Lista completa de puertos IT (Tecnologías de la Información)
# Servicios informáticos estándar comunes
IT_COMMON_PORTS = [
    # Servicios básicos
    21,      # FTP
    22,      # SSH
    23,      # Telnet
    25,      # SMTP
    53,      # DNS
    80,      # HTTP
    110,     # POP3
    111,     # RPCbind
    135,     # MSRPC
    139,     # NetBIOS
    143,     # IMAP
    443,     # HTTPS
    445,     # SMB/CIFS
    993,     # IMAPS
    995,     # POP3S
    1433,    # MS SQL Server
    1521,    # Oracle
    1723,    # PPTP
    3306,    # MySQL
    3389,    # RDP
    5432,    # PostgreSQL
    5900,    # VNC
    8080,    # HTTP-Proxy
    8443,    # HTTPS-Alt
    8888,    # HTTP-Alt (Jupyter, etc)
    9090,    # HTTP-Alt
    27017,   # MongoDB
    5000,    # UPnP / Flask dev server
    27018,   # MongoDB shard
    27019,   # MongoDB config server
    50000,   # DB2
]

# Lista completa y enriquecida de puertos OT (Operational Technology)
# Protocolos industriales y sistemas SCADA/ICS
# NOTA: Los puertos comunes (21, 22, 23, 80, 443, 445, 5900, 8080) están en IT
# y se eliminarán automáticamente de esta lista
OT_PORTS_RAW = [
    # Protocolos industriales principales
    102,     # ISO-TSAP (Siemens S7)
    502,     # Modbus TCP
    789,     # Red Lion Crimson
    1089,    # FF HSE (Foundation Fieldbus)
    1090,    # FF HSE (Foundation Fieldbus)
    1091,    # FF HSE (Foundation Fieldbus)
    1911,    # Niagara Fox Protocol
    1962,    # PCWorx Protocol
    2222,    # EtherNet/IP
    2223,    # EtherNet/IP
    2404,    # IEC 60870-5-104
    4000,    # Emerson DeltaV
    4840,    # OPC UA Discovery
    4843,    # OPC UA Binary
    4911,    # Niagara Fox Protocol
    5901,    # VNC (dispositivos industriales)
    7890,    # Red Lion Crimson
    9600,    # Omron FINS
    10000,   # Network Data Management Protocol
    12320,   # Codesys
    12321,   # Codesys
    18245,   # GE SRTP (GE Fanuc)
    18246,   # GE SRTP (GE Fanuc)
    19999,   # DNP3 Secure Authentication
    20000,   # DNP3 (Distributed Network Protocol)
    20547,   # ProConOS (Phoenix Contact)
    34962,   # EtherNet/IP
    34963,   # EtherNet/IP
    34964,   # EtherNet/IP
    34980,   # EtherNet/IP
    44818,   # EtherNet/IP (Cisco/Allen-Bradley)
    46823,   # Niagara Fox Protocol
    46824,   # Niagara Fox Protocol
    47808,   # BACnet/IP
    47809,   # BACnet/IP (Alternative)
    47810,   # BACnet/IP (Alternative)
    47820,   # BACnet/IP (Alternative)
    55000,   # Emerson DeltaV
    55001,   # Emerson DeltaV
    55002,   # Emerson DeltaV
    55003,   # Emerson DeltaV
    55555,   # Mitsubishi Electric
    55556,   # Mitsubishi Electric
    55900,   # Profinet RT
    55901,   # Profinet RT
    55902,   # Profinet RT
    55903,   # Profinet RT
    61408,   # Schneider Electric PLC (Unity/Modicon)
    62351,   # Rockwell FactoryTalk
    62352,   # Rockwell FactoryTalk
    62353,   # Rockwell FactoryTalk
    62354,   # Rockwell FactoryTalk
    62355,   # Rockwell FactoryTalk
]

# Lista OT final eliminando duplicados de IT
IT_PORTS_SET = set(IT_COMMON_PORTS)
OT_PORTS = sorted([p for p in OT_PORTS_RAW if p not in IT_PORTS_SET])

# OT_PORTS ya está limpio (sin duplicados de IT)
# Mantenemos esta variable para compatibilidad con código existente
OT_PORTS_CLEANED = OT_PORTS


class PortScanner:
    """Clase mejorada para escaneo de puertos usando Nmap con técnicas avanzadas."""
    
    def __init__(self, output_file: Optional[str] = None, max_threads: int = 50):
        """
        Inicializa el escáner de puertos.
        
        Args:
            output_file: Archivo XML de salida para resultados Nmap
            max_threads: Número máximo de hilos para escaneos rápidos
        """
        self.output_file = output_file
        self.max_threads = max_threads
        self.current_process: Optional[subprocess.Popen] = None

    def _write_command_evidence(self, evidence_file: Optional[str], command: List[str],
                                stdout: str = "", stderr: str = "",
                                returncode: Optional[int] = None,
                                started_at: Optional[datetime] = None,
                                completed_at: Optional[datetime] = None):
        if not evidence_file:
            return
        try:
            completed_at = completed_at or datetime.now()
            lines = [
                f"started_at: {(started_at or completed_at).isoformat()}",
                f"completed_at: {completed_at.isoformat()}",
                f"command: {' '.join(command)}",
            ]
            if returncode is not None:
                lines.append(f"returncode: {returncode}")
            lines.extend(["", "stdout:", stdout or ""])
            lines.extend(["", "stderr:", stderr or ""])
            with open(evidence_file, "w", encoding="utf-8", errors="replace") as fh:
                fh.write("\n".join(lines))
        except Exception as e:
            print(f"⚠️  No se pudo guardar evidencia de Nmap: {e}")
    
    def format_ports_list(self, ports: List[int]) -> str:
        """Formatea una lista de puertos en formato Nmap."""
        if not ports:
            return ""
        ports_str = ",".join(map(str, sorted(set(ports))))
        return f"-p {ports_str}"
    
    def build_port_list(self, ot_ports: bool = True, it_ports: bool = True, 
                       custom_ports: Optional[str] = None) -> List[int]:
        """
        Construye la lista de puertos a escanear sin duplicados.
        
        Args:
            ot_ports: Incluir puertos OT (sin duplicados de IT)
            it_ports: Incluir puertos IT comunes
            custom_ports: Puertos personalizados (string separado por comas)
            
        Returns:
            Lista de puertos únicos ordenados
        """
        ports = set()
        
        if it_ports:
            ports.update(IT_COMMON_PORTS)
        
        if ot_ports:
            # Usar la lista limpia de OT (sin duplicados de IT)
            ports.update(OT_PORTS_CLEANED)
        
        if custom_ports:
            try:
                custom_list = [int(p.strip()) for p in custom_ports.split(',') if p.strip()]
                ports.update(custom_list)
            except ValueError:
                pass
        
        return sorted(list(ports))
    
    def build_nmap_command(self, target_range: str, speed: str = 'normal',
                          ports: Optional[List[int]] = None,
                          enable_versions: bool = False,
                          enable_vulns: bool = False,
                          output_file: Optional[str] = None) -> List[str]:
        """
        Construye el comando Nmap optimizado según configuración.
        
        Mejoras implementadas:
        - Técnicas de escaneo más sigilosas
        - Optimización según velocidad
        - Scripts especializados para OT/IT
        
        Args:
            target_range: Rango de IPs a escanear
            speed: Velocidad ('rapido', 'normal', 'lento')
            ports: Lista de puertos a escanear
            enable_versions: Habilitar detección de versiones (-sV)
            enable_vulns: Habilitar scripts de vulnerabilidades
            output_file: Archivo XML de salida
            
        Returns:
            Lista de argumentos para subprocess
        """
        cmd = ['nmap']
        
        # Configuración de velocidad
        speed_map = {
            'rapido': '-T4',
            'normal': '-T3',
            'lento': '-T2',
            'icmp': '-T4' # ICMP por defecto rápido
        }
        
        cmd.append(speed_map.get(speed, '-T3'))
        
        if speed == 'icmp':
            # Modo descubrimiento ICMP real. Nmap -sn por defecto mezcla
            # probes TCP/ARP y en algunos entornos puede marcar todo un /24
            # como up por respuestas reset. Esta fase debe ser ICMP.
            cmd.extend(['-sn', '-PE', '--disable-arp-ping'])
        else:
            # Técnica de escaneo: TCP connect scan (no requiere privilegios root)
            cmd.append('-sT')
            
            # Puertos (solo si no es modo ICMP)
            if ports:
                ports_str = self.format_ports_list(ports)
                if ports_str:
                    cmd.extend(ports_str.split())
            else:
                # Por defecto, top 1000 puertos más comunes
                cmd.append('--top-ports')
                cmd.append('1000')
            
            # Detección de versiones (solo si está marcado en la interfaz y no es ICMP)
            if enable_versions:
                cmd.append('-sV')
            
            # Scripts de vulnerabilidades (solo si está marcado en la interfaz y no es ICMP)
            if enable_vulns:
                cmd.append('--script')
                cmd.append('vuln')
        
        # Salida XML (necesario para el funcionamiento del sistema)
        if output_file:
            cmd.extend(['-oX', output_file])
        
        # Target(s) — may be a space-separated list of IPs built by the caller
        cmd.extend(target_range.split())
        
        return cmd
    def scan(self, target_range: str, speed: str = 'normal', 
            ot_ports: bool = True, it_ports: bool = True,
            custom_ports: Optional[str] = None,
            enable_versions: bool = False,
            enable_vulns: bool = False,
            output_file: Optional[str] = None,
            process_callback: Optional[callable] = None,
            command_evidence_file: Optional[str] = None) -> str:
        """
        Ejecuta un escaneo de puertos con Nmap mejorado.
        
        Args:
            target_range: Rango de IPs a escanear
            speed: Velocidad del escaneo ('rapido', 'normal', 'lento')
            ot_ports: Incluir puertos OT (sin duplicados de IT)
            it_ports: Incluir puertos IT comunes
            custom_ports: Puertos personalizados (string separado por comas)
            enable_versions: Habilitar detección de versiones
            enable_vulns: Habilitar scripts de vulnerabilidades
            output_file: Archivo XML de salida
            
        Returns:
            Ruta al archivo XML generado
        """
        # Construir lista de puertos (sin duplicados)
        ports = self.build_port_list(ot_ports, it_ports, custom_ports)
        
        # Generar archivo de salida si no se proporciona
        if not output_file:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
                output_file = f.name
        
        # Construir comando
        cmd = self.build_nmap_command(
            target_range=target_range,
            speed=speed,
            ports=ports,
            enable_versions=enable_versions,
            enable_vulns=enable_vulns,
            output_file=output_file
        )
        
        print(f"🔍 Ejecutando escaneo Nmap mejorado...")
        print(f"   Comando: {' '.join(cmd)}")
        print(f"   Puertos configurados: {len(ports)} (IT: {len(IT_COMMON_PORTS) if it_ports else 0}, OT: {len(OT_PORTS_CLEANED) if ot_ports else 0})")
        print(f"   Velocidad: {speed}")
        if enable_versions:
            print(f"   Detección de versiones: ✓ (intensidad 7)")
        if enable_vulns:
            print(f"   Escaneo de vulnerabilidades: ✓ (incluyendo scripts OT)")
        
        try:
            # Ejecutar Nmap usando Popen para permitir seguimiento/cancelación
            started_at = datetime.now()
            self.current_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
        
            # Llamar al callback si se proporcionó
            if process_callback:
                try:
                    process_callback(self.current_process)
                except:
                    pass
            
            stdout, stderr = self.current_process.communicate()
            returncode = self.current_process.returncode
            self._write_command_evidence(
                command_evidence_file,
                cmd,
                stdout=stdout,
                stderr=stderr,
                returncode=returncode,
                started_at=started_at,
                completed_at=datetime.now(),
            )
            
            # Crear un objeto similar al resultado de subprocess.run para compatibilidad mínima interna
            class DummyResult:
                def __init__(self, rc, out, err):
                    self.returncode = rc
                    self.stdout = out
                    self.stderr = err
            
            result = DummyResult(returncode, stdout, stderr)
                
            # Nmap puede devolver códigos de salida diferentes:
            # 0: éxito
            # 1: algún error pero puede haber resultados
            # 2: error grave (ej: sintaxis incorrecta)
            if result.returncode == 0:
                # Verificar que el archivo XML existe, no está vacío y está completo
                if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                    # Verificar que el XML está completo (tiene el cierre </nmaprun>)
                    try:
                        with open(output_file, 'r', encoding='utf-8') as f:
                            content = f.read()
                            if '</nmaprun>' not in content:
                                error_msg = "El archivo XML está incompleto (Nmap fue interrumpido)"
                                print(f"❌ {error_msg}")
                                raise Exception(error_msg)
                    except Exception as e:
                        if "incompleto" in str(e):
                            raise
                        # Si hay otro error leyendo, continuar (el parser lo detectará)
                    
                    print(f"✅ Escaneo completado. Resultados en: {output_file}")
                    return output_file
                else:
                    error_msg = "El archivo XML no se generó o está vacío"
                    print(f"❌ {error_msg}")
                    raise Exception(error_msg)
            elif result.returncode == 1:
                # Código 1: Error pero puede haber resultados parciales
                error_msg = result.stderr[:500] if result.stderr else "Advertencias durante el escaneo"
                print(f"⚠️  Nmap terminó con advertencias (código {result.returncode})")
                print(f"   {error_msg}")
                # Verificar si el XML se generó a pesar del error
                if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                    # Verificar que el XML está completo
                    try:
                        with open(output_file, 'r', encoding='utf-8') as f:
                            content = f.read()
                            if '</nmaprun>' not in content:
                                raise Exception(f"Nmap fue interrumpido: {error_msg}")
                    except Exception as e:
                        if "interrumpido" in str(e):
                            raise
                        # Si hay otro error, continuar
                    
                    print(f"✅ Archivo XML generado correctamente a pesar de advertencias")
                    return output_file
                else:
                    # Si no hay XML, es un error real
                    raise Exception(f"Nmap falló: {error_msg}")
            elif result.returncode < 0:
                # Código negativo: proceso terminado por señal del sistema
                signal_num = -result.returncode
                signal_names = {
                    2: "SIGINT (interrumpido)",
                    9: "SIGKILL (forzado a terminar)",
                    15: "SIGTERM (solicitud de terminación)"
                }
                signal_name = signal_names.get(signal_num, f"Señal {signal_num}")
                error_msg = f"El proceso Nmap fue interrumpido por {signal_name}"
                print(f"❌ Nmap fue interrumpido (código {result.returncode}, {signal_name})")
                # Verificar si hay XML parcial
                if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                    try:
                        with open(output_file, 'r', encoding='utf-8') as f:
                            content = f.read()
                            if '</nmaprun>' in content:
                                # XML completo a pesar de la interrupción, puede ser válido
                                print(f"⚠️  XML completo encontrado a pesar de interrupción")
                                return output_file
                    except:
                        pass
                raise Exception(error_msg)
            else:
                # Código 2 o superior: Error grave
                error_msg = result.stderr[:500] if result.stderr else f"Código de salida {result.returncode}"
                print(f"❌ Nmap terminó con error (código {result.returncode})")
                print(f"   {error_msg}")
                raise Exception(f"Nmap falló (código {result.returncode}): {error_msg}")
        except FileNotFoundError:
            error_msg = "Nmap no está instalado o no está en PATH"
            self._write_command_evidence(
                command_evidence_file,
                cmd,
                stderr=error_msg,
                started_at=locals().get('started_at') or datetime.now(),
                completed_at=datetime.now(),
            )
            print(f"❌ Error: {error_msg}")
            raise Exception(error_msg)
        except subprocess.TimeoutExpired:
            error_msg = "Nmap excedió el tiempo límite"
            self._write_command_evidence(
                command_evidence_file,
                cmd,
                stderr=error_msg,
                started_at=locals().get('started_at') or datetime.now(),
                completed_at=datetime.now(),
            )
            print(f"❌ Error: {error_msg}")
            raise Exception(error_msg)
        except Exception as e:
            if command_evidence_file and 'returncode' not in locals():
                self._write_command_evidence(
                    command_evidence_file,
                    cmd,
                    stderr=str(e),
                    started_at=locals().get('started_at') or datetime.now(),
                    completed_at=datetime.now(),
                )
            # Re-lanzar errores ya formateados
            if "Nmap falló" in str(e) or "no está instalado" in str(e) or "excedió" in str(e):
                raise
            error_msg = f"Error ejecutando Nmap: {str(e)}"
            print(f"❌ {error_msg}")
            raise Exception(error_msg)
    
    def quick_port_check(self, target_ip: str, ports: List[int], 
                        timeout: int = 2) -> Dict[int, bool]:
        """
        Verificación rápida de puertos usando sockets con multithreading.
        
        Mejora: Usa ThreadPoolExecutor para verificar múltiples puertos en paralelo,
        acelerando significativamente el proceso.
        
        Args:
            target_ip: IP objetivo
            ports: Lista de puertos a verificar
            timeout: Timeout en segundos para cada puerto
            
        Returns:
            Diccionario {puerto: está_abierto}
        """
        results = {}
        
        def check_port(port: int) -> tuple[int, bool]:
            """Verifica si un puerto está abierto."""
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((target_ip, port))
                sock.close()
                return (port, result == 0)
            except Exception:
                return (port, False)
        
        # Usar ThreadPoolExecutor para verificación paralela
        with ThreadPoolExecutor(max_workers=min(self.max_threads, len(ports))) as executor:
            futures = {executor.submit(check_port, port): port for port in ports}
            for future in as_completed(futures):
                port, is_open = future.result()
                results[port] = is_open
        
        return results
    
    def get_port_info(self, port: int) -> Dict[str, str]:
        """
        Obtiene información sobre un puerto específico.
        
        Args:
            port: Número de puerto
            
        Returns:
            Diccionario con información del puerto (categoría, protocolo, descripción)
        """
        info = {
            'port': str(port),
            'category': 'unknown',
            'protocol': 'unknown',
            'description': 'Unknown service'
        }
        
        # Verificar si es puerto IT
        if port in IT_COMMON_PORTS:
            info['category'] = 'IT'
        # Verificar si es puerto OT
        elif port in OT_PORTS:
            info['category'] = 'OT'
        
        # Mapeo de puertos comunes a protocolos
        port_protocols = {
            21: ('TCP', 'FTP'),
            22: ('TCP', 'SSH'),
            23: ('TCP', 'Telnet'),
            25: ('TCP', 'SMTP'),
            53: ('UDP/TCP', 'DNS'),
            80: ('TCP', 'HTTP'),
            102: ('TCP', 'ISO-TSAP / Siemens S7'),
            110: ('TCP', 'POP3'),
            443: ('TCP', 'HTTPS'),
            502: ('TCP', 'Modbus TCP'),
            1433: ('TCP', 'MS SQL Server'),
            3306: ('TCP', 'MySQL'),
            3389: ('TCP', 'RDP'),
            4840: ('TCP', 'OPC UA Discovery'),
            4843: ('TCP', 'OPC UA Binary'),
            47808: ('UDP', 'BACnet/IP'),
            44818: ('UDP', 'EtherNet/IP'),
            20000: ('TCP', 'DNP3'),
            2404: ('TCP', 'IEC 60870-5-104'),
        }
        
        if port in port_protocols:
            protocol, description = port_protocols[port]
            info['protocol'] = protocol
            info['description'] = description
        
        return info
