#!/usr/bin/env python3
import subprocess
import sys
import xml.etree.ElementTree as ET
import os
import argparse
import re
import time

# ==========================================
# CONFIGURACIÓN Y COLORES
# ==========================================
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    EVIDENCE = '\033[96m' # Cian para evidencias
    ENDC = '\033[0m'
    BOLD = '\033[1m'

INSECURE_PROTOCOLS = ['telnet', 'ftp', 'http', 'vnc', 'tftp']
TEMP_XML_FILE = "temp_nmap_audit.xml"

# ==========================================
# MOTOR DE ANÁLISIS (TIEMPO REAL)
# ==========================================

def run_scan(target_ip):
    print(f"{Colors.HEADER}[*] Iniciando escaneo experto IEC 62443 sobre {target_ip}...{Colors.ENDC}")
    print(f"{Colors.OKBLUE}    Los resultados aparecerán en pantalla mientras se ejecuta Nmap.{Colors.ENDC}")
    
    # Comando optimizado
    command = [
        "nmap", "-n", "-Pn", "-sV", "-T4", "--open", "-v",
        "--stats-every", "10s",
        "--script", "http-auth,ssh-auth-methods,ssl-enum-ciphers,ssl-cert,ftp-anon,ssh2-enum-algos,banner",
        "-oX", TEMP_XML_FILE, 
        target_ip
    ]
    
    try:
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1) as process:
            for line in process.stdout:
                print(line, end='') 
        
        if process.returncode != 0:
            print(f"\n{Colors.FAIL}[X] Nmap terminó con errores (pero intentaremos leer el XML).{Colors.ENDC}")
            
    except FileNotFoundError:
        print(f"{Colors.FAIL}[X] Nmap no está instalado.{Colors.ENDC}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n{Colors.FAIL}[!] Escaneo cancelado.{Colors.ENDC}")
        if os.path.exists(TEMP_XML_FILE): os.remove(TEMP_XML_FILE)
        sys.exit(1)

def parse_xml_file():
    if not os.path.exists(TEMP_XML_FILE):
        print(f"{Colors.FAIL}[X] No se generó el archivo XML.{Colors.ENDC}")
        sys.exit(1)
    try:
        tree = ET.parse(TEMP_XML_FILE)
        return tree.getroot()
    except ET.ParseError:
        print(f"{Colors.FAIL}[X] Error parseando XML.{Colors.ENDC}")
        sys.exit(1)

def cleanup():
    if os.path.exists(TEMP_XML_FILE): os.remove(TEMP_XML_FILE)

def extract_evidence(full_text, keyword):
    """Busca la línea que contiene la keyword en el texto de salida de Nmap."""
    if not full_text: return ""
    lines = full_text.split('\n')
    for line in lines:
        if keyword.lower() in line.lower():
            return line.strip()
    return "(Texto completo detectado, línea específica no parseada)"

# ==========================================
# LÓGICA DE CUMPLIMIENTO CON EVIDENCIAS
# ==========================================

def evaluate_cr_1_8_pki(host_node):
    print(f"\n{Colors.BOLD}--- ANÁLISIS CR 1.8: PKI Certificates ---{Colors.ENDC}")
    compliance_status = "CUMPLE"
    findings = []
    cert_found = False

    ports = host_node.findall(".//port")
    for port in ports:
        for script in port.findall('script'):
            if script.get('id') == 'ssl-cert':
                cert_found = True
                output = script.get('output')
                port_str = f"Puerto {port.get('portid')}"

                # 1. Expiración
                if "expired" in output.lower() or "not valid" in output.lower():
                    ev = extract_evidence(output, "Not valid after")
                    findings.append(f"{port_str}: Certificado EXPIRADO.\n      {Colors.EVIDENCE}[EVIDENCIA]: {ev}{Colors.ENDC}")
                    compliance_status = "NO CUMPLE"

                # 2. Algoritmo Débil
                if "sha1" in output.lower() or "md5" in output.lower():
                    ev = extract_evidence(output, "Signature Algorithm")
                    findings.append(f"{port_str}: Algoritmo de firma DÉBIL.\n      {Colors.EVIDENCE}[EVIDENCIA]: {ev}{Colors.ENDC}")
                    compliance_status = "NO CUMPLE"

                # 3. Clave Corta
                rsa_match = re.search(r'rsa\s+(\d{3,4})', output.lower())
                if rsa_match:
                    bits = int(rsa_match.group(1))
                    if bits < 2048:
                        ev = extract_evidence(output, "Public Key bits")
                        findings.append(f"{port_str}: Clave RSA insegura ({bits} bits).\n      {Colors.EVIDENCE}[EVIDENCIA]: {ev}{Colors.ENDC}")
                        compliance_status = "NO CUMPLE"
                
                # 4. Autofirmado
                if "self-signed" in output.lower() or "unable to get local issuer certificate" in output.lower():
                    ev = extract_evidence(output, "Issuer")
                    findings.append(f"{port_str}: Certificado AUTOFIRMADO o CA desconocida.\n      {Colors.EVIDENCE}[EVIDENCIA]: {ev}{Colors.ENDC}")
                    if compliance_status == "CUMPLE":
                        compliance_status = "PARCIAL (SL1 OK / SL2+ FAIL)"

    if not cert_found:
        print(f"{Colors.WARNING}[INFO] No se encontraron certificados expuestos.{Colors.ENDC}")
        return

    if compliance_status == "NO CUMPLE":
        print(f"{Colors.FAIL}[SUGERENCIA: NO CUMPLE]{Colors.ENDC}")
    elif "PARCIAL" in compliance_status:
        print(f"{Colors.WARNING}[SUGERENCIA: {compliance_status}]{Colors.ENDC}")
    else:
        print(f"{Colors.OKGREEN}[SUGERENCIA: CUMPLE]{Colors.ENDC}")
    
    for f in findings: print(f"  - {f}")

def evaluate_cr_1_9_strength_public_key(host_node):
    print(f"\n{Colors.BOLD}--- ANÁLISIS CR 1.9: Strength of Public Key Auth ---{Colors.ENDC}")
    compliance_status = "CUMPLE"
    findings = []
    checked = False

    ports = host_node.findall(".//port")
    for port in ports:
        port_id = port.get('portid')
        
        # SSH
        for script in port.findall('script'):
            if script.get('id') == 'ssh2-enum-algos':
                checked = True
                output = script.get('output')
                if "ssh-dss" in output:
                    findings.append(f"Puerto {port_id} (SSH): Soporta 'ssh-dss' (DSA).\n      {Colors.EVIDENCE}[EVIDENCIA]: Encontrado en lista 'server_host_key_algorithms'{Colors.ENDC}")
                    compliance_status = "NO CUMPLE"
                if "diffie-hellman-group1-sha1" in output:
                    findings.append(f"Puerto {port_id} (SSH): KEX débil detectado.\n      {Colors.EVIDENCE}[EVIDENCIA]: diffie-hellman-group1-sha1 presente en 'kex_algorithms'{Colors.ENDC}")
                    compliance_status = "NO CUMPLE"

        # SSL
        for script in port.findall('script'):
            if script.get('id') == 'ssl-enum-ciphers':
                checked = True
                output = script.get('output')
                if "anon" in output.lower() or "null" in output.lower():
                    # Intentamos extraer la linea exacta del cipher
                    lines = [l.strip() for l in output.split('\n') if "anon" in l.lower() or "null" in l.lower()]
                    ev = lines[0] if lines else "Cipher suite anónima detectada"
                    findings.append(f"Puerto {port_id} (SSL): Auth ANÓNIMA/NULA.\n      {Colors.EVIDENCE}[EVIDENCIA]: {ev}{Colors.ENDC}")
                    compliance_status = "NO CUMPLE"
                
                dh_match = re.search(r'dh\s+(\d{3,4})', output.lower())
                if dh_match:
                    bits = int(dh_match.group(1))
                    if bits < 2048:
                        findings.append(f"Puerto {port_id} (SSL): DH débil ({bits} bits).\n      {Colors.EVIDENCE}[EVIDENCIA]: {extract_evidence(output, 'dh ' + str(bits))}{Colors.ENDC}")
                        compliance_status = "NO CUMPLE"

    if not checked:
        print(f"{Colors.WARNING}[INFO] No se detectaron servicios SSH/SSL.{Colors.ENDC}")
        return

    if compliance_status == "NO CUMPLE":
        print(f"{Colors.FAIL}[SUGERENCIA: NO CUMPLE]{Colors.ENDC}")
    else:
        print(f"{Colors.OKGREEN}[SUGERENCIA: CUMPLE]{Colors.ENDC}")
    
    for f in findings: print(f"  - {f}")

def evaluate_cr_1_1_authentication(host_node):
    print(f"\n{Colors.BOLD}--- ANÁLISIS CR 1.1: Human User I&A ---{Colors.ENDC}")
    compliance_status = "CUMPLE"
    findings = []
    
    ports = host_node.findall(".//port")
    for port in ports:
        port_id = port.get('portid')
        service = port.find('service')
        service_name = service.get('name') if service is not None else "unknown"
        state = port.find('state').get('state')
        
        if state == 'open':
            if service_name in INSECURE_PROTOCOLS:
                findings.append(f"Puerto {port_id} ({service_name}): Protocolo inseguro.\n      {Colors.EVIDENCE}[EVIDENCIA]: Servicio '{service_name}' transmite credenciales en texto plano.{Colors.ENDC}")
                compliance_status = "NO CUMPLE"
            
            for script in port.findall('script'):
                if script.get('id') == 'ftp-anon' and "Anonymous FTP login allowed" in script.get('output'):
                    findings.append(f"Puerto {port_id} (FTP): Acceso anónimo permitido.\n      {Colors.EVIDENCE}[EVIDENCIA]: {extract_evidence(script.get('output'), 'Anonymous FTP login allowed')}{Colors.ENDC}")
                    compliance_status = "NO CUMPLE"
                
                if script.get('id') == 'ssh-auth-methods' and "none" in script.get('output').lower():
                    findings.append(f"Puerto {port_id} (SSH): Auth 'none' habilitada.\n      {Colors.EVIDENCE}[EVIDENCIA]: {extract_evidence(script.get('output'), 'none')}{Colors.ENDC}")
                    compliance_status = "NO CUMPLE"
                
                if script.get('id') == 'http-auth':
                    if "Basic" in script.get('output') and service_name == 'http':
                        findings.append(f"Puerto {port_id} (HTTP): Auth Basic insegura.\n      {Colors.EVIDENCE}[EVIDENCIA]: {extract_evidence(script.get('output'), 'Basic')}{Colors.ENDC}")
                        compliance_status = "NO CUMPLE"

    if compliance_status == "NO CUMPLE":
        print(f"{Colors.FAIL}[SUGERENCIA: NO CUMPLE]{Colors.ENDC}")
    else:
        print(f"{Colors.OKGREEN}[SUGERENCIA: CUMPLE / PARCIAL]{Colors.ENDC}")
    
    for f in findings: print(f"  - {f}")

def evaluate_cr_7_7_least_functionality(host_node):
    print(f"\n{Colors.BOLD}--- ANÁLISIS CR 7.7: Least Functionality ---{Colors.ENDC}")
    open_ports = []
    ports = host_node.findall(".//port")
    for port in ports:
        if port.find('state').get('state') == 'open':
            svc = port.find('service')
            svc_name = svc.get('name') if svc is not None else "unknown"
            # AÑADIDO: Extraer producto y versión para mejor evidencia
            product = svc.get('product') if svc is not None else ""
            version = svc.get('version') if svc is not None else ""
            full_svc = f"{svc_name} {product} {version}".strip()
            
            open_ports.append(f"{port.get('portid')}/{port.get('protocol')} -> {full_svc}")
    
    print(f"Puertos Abiertos: {len(open_ports)}")
    if len(open_ports) > 0:
        for p in open_ports: 
            print(f"  - {p}")
        
        if len(open_ports) > 6:
             print(f"\n{Colors.WARNING}[SUGERENCIA: REVISAR]{Colors.ENDC} Demasiados servicios expuestos.")
             print(f"{Colors.EVIDENCE}[EVIDENCIA]: Se detectaron {len(open_ports)} servicios. En OT, lo ideal es < 5.{Colors.ENDC}")
        else:
             print(f"{Colors.OKGREEN}[SUGERENCIA: CUMPLE]{Colors.ENDC} Superficie de ataque contenida.")

# ==========================================
# MAIN
# ==========================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Auditor Experto IEC 62443-4-2 (Con Evidencias)')
    parser.add_argument('ip', help='IP del componente industrial')
    args = parser.parse_args()

    run_scan(args.ip)
    
    root = parse_xml_file()
    host = root.find('host')
    
    if host is None or (host.find('status') is not None and host.find('status').get('state') != 'up'):
        ports = root.findall(".//port")
        if not ports:
            print(f"{Colors.FAIL}[!] Host inactivo o sin puertos abiertos.{Colors.ENDC}")
            cleanup()
            sys.exit()

    print(f"\n{Colors.HEADER}=== REPORTE DE CUMPLIMIENTO TÉCNICO ==={Colors.ENDC}")
    
    evaluate_cr_1_1_authentication(host)
    evaluate_cr_1_8_pki(host)
    evaluate_cr_1_9_strength_public_key(host)
    evaluate_cr_7_7_least_functionality(host)
    
    print(f"\n{Colors.BOLD}--- FIN DEL REPORTE ---{Colors.ENDC}")
    cleanup()