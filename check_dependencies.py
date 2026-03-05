import shutil
import subprocess
import sys

def check_command(command, description):
    path = shutil.which(command)
    if path:
        print(f"[✓] {description} ({command}) encontrado en: {path}")
        return True
    else:
        print(f"[✗] {description} ({command}) NO encontrado.")
        return False

def check_library(library, description):
    try:
        __import__(library)
        print(f"[✓] Librería Python: {description} ({library}) instalada.")
        return True
    except ImportError:
        print(f"[✗] Librería Python: {description} ({library}) NO encontrada.")
        return False

def main():
    print("=== Verificador de Dependencias de ArsenalOT ===\n")
    
    critical = [
        ("nmap", "Escaneo de red principal"),
    ]
    
    optional = [
        ("arp-scan", "Descubrimiento ARP secundario"),
        ("tshark", "Análisis de tráfico pasivo"),
        ("geckodriver", "Driver Selenium (Necesario para capturas de pantalla)"),
        ("firefox", "Navegador para capturas"),
    ]
    
    missing_critical = []
    for cmd, desc in critical:
        if not check_command(cmd, desc):
            missing_critical.append(cmd)
            
    critical_libs = [
        ("impacket", "Protocolos de red avanzada"),
        ("pydantic", "Validación de datos"),
    ]
    
    for lib, desc in critical_libs:
        if not check_library(lib, desc):
            missing_critical.append(f"python:{lib}")
            
    print("\n--- Dependencias Opcionales ---")
    for cmd, desc in optional:
        check_command(cmd, desc)
        
    if missing_critical:
        print("\n¡ADVERTENCIA! Faltan dependencias críticas:")
        for cmd in missing_critical:
            print(f"  - {cmd}")
        print("\nInstala las dependencias críticas para asegurar el funcionamiento básico.")
    else:
        print("\n¡Todo listo! Las dependencias críticas están instaladas.")
        
    print("\n💡 NOTA SOBRE GECKODRIVER:")
    print("Si falta 'geckodriver', descárgalo de: https://github.com/mozilla/geckodriver/releases")
    print("Descomprímelo y muévelo a /usr/local/bin/ o /usr/bin/")

if __name__ == "__main__":
    main()
