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

def main():
    print("=== Verificador de Dependencias de ScanHound ===\n")
    
    critical = [
        ("nmap", "Escaneo de red principal"),
    ]
    
    optional = [
        ("arp-scan", "Descubrimiento ARP secundario"),
        ("tshark", "Análisis de tráfico pasivo"),
        ("geckodriver", "Capturas de pantalla (Selenium)"),
        ("firefox", "Navegador para capturas"),
    ]
    
    missing_critical = []
    for cmd, desc in critical:
        if not check_command(cmd, desc):
            missing_critical.append(cmd)
            
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

if __name__ == "__main__":
    main()
