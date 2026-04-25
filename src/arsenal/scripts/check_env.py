#!/usr/bin/env python3
"""
Módulo para verificar dependencias del sistema necesarias para la aplicación.
"""

import subprocess
import shutil
import sys
import platform

class DependencyChecker:
    """Verifica que todas las herramientas necesarias estén instaladas."""
    
    def __init__(self):
        self.missing_critical = []
        self.missing_optional = []
        self.os_type = platform.system().lower()
    
    def check_command(self, command, name, description, critical=True, install_instructions=None):
        """
        Verifica si un comando está disponible en el sistema.
        
        Args:
            command: Nombre del comando a verificar
            name: Nombre descriptivo de la herramienta
            description: Descripción de para qué se usa
            critical: Si es True, la aplicación no puede funcionar sin esto
            install_instructions: Instrucciones de instalación específicas
        """
        # Intentar encontrar el comando
        found = False
        
        # Método 1: usar shutil.which (más confiable)
        if shutil.which(command):
            found = True
        else:
            # Método 2: intentar ejecutar el comando con --version o --help
            try:
                result = subprocess.run(
                    [command, '--version'],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=5
                )
                if result.returncode == 0 or result.returncode == 1:  # Algunos comandos devuelven 1 en --version
                    found = True
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass
        
        if not found:
            if critical:
                self.missing_critical.append({
                    'name': name,
                    'command': command,
                    'description': description,
                    'install_instructions': install_instructions or self._get_default_install(command)
                })
            else:
                self.missing_optional.append({
                    'name': name,
                    'command': command,
                    'description': description,
                    'install_instructions': install_instructions or self._get_default_install(command)
                })
        
        return found
    
    def _get_default_install(self, command):
        """Obtiene instrucciones de instalación por defecto según el SO."""
        if self.os_type == 'linux':
            # Detectar distribución Linux
            distro = self._detect_linux_distro()
            if distro in ['debian', 'ubuntu']:
                return f"sudo apt-get update && sudo apt-get install -y {command}"
            elif distro in ['redhat', 'centos', 'fedora']:
                return f"sudo yum install -y {command}"
            elif distro == 'arch':
                return f"sudo pacman -S {command}"
            else:
                return f"Instalar {command} usando el gestor de paquetes de tu distribución"
        elif self.os_type == 'darwin':  # macOS
            return f"brew install {command}"
        elif self.os_type == 'windows':
            return f"Descargar e instalar {command} desde su sitio web oficial"
        else:
            return f"Instalar {command} según tu sistema operativo"
    
    def _detect_linux_distro(self):
        """Detecta la distribución Linux."""
        try:
            # Intentar leer /etc/os-release (método moderno)
            with open('/etc/os-release', 'r') as f:
                content = f.read().lower()
                if 'ubuntu' in content or 'debian' in content:
                    return 'ubuntu' if 'ubuntu' in content else 'debian'
                elif 'centos' in content or 'rhel' in content or 'red hat' in content:
                    return 'redhat'
                elif 'fedora' in content:
                    return 'fedora'
                elif 'arch' in content:
                    return 'arch'
        except:
            pass
        
        # Fallback: usar platform
        try:
            distro_info = platform.freedesktop_os_release()
            if distro_info:
                id_like = distro_info.get('ID_LIKE', '').lower()
                if 'debian' in id_like or 'ubuntu' in id_like:
                    return 'debian'
                elif 'rhel' in id_like or 'fedora' in id_like:
                    return 'redhat'
                elif 'arch' in id_like:
                    return 'arch'
        except:
            pass
        
        return 'unknown'
    
    def check_eyewitness(self):
        """Verifica si EyeWitness está disponible para capturas de pantalla."""
        candidates = [
            "eyewitness",
            "/usr/bin/eyewitness",
            "/usr/local/bin/eyewitness",
            "/opt/EyeWitness/Python/EyeWitness.py",
            "/opt/eyewitness/Python/EyeWitness.py",
            "/usr/share/eyewitness/EyeWitness.py",
        ]
        for path in candidates:
            if shutil.which(path) or __import__("os").path.isfile(path):
                return True
        return False
    
    def check_all(self, check_optional=True, check_screenshots=True):
        """Verifica todas las dependencias."""
        print("🔍 Verificando dependencias del sistema...")
        print("="*70)
        
        # Dependencias críticas (obligatorias)
        print("\n📋 Dependencias críticas:")
        self.check_command(
            'nmap',
            'Nmap',
            'Herramienta esencial para escaneos de red',
            critical=True,
            install_instructions=self._get_nmap_install()
        )
        
        # Dependencias opcionales (recomendadas)
        if check_optional:
            print("\n📋 Dependencias opcionales:")
            self.check_command(
                'arp-scan',
                'arp-scan',
                'Mejora la precisión del descubrimiento de hosts (opcional)',
                critical=False,
                install_instructions=self._get_arp_scan_install()
            )
        # Verificar dependencias para capturas de pantalla
        if check_screenshots:
            print("\n📋 Dependencias para capturas de pantalla (EyeWitness):")
            eyewitness_ok = self.check_eyewitness()
            if not eyewitness_ok:
                self.missing_optional.append({
                    'name': 'EyeWitness',
                    'command': 'eyewitness',
                    'description': 'Herramienta de captura web (screenshots + código fuente)',
                    'install_instructions': self._get_eyewitness_install()
                })
            # Verificar Chromium (requerido por EyeWitness)
            self.check_command(
                'chromium',
                'Chromium',
                'Navegador necesario para EyeWitness (capturas de pantalla)',
                critical=False,
                install_instructions='sudo apt-get install -y chromium chromium-driver'
            )
        
        # Mostrar resultados
        print("\n" + "="*70)
        
        if self.missing_critical:
            print("❌ DEPENDENCIAS CRÍTICAS FALTANTES:")
            print("="*70)
            for dep in self.missing_critical:
                print(f"\n🔴 {dep['name']} ({dep['command']})")
                print(f"   Descripción: {dep['description']}")
                print(f"   Instalación:")
                print(f"   {dep['install_instructions']}")
            
            print("\n" + "="*70)
            print("⚠️  ERROR: No se puede continuar sin las dependencias críticas.")
            print("   Por favor, instala las herramientas faltantes y vuelve a intentar.")
            return False
        
        if self.missing_optional:
            print("⚠️  DEPENDENCIAS OPCIONALES FALTANTES:")
            print("="*70)
            for dep in self.missing_optional:
                print(f"\n🟡 {dep['name']} ({dep['command']})")
                print(f"   Descripción: {dep['description']}")
                print(f"   Instalación (recomendado):")
                print(f"   {dep['install_instructions']}")
            print("\n💡 Puedes continuar sin estas herramientas, pero algunas funcionalidades estarán limitadas.")
        
        if not self.missing_critical and not self.missing_optional:
            print("✅ Todas las dependencias están instaladas correctamente.")
        elif not self.missing_critical:
            print("✅ Todas las dependencias críticas están instaladas.")
        
        print("="*70 + "\n")
        return True
    
    def _get_nmap_install(self):
        """Instrucciones específicas para instalar Nmap."""
        if self.os_type == 'linux':
            distro = self._detect_linux_distro()
            if distro in ['debian', 'ubuntu']:
                return "sudo apt-get update && sudo apt-get install -y nmap"
            elif distro in ['redhat', 'centos', 'fedora']:
                return "sudo yum install -y nmap"
            elif distro == 'arch':
                return "sudo pacman -S nmap"
            else:
                return "Instalar nmap usando el gestor de paquetes de tu distribución"
        elif self.os_type == 'darwin':
            return "brew install nmap"
        elif self.os_type == 'windows':
            return "Descargar desde https://nmap.org/download.html o usar: choco install nmap"
        else:
            return "Instalar nmap según tu sistema operativo"
    
    def _get_arp_scan_install(self):
        """Instrucciones específicas para instalar arp-scan."""
        if self.os_type == 'linux':
            distro = self._detect_linux_distro()
            if distro in ['debian', 'ubuntu']:
                return "sudo apt-get update && sudo apt-get install -y arp-scan"
            elif distro in ['redhat', 'centos', 'fedora']:
                return "sudo yum install -y arp-scan"
            elif distro == 'arch':
                return "sudo pacman -S arp-scan"
            else:
                return "Instalar arp-scan usando el gestor de paquetes de tu distribución"
        elif self.os_type == 'darwin':
            return "brew install arp-scan"
        elif self.os_type == 'windows':
            return "arp-scan no está disponible para Windows. Se usará ping como alternativa."
        else:
            return "Instalar arp-scan según tu sistema operativo"
    
    def _get_eyewitness_install(self):
        """Instrucciones para instalar EyeWitness."""
        if self.os_type == 'linux':
            distro = self._detect_linux_distro()
            if distro in ['debian', 'ubuntu']:
                return (
                    "sudo apt-get install -y chromium chromium-driver && "
                    "git clone --depth 1 https://github.com/FortyNorthSecurity/EyeWitness.git /opt/eyewitness && "
                    "pip install -r /opt/eyewitness/requirements.txt"
                )
            else:
                return "git clone https://github.com/FortyNorthSecurity/EyeWitness.git /opt/eyewitness && pip install -r /opt/eyewitness/requirements.txt"
        else:
            return "Ver https://github.com/FortyNorthSecurity/EyeWitness para instrucciones de instalación"

def check_dependencies(check_optional=True, check_screenshots=True):
    """
    Función principal para verificar dependencias.
    
    Args:
        check_optional: Si es True, también verifica dependencias opcionales
        check_screenshots: Si es True, verifica dependencias para capturas de pantalla
    
    Returns:
        True si todas las dependencias críticas están instaladas, False en caso contrario
    """
    checker = DependencyChecker()
    return checker.check_all(check_optional=check_optional, check_screenshots=check_screenshots)


if __name__ == "__main__":
    # Ejecutar verificación si se llama directamente
    success = check_dependencies()
    sys.exit(0 if success else 1)
