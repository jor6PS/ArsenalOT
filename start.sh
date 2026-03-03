#!/bin/bash

# Script de inicio seguro para ArsenalOT / ScanHound
echo "================================================="
echo "🚀 Iniciando ArsenalOT / ScanHound"
echo "================================================="

# 1. Comprobar si existe el entorno virtual
if [ ! -d "venv" ]; then
    echo "❌ Error: No se encontró el entorno virtual 'venv'."
    echo "💡 Instálalo primero con: python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt"
    exit 1
fi

# 2. Buscar si el usuario actual tiene permisos sudo activos o pedirle la contraseña de antemano
# Nmap y tshark necesitan permisos root para los escaneos avanzados (SYN scan, OS fingerprinting)
echo "🔑 Verificando permisos de superusuario (necesario para Nmap y capturas de red)..."
sudo -v

if [ $? -ne 0 ]; then
    echo "❌ Error: Necesitas permisos de administrador (sudo) para ejecutar esta herramienta."
    exit 1
fi

# 3. Lanzar la aplicación web usando el Python del entorno virtual pero con privilegios de root
echo "✨ Iniciando el servidor web en http://0.0.0.0:8000"
echo "Presiona Ctrl+C para detener el servidor..."
echo ""

sudo PYTHONPATH=src ./venv/bin/python -m arsenal.web.app
