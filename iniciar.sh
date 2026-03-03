#!/bin/bash
# Script de inicio rápido para ArsenalOT ScanHound
# Ejecuta este script para configurar y ejecutar la aplicación en Linux

set -e

echo "========================================"
echo "  ArsenalOT ScanHound - Inicio Rápido"
echo "========================================"
echo ""

# Colores
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Verificar Python
echo -e "${YELLOW}[1/5] Verificando Python...${NC}"
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1)
    echo -e "  ${GREEN}✓ Python encontrado: $PYTHON_VERSION${NC}"
    PYTHON_CMD=python3
elif command -v python &> /dev/null; then
    PYTHON_VERSION=$(python --version 2>&1)
    echo -e "  ${GREEN}✓ Python encontrado: $PYTHON_VERSION${NC}"
    PYTHON_CMD=python
else
    echo -e "  ${RED}✗ Python no encontrado. Por favor instala Python 3.8+${NC}"
    exit 1
fi

# Verificar/Crear entorno virtual
echo -e "${YELLOW}[2/5] Configurando entorno virtual...${NC}"
if [ ! -f "venv/bin/activate" ]; then
    echo "  Creando nuevo entorno virtual..."
    $PYTHON_CMD -m venv venv
    if [ $? -ne 0 ]; then
        echo -e "  ${RED}✗ Error creando entorno virtual${NC}"
        exit 1
    fi
    echo -e "  ${GREEN}✓ Entorno virtual creado${NC}"
else
    echo -e "  ${GREEN}✓ Entorno virtual encontrado${NC}"
fi

# Activar entorno virtual
echo -e "${YELLOW}[3/5] Activando entorno virtual...${NC}"
source venv/bin/activate
if [ $? -ne 0 ]; then
    echo -e "  ${YELLOW}⚠ No se pudo activar el entorno virtual automáticamente${NC}"
    echo "  Ejecuta manualmente: source venv/bin/activate"
else
    echo -e "  ${GREEN}✓ Entorno virtual activado${NC}"
fi

# Instalar dependencias
echo -e "${YELLOW}[4/5] Instalando/Verificando dependencias...${NC}"
pip install --upgrade pip --quiet
pip install -r requirements.txt
if [ $? -eq 0 ]; then
    echo -e "  ${GREEN}✓ Dependencias instaladas${NC}"
else
    echo -e "  ${YELLOW}⚠ Algunas dependencias pueden no haberse instalado correctamente${NC}"
fi

# Verificar requisitos externos
echo -e "${YELLOW}[5/5] Verificando requisitos externos...${NC}"

# Verificar Nmap
if command -v nmap &> /dev/null; then
    echo -e "  ${GREEN}✓ Nmap encontrado${NC}"
else
    echo -e "  ${YELLOW}⚠ Nmap no encontrado${NC}"
    echo "     La aplicación necesita Nmap para funcionar."
    echo "     Instálalo con: sudo apt-get install nmap"
    echo "     O: sudo yum install nmap"
fi

# Verificar Docker
if command -v docker &> /dev/null; then
    echo -e "  ${GREEN}✓ Docker encontrado (Neo4j funcionará)${NC}"
else
    echo -e "  ${YELLOW}⚠ Docker no encontrado (Neo4j no estará disponible)${NC}"
    echo "     Instala Docker desde: https://docs.docker.com/get-docker/"
fi

# Verificar arp-scan (opcional)
if command -v arp-scan &> /dev/null; then
    echo -e "  ${GREEN}✓ arp-scan encontrado (descubrimiento de hosts mejorado)${NC}"
else
    echo -e "  ${YELLOW}⚠ arp-scan no encontrado (opcional)${NC}"
    echo "     Instálalo con: sudo apt-get install arp-scan"
fi

echo ""
echo "========================================"
echo -e "  ${CYAN}Iniciando aplicación...${NC}"
echo "========================================"
echo ""
echo -e "${GREEN}La aplicación estará disponible en:${NC}"
echo -e "  ${CYAN}http://localhost:5000${NC}"
echo ""
echo -e "${YELLOW}Presiona Ctrl+C para detener la aplicación${NC}"
echo ""

# Ejecutar aplicación
$PYTHON_CMD app.py

