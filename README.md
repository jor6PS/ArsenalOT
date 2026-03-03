# ArsenalOT ScanHound

Aplicación web para pentesting IT/OT con escaneo de red, análisis de protocolos industriales y visualización en Neo4j.

## Requisitos

- Python 3.8+
- Nmap
- Docker (opcional, para Neo4j)

## Instalación

```bash
# Crear entorno virtual
python3 -m venv venv
source venv/bin/activate

# Instalar dependencias
pip install -r requirements.txt

# Instalar Nmap
sudo apt-get install nmap  # Ubuntu/Debian
```

## Ejecución

```bash
# Opción 1: Script de inicio
chmod +x iniciar.sh
./iniciar.sh

# Opción 2: Manual
source venv/bin/activate
python app.py
```

Accede a: http://localhost:5000

## Estructura

- `app.py` - Aplicación Flask principal
- `core/` - Módulos de escaneo y base de datos
- `simulators/` - Simuladores de protocolos industriales
- `protocols/` - Análisis de protocolos
- `templates/` - Plantillas HTML
- `static/` - CSS y JavaScript
