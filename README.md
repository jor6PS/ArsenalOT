# ArsenalOT
ArsenalOT es una herramienta avanzada de escaneo y descubrimiento de redes, diseñada para detectar activos y servicios (con enfoque especial en redes OT/Industriales). 

Esta herramienta permite no solo obtener información detallada sobre los puertos, servicios y vulnerabilidades presentes en una red, sino también **representar estos datos visualmente** utilizando bases de datos orientadas a grafos (Neo4j), permitiendo un análisis de relaciones y topología de red avanzado a través de dashboards interactivos.

## Capacidades Principales
- **Descubrimiento de Activos**: Utiliza múltiples técnicas ARP e ICMP para un mapeo rápido y preciso de la red para focalizar el escaneo posterior y reducir tiempos.
- **Escaneo de Servicios Flexible**: Perfiles que van desde escaneos rápidos y estándar hasta escaneos sigilosos (lentos para no saturar la red) o enfocados exclusivamente en entornos industriales (telemetría Modbus, S7, Ethernet/IP, etc.).
- **Captura Pasiva**: Soporte para análisis pasivo de tráfico de red (PCAP).
- **Exportación e Integración**: Almacenamiento local SQLite, exportación a JSON y **volcado directo a Neo4j** para visualización avanzada de grafos de red.
- **Interfaz Web Moderna**: Centralización de los escaneos gestionados por un backend FastAPI y un entorno visual amigable y centralizado.

---

## 🚀 Instalación y Ejecución Rápida (Docker - Recomendado)

La forma más sencilla y robusta de ejecutar ArsenalOT junto con Neo4j es utilizando **Docker Compose**. Esto evita conflictos de dependencias y configura todo el entorno automáticamente.

### 1. Requisitos
*   Docker y Docker Compose instalado.

### 2. Inicio
Desde la carpeta raíz del proyecto, ejecuta:
```bash
docker-compose up -d --build
```

### 3. Acceso
*   **ArsenalOT Web**: [http://localhost:8000](http://localhost:8000)
*   **Neo4j Browser**: [http://localhost:7474](http://localhost:7474)

> [!TIP]
> Para una guía detallada sobre persistencia de datos y gestión de contenedores, consulta la **[Guía de Inicio con Docker](.system/brain/docker_guide.md)** (o similar en la carpeta de documentación).

---

## 🔧 Instalación Manual (Alternativa)

Si prefieres no usar Docker, puedes realizar una instalación tradicional en tu sistema Linux:

### 1. Dependencias del Sistema
```bash
sudo apt-get update
sudo apt-get install -y nmap tshark arp-scan firefox-esr
# Instalación de geckodriver... (ver scripts de ayuda)
```

### 2. Entorno Python
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Ejecución
```bash
./start.sh
```

---

## 📊 Visualización Avanzada (Neo4j)

ArsenalOT permite representar los activos detectados en una base de datos de grafos. Si usas la versión Docker, Neo4j ya estará corriendo.

*   **Exportación**: Desde la interfaz web de ArsenalOT, puedes enviar los resultados directamente a Neo4j configurando la IP como `localhost` (ya que comparten red).
*   **Grafos**: Accede a `http://localhost:7474` para realizar consultas Cypher manuales o visualizar el mapa de red generado.

---

## TODO List
Futuras utilidades y mejoras abiertas a la comunidad:

- [ ] Guardar información del escaneo ping en CSV para cada escaneo.
- [ ] Incluir el modo `--industrial-hardcore` para realizar solo el escaneo ICMP sin escaneo de servicios.
- [x] Cambiar la detección de subredes en `scan2neo.py` para obtener los /24 de cada IP detectada.
- [ ] Optimizar el grafo de activos pivote eliminando el nodo origen y generando relaciones directas entre segmentos.
- [x] Contabilizar el número total de activos inseguros (con protocolos inseguros).
- [ ] Implementar filtro por IP en el grafo de activos similares en base a capturas de pantalla.
- [ ] Mostrar la cantidad de subredes /24 encontradas.
- [~] Incluir un departamento nuevo para el control de cambios entre escaneos con fechas diferentes.
- [~] Implementar escala logarítmica en el gráfico comparativo entre organizaciones.
- [x] Actualizar el README general.

¡Gracias por usar ArsenalOT! 🚀
