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

## Requisitos e Instalación

### 1. Dependencias del Sistema (Linux)
ArsenalOT requiere varias herramientas del sistema para funcionar al 100%. Ejecuta los siguientes comandos en tu terminal Linux:

**Instalación unificada:**
```bash
sudo apt-get update
sudo apt-get install -y nmap tshark arp-scan firefox-esr
```

**Herramientas incluidas:**
- **`nmap`** (Crítico): Escaneo de puertos y servicios.
- **`tshark`** (Opcional): Captura pasiva de tráfico.
- **`arp-scan`** (Opcional): Descubrimiento rápido en red local.
- **`firefox-esr`** (Opcional): Necesario para capturas de pantalla automáticas.

**Configuración de permisos para tshark:**
Durante la instalación de `tshark`, selecciona **SÍ** cuando pregunte si los usuarios sin privilegios pueden capturar paquetes. Luego añade tu usuario al grupo:
```bash
sudo usermod -a -G wireshark $USER
```
*(Es posible que sea necesario cerrar sesión y volver a entrar para que el cambio de grupo surta efecto).*

Puedes validar el estado de tus dependencias ejecutando:
```bash
python3 check_dependencies.py
```

### 2. Entorno y Dependencias de Python

Para instalar la aplicación, sigue estos pasos desde la consola:

```bash
# 1. Clona el repositorio (Si no lo has hecho ya)
# git clone <URL_DEL_REPO>
# cd ArsenalOT

# 2. Crea tu entorno virtual (¡Git lo ignorará de tus commits automáticamente!)
python3 -m venv venv

# 3. Activa el entorno virtual. Tienes que realizar este paso cada vez que abras una nueva terminal
source venv/bin/activate

# 4. Instala las dependencias de Python necesarias para hacer volar ArsenalOT
pip install -r requirements.txt
```

---

## Ejecución y Modo de Uso

### Iniciar la Plataforma (Interfaz Web)
El método principal e ideal para utilizar ArsenalOT es a través de su interfaz web.
Asegúrate de que estás en la carpeta raíz (`ArsenalOT`) y ejecuta nuestro lanzador unificado:

```bash
./start.sh
```
El script detectará tu entorno de Python local para aislar la ejecución, verificará que estés con un usuario con ciertos privilegios y lanzará todo el motor que da vida a este software (FastAPI en entorno productivo Gunicorn / Uvicorn).

A continuación, abre un navegador web en: **`http://localhost:8000`** para iniciar y gestionar tus escaneos.

---

### Visualización Avanzada (Importar resultados en Neo4j)

ArsenalOT permite llevar los resultados encontrados (hosts, puertos vulnerables, subredes enteras, etc.) hacia **Neo4j** para generar el mapa completo de tu organización en una base de datos grafo. Aunque desde la web es posible elvantar los servicios de Neo4j y NeoDash ttambién se puede levantar en local con docker de la sigueinte manera:

**1. Preparar la Base de Datos Neo4j y NeoDash:**
En una consola secundaria, si tienes Neo4J de forma nativa:
```bash
sudo neo4j console
```

Para dotar a los resultados de pantallas preconstruidas por nosotros, usamos el cliente NeoDash como frontend conectándose a nuestra BBDD Neo4j:
```bash
sudo docker run -it --rm -p 5005:5005 neo4jlabs/neodash
```

**2. Importar los Resultados de ArsenalOT a Neo4j:**
Podemos instruirle desde el sistema ArsenalOT a enviar todo lo analizado a Neo4J:
```bash
python3 src/arsenal/scripts/scan2neo.py -r <IP_Neo4j>
```

Podrás acceder a dashboards en NeoDash entrando a `http://localhost:5005` y cargando o importando el archivo de configuración **`dashboard.json`**. 

Tus mapas de red empezarán a visualizarse orgánicamente, creando relaciones, marcando servicios críticos descubiertos e incorporándose al grafo total de la organización.

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
