# ScanHound

## Índice
- [Introducción](#introduccion)
- [Modo de uso](#modo-de-uso)
  - [Escaneo](#escaneo)
  - [Ejemplos de uso](#ejemplos-de-uso)
  - [Importar resultados en Neo4j](#importar-resultados-en-neo4j)
- [Preparar el entorno](#preparar-el-entorno)
- [Instalación](#instalacion)
- [TODO](#todo)

## Introducción
ScanHound es una herramienta de escaneo de redes que permite detectar servicios abiertos y representarlos visualmente en Neo4j y en un DashBoard con consultas preestablecidas. Consta de una aplicación web centralizada:
1. **web_app.py**: Aplicación web FastAPI que proporciona una interfaz para realizar escaneos detallados y visualizar resultados.
2. **start.sh**: Script de inicio seguro que asegura que las dependencias de Python y los permisos `sudo` (necesarios para Nmap/tshark) están en orden.

## Modo de uso

### Iniciar la Plataforma
Para comenzar a usar ScanHound / ArsenalOT, simplemente ejecuta el script de inicio:

```bash
./start.sh
```

Este script detectará tu entorno virtual, solicitará permisos de administrador y lanzará la interfaz web en `http://0.0.0.0:8000`.

### Escaneo
Desde la interfaz web, puedes realizar diferentes tipos de escaneos. Por detrás, el sistema permite:

Descubrimiento de activos:

- Diferentes técnicas de descubrimiento ARP e ICMP para focalizar el escaneo posterior y reducir tiempo

Descubrimiento de servicios:

- **Rápido**: Escaneo rápido de puertos y servicios
- **Normal**: Escaneo estandard
- **Lento**: Escaneo lento para ocasiones en las que se pueda saturar la red
- **OT/Industrial**: Escaneo enfocado a redes industriales (puertos de telemetría como Modbus, S7, Ethernet/IP, etc.)
- Además cuenta con captura de tráfico pasivo (PCAP) opcional.

Esto generará escaneos y guardará los resultados en una base de datos local SQLite y exportará a demanda a formato JSON o importará a bases de datos orientadas a grafos.

### Importar resultados en Neo4j
Para cargar los resultados en la base de datos Neo4j, ejecuta el siguiente comando:

```bash
python3 scan2neo.py -r <IP_Neo4j>
```

Los resultados se representarán en Neo4j de la siguiente manera:

![Estado actual](https://github.com/jor6PS/ScanHound/blob/main/images/grafo_scanhound_4.png?raw=true)

![Estado actual 2](https://github.com/jor6PS/ScanHound/blob/main/images/Captura%20de%20pantalla%202023-06-12%20140444.png?raw=true)

NeoDash mantiene una comunicación constante con Neo4j y ofrece un dashboard interactivo para visualizar los escaneos:

![Dashboard](https://github.com/jor6PS/ScanHound/blob/main/images/NeoDash%20-%20Neo4j%20Dashboard%20Builder%20%E2%80%94%20Mozilla%20Firefox%202023-06-12%2013-56-03.gif)


### Preparar el entorno 

Intalar y Ejecutar Neo4j:
```bash
sudo neo4j console
```
Ejecutar NeoDash y conectarno a nuestra BBDD Neo4j para visualizar los dashboards:
```bash
sudo docker run -it --rm -p 5005:5005 neo4jlabs/neodash
```

Acceder a la web desde http://localhost:5005 e importar el archivo **dashboard.json**

## Instalación

### Dependencias de Python

Se ha preparado un fichero con las dependencias requeriments.txt, para intalarlas ejecutar:
```bash
pip install -r requirements.txt
```
Si da error preparar un entorno virtual e instalar las dependencias:

```bash
python3 -m venv myenv
source myenv/bin/activate
pip install -r requirements.txt
```

### Dependencias del Sistema

La aplicación requiere las siguientes herramientas del sistema:

**Dependencias críticas:**
- `nmap`: Herramienta esencial para escaneos de red
  ```bash
  # Ubuntu/Debian
  sudo apt-get update && sudo apt-get install -y nmap
  
  # RedHat/CentOS/Fedora
  sudo yum install -y nmap
  
  # Arch Linux
  sudo pacman -S nmap
  ```

**Dependencias opcionales (recomendadas):**
- `arp-scan`: Mejora la precisión del descubrimiento de hosts
  ```bash
  # Ubuntu/Debian
  sudo apt-get update && sudo apt-get install -y arp-scan
  ```

- `tshark` (Wireshark): Necesario para escaneos pasivos de tráfico de red
  ```bash
  # Ubuntu/Debian
  sudo apt-get update && sudo apt-get install -y wireshark-common tshark
  
  # RedHat/CentOS/Fedora
  sudo yum install -y wireshark
  
  # Arch Linux
  sudo pacman -S wireshark-cli
  ```

- `firefox` y `geckodriver`: Para capturas de pantalla de servicios web
  ```bash
  # Ubuntu/Debian
  sudo apt-get update && sudo apt-get install -y firefox-esr firefox-geckodriver
  ```

**Nota:** Puedes verificar todas las dependencias ejecutando:
```bash
python3 check_dependencies.py
```

Este script verificará automáticamente qué dependencias están instaladas y te proporcionará instrucciones de instalación para las que faltan.

## TODO

- [ ] Guardar información del escaneo ping en CSV para cada escaneo.
- [ ] Incluir el modo `--industrial-hardcore` para realizar solo el escaneo ICMP sin escaneo de servicios.
- [x] Cambiar la detección de subredes en `scan2neo.py` para obtener los /24 de cada IP detectada.
- [ ] Optimizar el grafo de activos pivote eliminando el nodo origen y generando relaciones directas entre segmentos.
- [x] Contabilizar el número total de activos inseguros (con protocolos inseguros).
- [ ] Implementar filtro por IP en el grafo de activos similares en base a capturas de pantalla.
- [ ] Mostrar la cantidad de subredes /24 encontradas.
- [~] Incluir un departamento nuevo para el control de cambios entre escaneos con fechas diferentes.
- [~] Implementar escala logarítmica en el gráfico comparativo entre organizaciones.
- [x] Actualizar el README.

---

¡Gracias por usar ScanHound! 🚀
