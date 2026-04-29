# ArsenalOT
ArsenalOT es una herramienta avanzada de escaneo y descubrimiento de redes, diseñada para detectar activos y servicios (con enfoque especial en redes OT/Industriales). 

Esta herramienta permite no solo obtener información detallada sobre los puertos, servicios y vulnerabilidades presentes en una red, sino también **representar estos datos visualmente** utilizando bases de datos orientadas a grafos (Neo4j), permitiendo un análisis de relaciones y topología de red avanzado a través de dashboards interactivos.

## Capacidades Principales
- **Descubrimiento de Activos**: Utiliza múltiples técnicas ARP e ICMP para un mapeo rápido y preciso de la red para focalizar el escaneo posterior y reducir tiempos.
- **Escaneo de Servicios Flexible**: Perfiles que van desde escaneos rápidos y estándar hasta escaneos sigilosos (lentos para no saturar la red) o enfocados exclusivamente en entornos industriales (telemetría Modbus, S7, Ethernet/IP, etc.).
- **Exportación e Integración**: Almacenamiento local SQLite, exportación a JSON y **volcado directo a Neo4j** para visualización avanzada de grafos de red.
- **Interfaz Web Moderna**: Centralización de los escaneos gestionados por un backend FastAPI y un entorno visual amigable y centralizado.
- **Dashboard de Reconocimiento**: Gestión por organización, sistemas, redes, dispositivos críticos y electrónica de red.
- **Vectores de Acceso**: Diagrama local para relacionar orígenes, redes accesibles, dispositivos y objetivos escaneados.
- **Integración con PwnDoc**: Creación y sincronización de auditorías, tipos de vulnerabilidad y findings.
- **Bitácora Obsidian**: Notas por organización con evidencias, visibilidad de escaneo y credenciales enmascaradas cuando corresponde.
- **Importación NetExec**: Importación controlada de workspaces para credenciales y datos de pentest.

> [!IMPORTANT]
> ArsenalOT debe utilizarse únicamente en redes propias, laboratorios o entornos donde exista autorización explícita. Los resultados, credenciales importadas y bases SQLite pueden contener información sensible.

---

## 🚀 Instalación y Ejecución Rápida (Docker - Recomendado)

La forma más sencilla y robusta de ejecutar ArsenalOT junto con Neo4j es utilizando **Docker Compose**. Esto evita conflictos de dependencias y configura todo el entorno automáticamente.

### 1. Requisitos
*   Docker y Docker Compose instalado.

### 2. Inicio
Desde la carpeta raíz del proyecto, ejecuta:
```bash
cp .env.example .env
# Edita .env y cambia las contraseñas de ejemplo antes de exponer el entorno.
docker-compose up -d --build
```

### 3. Acceso
*   **ArsenalOT Web**: [http://localhost:8000](http://localhost:8000)
*   **Neo4j Browser**: [http://localhost:7474](http://localhost:7474)
*   **PwnDoc**: [https://localhost:8443](https://localhost:8443)

> [!TIP]
> Para una guía detallada sobre persistencia de datos y gestión de contenedores, consulta la **[Guía de Inicio con Docker](.system/brain/docker_guide.md)** (o similar en la carpeta de documentación).

---

## 🔐 Buenas Prácticas de Seguridad

- No subas `.env`, `results/`, bases `.db`/`.sqlite`, evidencias ni exportaciones de clientes.
- Cambia `NEO4J_PASSWORD` y `PWNDOC_PASSWORD` en `.env` antes de usar el stack fuera de un laboratorio local.
- Mantén Neo4j y PwnDoc accesibles solo desde interfaces de confianza.
- Evita compartir workspaces NetExec o bitácoras con credenciales reales.
- Revisa el alcance antes de lanzar perfiles agresivos o scripts OT.
- Ejecuta Docker en una red aislada cuando no necesites acceso directo a interfaces físicas.

Variables mínimas recomendadas en `.env`:

- `NEO4J_HOST`: host de Neo4j, normalmente `localhost`.
- `NEO4J_PORT`: puerto Bolt, normalmente `7687`.
- `NEO4J_USERNAME`: usuario de Neo4j.
- `NEO4J_PASSWORD`: contraseña propia y no reutilizada.
- `PWNDOC_URL`: URL local de la API de PwnDoc.
- `PWNDOC_USER`: usuario de PwnDoc.
- `PWNDOC_PASSWORD`: contraseña propia y no reutilizada.

---

## 🔧 Instalación Manual (Alternativa)

Si prefieres no usar Docker, puedes realizar una instalación tradicional en tu sistema Linux:

### 1. Dependencias del Sistema
```bash
sudo apt-get update
sudo apt-get install -y nmap arp-scan firefox-esr
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

## 🌿 Flujo de Ramas

La rama estable recomendada es `main`. Para publicar el estado validado desde una rama de trabajo:

```bash
git checkout main
git pull origin main
git merge dev
git push origin main
```

Cuando `main` esté actualizada y validada, las ramas auxiliares se pueden retirar con:

```bash
git push origin --delete dev test test2
```

Esta eliminación debe hacerse solo cuando no haya trabajo pendiente en esas ramas.

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
