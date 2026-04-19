# AUDITORIA IEC 62443

## 📋 Procedimiento de Uso

**1. Generación de la Bitácora**
1.  Crea una **nueva nota** con el botón que puedes encontrar en cada una de las normas:
    *   [[IEC 62443-4-1]] (Ciclo de vida / Madurez)
    *   [[IEC 62443-4-2]] (Componentes / Dispositivos)
    *   [[IEC 62443-3-3]] (Sistema / Integración)
2.  **Configuración Automática:** Al crear la nota, aparecerá una ventana emergente.
    *   Introduce el **Nivel de Seguridad/Madurez Objetivo** (1, 2, 3 o 4).
    *   *La plantilla eliminará automáticamente los requisitos que no apliquen a ese nivel.*

**2. Toma de Datos (Input)**
1.  Ve al apartado del control que quieras auditar (ej. `CR 1.1`).
2.  Rellena los campos del bloque de datos escribiendo después de los dos puntos `::`:
    *   **Estado::** Escribe `Cumple`, `No cumple`, `Parcial`, `Pendiente` o `No aplica`.
    *   **Justificacion::** Explica brevemente el motivo técnico.
    *   **Evidencias::** Describe la prueba.
        *   *Tip:* Para adjuntar imágenes, pégalas directamente en esta línea o usa el formato `![[imagen.png]]`.
> ⚠️ **Importante:** Si dejas los `...` por defecto, el sistema lo marcará como **Pendiente (🔴)** en el dashboard.

**3. Visualización de Resultados (Output)**
No necesitas ir a ninguna otra nota. Los resultados se generan **al final de este mismo documento**:
1.  **Dashboard:** Gráficas de progreso y semáforos por familia.
2.  **Resumen Detallado:** Tabla con todos los controles y sus justificaciones.
3.  **Galería de Evidencias:** Visualización automática de todas las capturas de pantalla adjuntadas en los pasos anteriores.

## Plan de Pruebas y Metodología de Evaluación de Ciberseguridad ISA/IEC 62443

### 1. Propósito y Objetivos

El propósito de este documento es describir la metodología, el alcance, los requisitos y el plan de pruebas para la evaluación de ciberseguridad basada en la norma ISA/IEC 62443.

Los objetivos principales de la evaluación son:

*   Identificar las brechas de seguridad del sistema y/o de sus componentes en comparación con los requisitos de la norma ISA/IEC 62443.
*   Evaluar el Nivel de Seguridad (Security Level - SL) actual de la implementación.
*   Proporcionar un informe detallado con los hallazgos, el nivel de riesgo asociado y recomendaciones claras y priorizadas para mitigar dichos riesgos.

### 2. Definición del Alcance de la Evaluación

La definición precisa del alcance es el primer y más crítico paso de la auditoría. Este proceso se realizará en un taller colaborativo con el personal clave del cliente.

*   **Paso 1: Definir el Sistema Bajo Consideración (SuC - System under Consideration)**
    *   Se identificará el sistema industrial a auditar de forma funcional (ej: "Sistema de Control de la Turbina de Gas TG-01", "Red SCADA de la planta de tratamiento de aguas"). Este SuC será el perímetro de nuestra evaluación.
*   **Paso 2: Segmentación en Zonas y Conduits**
    *   **Zonas:** El SuC se dividirá en "Zonas", que son agrupaciones lógicas o físicas de activos con requisitos de seguridad comunes. Las zonas se definen por función y criticidad (ej: Zona de Control de Proceso, Zona de Supervisión, Zona de Seguridad (SIS), DMZ Industrial).
    *   **Conduits:** Se identificarán todos los "Conduits", que son los canales de comunicación que conectan las zonas entre sí o con redes externas. Cada conduit será analizado para verificar los controles de seguridad que protegen el flujo de datos.
*   **Paso 3: Identificar el Nivel de Seguridad Objetivo (SL-T)**
    *   Basándonos en el análisis de riesgos del cliente, se establecerá el Nivel de Seguridad Objetivo (Target Security Level) para cada Zona y Conduit. Este SL-T (de 1 a 4) será la referencia contra la cual se medirá el cumplimiento.

> 💡 **Nota de Experto:** Es vital documentar no solo las conexiones digitales, sino también los "conduits humanos" (uso de USBs, portátiles de mantenimiento) y las conexiones inalámbricas temporales, ya que a menudo se pasan por alto en los diagramas iniciales y son vectores de ataque críticos (Stuxnet, por ejemplo).

### 3. Tipología de Componentes del Sistema (IACS)

La evaluación abarcará los diferentes tipos de componentes que conforman un Sistema de Control y Automatización Industrial (IACS), según la clasificación de la norma:

*   **Dispositivos Embebidos (EDR - Embedded Device Requirements):**
    *   Descripción: Componentes de control en tiempo real.
    *   Ejemplos: PLCs, RTUs, Controladores (DCS), Relés de Protección Inteligentes (IEDs), Sensores y Actuadores de red.
*   **Dispositivos Host (HDR - Host Device Requirements):**
    *   Descripción: Sistemas operativos de propósito general (Windows, Linux) que ejecutan software de control o soportan el sistema.
    *   Ejemplos: Estaciones de Operador (HMI), Estaciones de Ingeniería (EWS), Servidores SCADA, Historiadores de Datos.
*   **Dispositivos de Red (NDR - Network Device Requirements):**
    *   Descripción: Componentes que gestionan el flujo de datos en la red.
    *   Ejemplos: Switches Gestionables, Routers, Firewalls, Puntos de Acceso Inalámbricos.
*   **Aplicaciones de Software (SAR - Software Application Requirements):**
    *   Descripción: El software que se ejecuta en los dispositivos host.
    *   Ejemplos: Software SCADA/HMI, software de gestión de activos, software antivirus.

### 4. Metodología y Fases de la Evaluación

La evaluación se llevará a cabo siguiendo un enfoque estructurado en tres fases:

*   **Fase 1: Planificación y Recopilación de Información**
    *   Realización del taller de definición de alcance.
    *   Recopilación y revisión de toda la documentación solicitada (diagramas de red, políticas, inventarios, etc.).
    *   Preparación del entorno de pruebas y validación de las credenciales de acceso.

*   **Fase 2: Ejecución de Pruebas y Análisis Técnico**
    *   **Análisis a Nivel de Sistema (Evaluación 3-3):**
        *   Auditoría de la configuración de firewalls y switches para validar la segmentación de red (SR 5.1) y la protección de fronteras (SR 5.2).
        *   Revisión de la configuración del Directorio Activo (GPOs) o sistemas de gestión de usuarios para validar las políticas de contraseñas y roles (SR 1.5, SR 1.4).
        *   Análisis de la configuración del SIEM y las herramientas de monitorización para validar la recolección de logs y la generación de alertas (SR 6.1, SR 6.2).
        *   Verificación de los procedimientos de backup y recuperación (SR 7.3, SR 7.4).
    *   **Análisis a Nivel de Componente (Evaluación 4-2 o Validación Básica):**
        *   **Análisis de Interfaces de Red:** Escaneo de puertos y servicios, análisis de protocolos en claro, pruebas de denegación de servicio controladas.
        *   **Análisis de Interfaces Web:** Pruebas de inyección (XSS, SQLi, Command Injection), validación de gestión de sesiones, pruebas de control de acceso.
        *   **Análisis de Interfaces Físicas:** Se probará la seguridad de todos los puertos físicos accesibles para verificar los controles de acceso y la resiliencia a la conexión de dispositivos no autorizados. Los puertos a evaluar incluyen:
            *   Puertos USB: Pruebas con memorias genéricas y dispositivos de emulación de teclado (HID attacks).
            *   Puertos Ethernet (Consola/Gestión): Verificación de autenticación y separación de la red de datos.
            *   Puertos Serie (UART, RS-232): Pruebas de acceso a la consola de comandos y protección contra el acceso no autenticado.
            *   Puertos de Depuración (JTAG, SWD): Verificación de si estos puertos están deshabilitados en producción para prevenir la depuración a bajo nivel.
        *   **Análisis de Firmware:** Extracción y análisis de la imagen de firmware para buscar credenciales embebidas, claves privadas y vulnerabilidades en el código. Pruebas de integridad del proceso de actualización.

*   **Fase 3: Análisis de Resultados y Generación de Informes**
    *   Correlación de todos los hallazgos técnicos y documentales.
    *   Clasificación de cada hallazgo según su riesgo (impacto y probabilidad).
    *   Redacción del informe final, que incluirá:
        *   Resumen Ejecutivo.
        *   Descripción de la metodología y alcance.
        *   Tabla de hallazgos detallados, mapeados a los requisitos de la norma ISA/IEC 62443.
        *   Recomendaciones de mitigación, priorizadas y accionables.

### 5. Requisitos y Prerrequisitos para el Cliente

Para garantizar el éxito de la evaluación, se requiere la colaboración del cliente en los siguientes puntos:

*   **Disponibilidad de Personal Clave:**
    *   Acceso a ingenieros de control, administradores de red (OT e IT) y responsables de ciberseguridad para el taller de alcance y para resolver dudas durante la evaluación.
*   **Documentación (Ver solicitud de información detallada):**
    *   Diagramas de red, políticas de seguridad, inventario de activos, análisis de riesgos, planes de recuperación, etc.
*   **Acceso Técnico (Ver solicitud de información detallada):**
    *   Credenciales de prueba con diferentes niveles de privilegio.
    *   Acceso de red desde un punto designado para nuestros equipos de prueba.
    *   Acceso de lectura a los sistemas de monitorización (SIEM) y consolas de gestión (antivirus, backups).
    *   Acceso físico supervisado a los componentes cuando sea necesario.

### 6. Tabla de Referencia: Requisitos de Componente (CR) y Niveles de Seguridad (SL) Afectados

Esta tabla resume los Requisitos de Componente (CR) de la norma 62443-4-2 y el Nivel de Seguridad (SL) a partir del cual se aplican o se introducen mejoras (Requirement Enhancements - RE).

| FR | Requisito de Componente (CR) y Mejoras (RE) | SL1 | SL2 | SL3 | SL4 |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **FR1** | **CR 1.1: Autenticación de usuario humano** | ✓ | ✓ | ✓ | ✓ |
| | RE (1): Identificación única | | ✓ | ✓ | ✓ |
| | RE (2): Autenticación Multifactor (MFA) | | | ✓ | ✓ |
| | CR 1.2: Autenticación de dispositivo/proceso | | ✓ | ✓ | ✓ |
| | CR 1.3: Gestión de cuentas | ✓ | ✓ | ✓ | ✓ |
| | CR 1.4: Gestión de identificadores (roles) | ✓ | ✓ | ✓ | ✓ |
| | CR 1.5: Gestión de autenticadores | ✓ | ✓ | ✓ | ✓ |
| | RE (1): Seguridad por hardware | | | ✓ | ✓ |
| | CR 1.7: Fortaleza de contraseñas | ✓ | ✓ | ✓ | ✓ |
| | RE (1): Restricciones de generación/vida | | | ✓ | ✓ |
| | CR 1.8: Certificados PKI | | ✓ | ✓ | ✓ |
| | CR 1.10: Feedback de autenticación (anti-enumeración) | ✓ | ✓ | ✓ | ✓ |
| | CR 1.11: Bloqueo de intentos fallidos | ✓ | ✓ | ✓ | ✓ |
| **FR2** | **CR 2.1: Aplicación de autorización** | ✓ | ✓ | ✓ | ✓ |
| | RE (2): Mapeo a roles | | ✓ | ✓ | ✓ |
| | RE (3): Anulación por supervisor | | | ✓ | ✓ |
| | RE (4): Aprobación dual | | | | ✓ |
| | CR 2.3: Control de dispositivos portátiles/móviles | ✓ | ✓ | ✓ | ✓ |
| | CR 2.5: Bloqueo de sesión | ✓ | ✓ | ✓ | ✓ |
| | CR 2.6: Terminación de sesión remota | | ✓ | ✓ | ✓ |
| | CR 2.7: Control de sesiones concurrentes | | | ✓ | ✓ |
| | CR 2.8: Eventos auditables | ✓ | ✓ | ✓ | ✓ |
| | CR 2.13: Uso de interfaces de diagnóstico físicas | | ✓ | ✓ | ✓ |
| | RE (1): Monitorización activa | | | ✓ | ✓ |
| **FR3** | **CR 3.1: Integridad de la comunicación** | ✓ | ✓ | ✓ | ✓ |
| | RE (1): Autenticación de la comunicación | | ✓ | ✓ | ✓ |
| | CR 3.2: Protección contra código malicioso | ✓ | ✓ | ✓ | ✓ |
| | CR 3.4: Integridad de software e información | ✓ | ✓ | ✓ | ✓ |
| | RE (1): Verificación de autenticidad (firma) | | ✓ | ✓ | ✓ |
| | CR 3.5: Validación de entradas | ✓ | ✓ | ✓ | ✓ |
| | CR 3.8: Integridad de la sesión | | ✓ | ✓ | ✓ |
| | CR 3.10: Soporte para actualizaciones | ✓ | ✓ | ✓ | ✓ |
| | RE (1): Autenticidad e integridad de la actualización | | ✓ | ✓ | ✓ |
| | CR 3.11: Resistencia a la manipulación física | | ✓ | ✓ | ✓ |
| | CR 3.14: Integridad del proceso de arranque (Secure Boot) | ✓ | ✓ | ✓ | ✓ |
| | RE (1): Autenticidad del arranque | | ✓ | ✓ | ✓ |
| **FR4** | **CR 4.1: Confidencialidad de la información** | ✓ | ✓ | ✓ | ✓ |
| | CR 4.2: Persistencia de la información (borrado seguro) | | ✓ | ✓ | ✓ |
| | CR 4.3: Uso de criptografía | ✓ | ✓ | ✓ | ✓ |
| **FR5** | **CR 5.1: Segmentación de red** | ✓ | ✓ | ✓ | ✓ |
| | CR 5.2: Protección de fronteras de zona (Firewall) | ✓ | ✓ | ✓ | ✓ |
| **FR7** | **CR 7.1: Protección contra Denegación de Servicio (DoS)** | ✓ | ✓ | ✓ | ✓ |
| | CR 7.3: Backup del sistema de control | ✓ | ✓ | ✓ | ✓ |
| | RE (1): Verificación de integridad del backup | | | ✓ | ✓ |
| | CR 7.4: Recuperación del sistema de control | ✓ | ✓ | ✓ | ✓ |
| | CR 7.6: Configuración de red y seguridad | ✓ | ✓ | ✓ | ✓ |
| | CR 7.7: Mínima funcionalidad | ✓ | ✓ | ✓ | ✓ |
| | CR 7.8: Inventario de componentes | | ✓ | ✓ | ✓ |

---

## Solicitud de documentación previa

### Auditoría de Componente (IEC 62443-4-2)
*(El foco aquí es validar las capacidades de seguridad inherentes de un producto o componente específico).*

**1. Acceso y Credenciales**
*   **Elemento Solicitado:** Credenciales de prueba con diferentes niveles de privilegio.
    *   *Propósito y Relevancia en la Auditoría:* Necesitamos cuentas para (al menos) un rol de administrador y un rol de operador/solo lectura. Esto es crucial para verificar los controles de autorización (FR2) y asegurar que un usuario con bajos privilegios no puede realizar acciones administrativas.
    *   *Relevancia por Nivel de Seguridad (SL):* Fundamental para todos los SLs (a partir de SL1).
*   **Elemento Solicitado:** Acceso al sistema de logs del componente.
    *   *Propósito y Relevancia en la Auditoría:* Requerido para verificar que se generan los eventos de auditoría correctos (CR 2.8), que los timestamps son precisos (CR 2.11) y que los intentos de acceso fallidos se registran (CR 1.11).
    *   *Relevancia por Nivel de Seguridad (SL):* Fundamental para todos los SLs (a partir de SL1).
*   **Elemento Solicitado:** Permiso para acceso físico al componente (si procede).
    *   *Propósito y Relevancia en la Auditoría:* Necesario para evaluar la seguridad de los puertos físicos (USB, consolas serie) y la resistencia a la manipulación física (CR 2.13, CR 3.11).
    *   *Relevancia por Nivel de Seguridad (SL):* Relevante a partir de SL2.

**2. Documentación Técnica y de Producto**
*   **Elemento Solicitado:** Manual de uso, guía de operación y manual de seguridad del componente.
    *   *Propósito y Relevancia en la Auditoría:* Nos permite entender el funcionamiento previsto, las funciones de seguridad declaradas por el fabricante y las configuraciones recomendadas ("hardening guide"). Es la base para validar que el componente hace lo que dice hacer.
    *   *Relevancia por Nivel de Seguridad (SL):* Fundamental para todos los SLs (a partir de SL1).
*   **Elemento Solicitado:** Inventario de componentes de software (SBOM - Software Bill of Materials).
    *   *Propósito y Relevancia en la Auditoría:* Esencial para identificar librerías de terceros y componentes de código abierto utilizados, lo que nos permite buscar vulnerabilidades conocidas en dichas dependencias.
    *   *Relevancia por Nivel de Seguridad (SL):* Fundamental para todos los SLs (a partir de SL1).
*   **Elemento Solicitado:** Imagen(es) de firmware (y hashes/firmas si están disponibles).
    *   *Propósito y Relevancia en la Auditoría:* Requerido para realizar análisis estático, buscar secretos embebidos (hardcoded credentials), verificar el almacenamiento seguro de credenciales (CR 1.5) y probar la integridad del proceso de actualización (CR 3.4, CR 3.10).
    *   *Relevancia por Nivel de Seguridad (SL):* Relevante a partir de SL2.
*   **Elemento Solicitado:** Documentación de Diseño Seguro y Modelado de Amenazas.
    *   *Propósito y Relevancia en la Auditoría:* Clave para entender cómo se ha integrado la seguridad en el ciclo de vida de desarrollo del producto. Nos permite verificar que se han considerado las amenazas relevantes y se han implementado contramedidas adecuadas desde el diseño.
    *   *Relevancia por Nivel de Seguridad (SL):* Crítico para SL3 y SL4.

**3. Procedimientos y Evidencias**
*   **Elemento Solicitado:** Procedimientos de actualización de firmware, incluyendo cómo se verifica la firma digital.
    *   *Propósito y Relevancia en la Auditoría:* Necesario para validar el proceso de actualización segura (CR 3.10) y la verificación de autenticidad e integridad del software (CR 3.4).
    *   *Relevancia por Nivel de Seguridad (SL):* Relevante a partir de SL2.
*   **Elemento Solicitado:** Resultados de pruebas de seguridad previas (si existen).
    *   *Propósito y Relevancia en la Auditoría:* Informes de pentesting, escaneos de vulnerabilidades o auditorías anteriores nos ayudan a entender la madurez de seguridad del producto y a enfocar nuestras pruebas.
    *   *Relevancia por Nivel de Seguridad (SL):* Útil para todos los SLs.

**Resumen Simplificado (4-2):**
1.  Credenciales de prueba con diferentes niveles de privilegio.
2.  Acceso al sistema de logs del componente.
3.  Permiso para acceso físico al componente (si procede).
4.  Manual de uso, guía de operación y manual de seguridad del componente.
5.  Inventario de componentes de software (SBOM - Software Bill of Materials).
6.  Imagen(es) de firmware (y hashes/firmas si están disponibles).
7.  Documentación de Diseño Seguro y Modelado de Amenazas.
8.  Procedimientos de actualización de firmware, incluyendo cómo se verifica la firma digital.
9.  Resultados de pruebas de seguridad previas (si existen).

---

### Auditoría de Sistema (IEC 62443-3-3)
*(El foco aquí es validar cómo se han implementado, configurado y gestionado los componentes para securizar el sistema en su conjunto).*

**1. Acceso y Credenciales**
*   **Elemento Solicitado:** Credenciales de prueba con diferentes roles definidos para el sistema (ej. Administrador de SCADA, Ingeniero de Mantenimiento, Operador).
    *   *Propósito y Relevancia en la Auditoría:* Fundamental para probar la correcta implementación de la matriz de roles y permisos (SR 1.4) y la separación de privilegios (SR 2.1) en todo el sistema.
    *   *Relevancia por Nivel de Seguridad (SL):* Fundamental para todos los SLs (a partir de SL1).
*   **Elemento Solicitado:** Acceso de lectura al sistema centralizado de logs (SIEM) o servidor syslog.
    *   *Propósito y Relevancia en la Auditoría:* Clave para verificar la centralización y accesibilidad de los logs (SR 6.1), la monitorización continua (SR 6.2) y la correlación de eventos entre diferentes componentes.
    *   *Relevancia por Nivel de Seguridad (SL):* Relevante a partir de SL2, crítico para SL3 y SL4.

**2. Documentación de Arquitectura y Configuración**
*   **Elemento Solicitado:** Diagrama(s) de Arquitectura de Red (detallando Zonas y Conduits).
    *   *Propósito y Relevancia en la Auditoría:* El documento más importante para una auditoría 3-3. Es el mapa que define el alcance (SuC) y sobre el cual se evalúan todos los requisitos de segmentación (SR 5.1) y protección de fronteras (SR 5.2).
    *   *Relevancia por Nivel de Seguridad (SL):* Fundamental para todos los SLs (a partir de SL1).
*   **Elemento Solicitado:** Inventario de Activos del Sistema.
    *   *Propósito y Relevancia en la Auditoría:* Necesario para verificar que se mantiene un inventario completo y preciso (SR 7.8), base para la gestión de parches y vulnerabilidades.
    *   *Relevancia por Nivel de Seguridad (SL):* Relevante a partir de SL2.
*   **Elemento Solicitado:** Exportación de configuración de los dispositivos de frontera (Firewalls, Routers).
    *   *Propósito y Relevancia en la Auditoría:* Evidencia directa para auditar las ACLs y políticas de firewall (SR 5.2), la restricción de comunicaciones (SR 5.3) y la protección contra DoS a nivel de red (SR 7.1).
    *   *Relevancia por Nivel de Seguridad (SL):* Fundamental para todos los SLs (a partir de SL1).

**3. Políticas, Procedimientos y Evidencias Operativas**
*   **Elemento Solicitado:** Análisis de Riesgos del Sistema (SuC).
    *   *Propósito y Relevancia en la Auditoría:* Documento fundacional que justifica la elección del Nivel de Seguridad Objetivo (SL-T) para cada zona y conduit. Sin esto, la auditoría carece de un objetivo claro contra el que medir.
    *   *Relevancia por Nivel de Seguridad (SL):* Fundamental para todos los SLs (a partir de SL1).
*   **Elemento Solicitado:** Políticas de Ciberseguridad para OT.
    *   *Propósito y Relevancia en la Auditoría:* Incluye la política de contraseñas, política de acceso remoto, política de uso de medios extraíbles, etc. Auditamos la implementación técnica contra estas políticas.
    *   *Relevancia por Nivel de Seguridad (SL):* Fundamental para todos los SLs (a partir de SL1).
*   **Elemento Solicitado:** Matriz de Roles y Permisos.
    *   *Propósito y Relevancia en la Auditoría:* Documento que define qué puede hacer cada rol en el sistema. Es la base para auditar la implementación del mínimo privilegio (SR 1.4, SR 2.1).
    *   *Relevancia por Nivel de Seguridad (SL):* Fundamental para todos los SLs (a partir de SL1).
*   **Elemento Solicitado:** Plan de Recuperación ante Desastres (DRP) y Registros de Pruebas.
    *   *Propósito y Relevancia en la Auditoría:* No solo necesitamos el plan, sino la evidencia de que se ha probado periódicamente. Un plan no probado no es fiable (SR 7.3, SR 7.4).
    *   *Relevancia por Nivel de Seguridad (SL):* Fundamental para todos los SLs (a partir de SL1).
*   **Elemento Solicitado:** Procedimiento de Gestión de Cambios y registros asociados.
    *   *Propósito y Relevancia en la Auditoría:* Nos permite verificar que los cambios en la configuración de firewalls, servidores o PLCs se realizan de forma controlada y autorizada.
    *   *Relevancia por Nivel de Seguridad (SL):* Relevante a partir de SL2.
*   **Elemento Solicitado:** Plan y Registros de Formación en Ciberseguridad para el personal de OT.
    *   *Propósito y Relevancia en la Auditoría:* Evidencia de la concienciación del personal, que es un control compensatorio clave en cualquier nivel de seguridad.
    *   *Relevancia por Nivel de Seguridad (SL):* Relevante a partir de SL2.

**Resumen Simplificado (3-3):**
1.  Credenciales de prueba con diferentes roles definidos para el sistema (ej. Administrador de SCADA, Ingeniero de Mantenimiento, Operador).
2.  Acceso de lectura al sistema centralizado de logs (SIEM) o servidor syslog.
3.  Diagrama(s) de Arquitectura de Red (detallando Zonas y Conduits).
4.  Inventario de Activos del Sistema.
5.  Exportación de configuración de los dispositivos de frontera (Firewalls, Routers).
6.  Análisis de Riesgos del Sistema (SuC).
7.  Políticas de Ciberseguridad para OT.
8.  Matriz de Roles y Permisos.
9.  Plan de Recuperación ante Desastres (DRP) y Registros de Pruebas.
10. Procedimiento de Gestión de Cambios y registros asociados.
11. Plan y Registros de Formación en Ciberseguridad para el personal de OT.

---

## Software necesario para las pruebas

> 💡 **Nota de Experto:** Asegúrese de que las herramientas de escaneo activo (como Nmap o Nessus) estén configuradas con perfiles "seguros para OT" (baja velocidad, sin escaneo de plugins peligrosos) para evitar la denegación de servicio accidental en PLCs antiguos o dispositivos legacy.

**BÁSICAS (Relevantes para SL 1 y SL 2)**

*   **Nmap:**
    *   Aplica a: SR 1.13, SR 7.7, SR 7.8 (Descubrimiento y escaneo de puertos/servicios).
    *   SL: A partir de SL1.
*   **Wireshark / Tshark:**
    *   Aplica a: SR 1.5, SR 4.1, SR 3.1 (Análisis de tráfico, verificación de cifrado).
    *   SL: A partir de SL1.
*   **Netdiscover / Arp-scan:**
    *   Aplica a: SR 7.8 (Descubrimiento de activos en la red local).
    *   SL: A partir de SL1.
*   **OpenSSL:**
    *   Aplica a: SR 1.8, SR 1.9, SR 4.3 (Validación de certificados y PKI).
    *   SL: A partir de SL1.
*   **sslscan / testssl.sh:**
    *   Aplica a: SR 4.3 (Auditoría de configuración TLS/SSL y criptografía).
    *   SL: A partir de SL1.
*   **Ficheros de prueba EICAR:**
    *   Aplica a: SR 3.2 (Prueba de detección de malware).
    *   SL: A partir de SL1.
*   **Python (con librerías como requests y scapy):**
    *   Aplica a: Varios (Creación de scripts personalizados para pruebas específicas, manipulación de paquetes).
    *   SL: A partir de SL1.
*   **Burp Suite / OWASP ZAP:**
    *   Aplica a: SR 1.1, SR 1.10, SR 2.1, SR 3.5, SR 3.8 (Análisis web, inyecciones, gestión de sesión).
    *   SL: A partir de SL2.
*   **Hydra:**
    *   Aplica a: SR 1.1, SR 1.5, SR 1.11 (Pruebas de fuerza bruta de credenciales).
    *   SL: A partir de SL2.
*   **Metasploit Framework:**
    *   Aplica a: SR 3.2 (Validación de vulnerabilidades conocidas, generación de payloads de prueba).
    *   SL: A partir de SL2.
*   **Bettercap / mitmproxy:**
    *   Aplica a: SR 1.2, SR 3.1 (Pruebas de Man-in-the-Middle).
    *   SL: A partir de SL2.
*   **hping3 / slowhttptest:**
    *   Aplica a: SR 7.1, SR 7.2 (Pruebas de Denegación de Servicio - DoS).
    *   SL: A partir de SL2.
*   **sqlmap:**
    *   Aplica a: SR 3.5 (Detección avanzada de inyección SQL).
    *   SL: A partir de SL2.
*   **commix:**
    *   Aplica a: SR 3.5 (Detección de inyección de comandos).
    *   SL: A partir de SL2.
*   **ffuf / wfuzz:**
    *   Aplica a: SR 3.5, SR 3.7 (Fuzzing web, descubrimiento de contenido).
    *   SL: A partir de SL2.
*   **Aircrack-ng (suite) / Wifite:**
    *   Aplica a: SR 1.6 (Auditoría de seguridad de redes inalámbricas).
    *   SL: A partir de SL2.
*   **hostapd-mana / eaphammer:**
    *   Aplica a: SR 1.6 (Ataques avanzados de "Evil Twin" y 802.1X).
    *   SL: A partir de SL2.
*   **Binwalk:**
    *   Aplica a: CR 1.5, CR 3.14, CR 4.1 (Extracción y análisis de firmware).
    *   SL: A partir de SL2.
*   **HxD (o editor hexadecimal):**
    *   Aplica a: CR 3.4, CR 3.10, CR 7.3 (Modificación de ficheros para pruebas de integridad).
    *   SL: A partir de SL2.
*   **strings / grep:**
    *   Aplica a: CR 1.5, CR 4.1 (Búsqueda de cadenas de texto y secretos en binarios/firmware).
    *   SL: A partir de SL2.

**AVANZADAS (Relevantes para SL 3 y SL 4)**

*   **GDB (GNU Debugger):**
    *   Aplica a: CR 1.5 (RE 1), CR 2.13, CR 3.14 (Depuración de software a bajo nivel en tiempo de ejecución).
    *   SL: A partir de SL3.
*   **OpenOCD:**
    *   Aplica a: CR 2.13, CR 3.14 (Software para interactuar con interfaces de depuración de hardware como JTAG/SWD).
    *   SL: A partir de SL3.
*   **Boofuzz / AFL (American Fuzzy Lop):**
    *   Aplica a: SR 3.5 (Fuzzing avanzado para descubrir corrupción de memoria y DoS).
    *   SL: A partir de SL3.
*   **Delorean / NTSke:**
    *   Aplica a: CR 2.11 (RE 2) (Pruebas de seguridad del protocolo NTP).
    *   SL: A partir de SL3.
*   **Autopsy / Photorec:**
    *   Aplica a: CR 4.2 (RE 2) (Software forense para verificar el borrado seguro de datos).
    *   SL: A partir de SL4.
*   **Ghidra / IDA Pro:**
    *   Aplica a: Varios (Software de ingeniería inversa para análisis estático profundo de firmware y binarios).
    *   SL: A partir de SL4.

---

## Hardware necesario para las pruebas

> 💡 **Nota de Experto:** Para pruebas físicas (JTAG, UART), utilice siempre aisladores lógicos o convertidores de nivel de voltaje adecuados para evitar dañar los componentes electrónicos del dispositivo bajo prueba.

**BÁSICAS (Relevantes para SL 1 y SL 2)**

*   **Herramienta: Portátil de Pruebas (con Kali Linux)**
    *   Aplica a: Todos los SR/CR (Es la plataforma principal desde la que se ejecutan todas las herramientas de software para la auditoría).
    *   SL: A partir de SL1.
*   **Herramienta: Switch de Red Gestionable**
    *   Aplica a: SR 5.1, SR 4.1 (Permite crear redes de prueba aisladas, configurar VLANs y realizar Port Mirroring (SPAN) para capturar tráfico sin un TAP).
    *   SL: A partir de SL1.
*   **Herramienta: TAP de Red (Network TAP)**
    *   Aplica a: SR 4.1, SR 3.1 (Permite la captura pasiva de tráfico de red sin interrumpir la comunicación, garantizando que no se alteran los datos).
    *   SL: A partir de SL1.
*   **Herramienta: Cables y Conectividad Básica (Ethernet, USB, etc.)**
    *   Aplica a: Todas (Necesarios para la conexión física de nuestros equipos de prueba).
    *   SL: A partir de SL1.
*   **Herramienta: Memoria USB Genérica / Maliciosa (tipo Rubber Ducky)**
    *   Aplica a: SR 2.3 (Para probar los controles de seguridad de los puertos USB contra dispositivos no autorizados y ataques de emulación de teclado).
    *   SL: A partir de SL1.
*   **Herramienta: Programadores y Cables Específicos de Vendor (PLC, etc.)**
    *   Aplica a: Varios (Necesarios para interactuar directamente con equipos de control propietarios, cargar/descargar configuraciones y lógica).
    *   SL: A partir de SL1.
*   **Herramienta: Adaptador USB a Serie (UART)**
    *   Aplica a: CR 2.13, CR 3.14 (Es la herramienta más básica para acceder a la consola serie de los dispositivos, analizar logs de arranque y probar si el acceso está protegido).
    *   SL: A partir de SL1.
*   **Herramienta: Bus Pirate**
    *   Aplica a: CR 2.13, CR 3.14 (Herramienta de interfaz universal para interactuar con diversos protocolos serie (UART, I2C, SPI), esencial para probar la seguridad de múltiples tipos de puertos de diagnóstico).
    *   SL: A partir de SL2.
*   **Herramienta: JTAGulator**
    *   Aplica a: CR 2.13 (Hardware utilizado para identificar los pines de interfaces de depuración (JTAG/UART) cuando no están documentados, necesario para poder probar si dichos puertos están correctamente deshabilitados).
    *   SL: A partir de SL2.
*   **Herramienta: Punto de Acceso Wi-Fi (AP) de Pruebas**
    *   Aplica a: SR 1.6 (Para crear redes inalámbricas controladas, como en un ataque "Evil Twin", y probar la respuesta de los dispositivos).
    *   SL: A partir de SL2.

**AVANZADAS (Relevantes para SL 3 y SL 4)**

*   **Herramienta: Multímetro y Analizador Lógico**
    *   Aplica a: CR 2.13 (Esenciales para identificar señales, voltajes, y protocolos en la placa de circuito impreso durante la fase de reversing de hardware avanzado).
    *   SL: A partir de SL3.
*   **Herramienta: Sonda de depuración JTAG/SWD (ej. J-Link)**
    *   Aplica a: CR 1.5 (RE 1), CR 2.13, CR 3.14 (Hardware para realizar depuración activa del procesador, volcar memoria en tiempo real y verificar protecciones de hardware, yendo más allá de una simple prueba de conexión).
    *   SL: A partir de SL3.
*   **Herramienta: Keylogger por Hardware**
    *   Aplica a: SR 2.3 (Dispositivo para probar la resiliencia de los puertos físicos a la interceptación de datos, como las pulsaciones de teclado).
    *   SL: A partir de SL3.
*   **Herramienta: Estación de Soldadura / Aire Caliente**
    *   Aplica a: CR 4.2 (RE 2), CR 3.14 (Equipo para desoldar de forma segura los chips de memoria de la placa para un análisis "chip-off").
    *   SL: A partir de SL4.
*   **Herramienta: Programador de Memorias (SPI, EEPROM, Flash)**
    *   Aplica a: CR 4.2 (RE 2), CR 3.14, CR 1.5 (Hardware para leer y escribir directamente el contenido de los chips de memoria una vez desoldados, permitiendo un análisis forense completo del firmware).
    *   SL: A partir de SL4.

---