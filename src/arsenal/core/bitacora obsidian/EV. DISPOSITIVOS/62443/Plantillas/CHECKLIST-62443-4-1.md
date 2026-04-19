<%*
// 1. PREGUNTAR EL NIVEL DE MADUREZ AL CREAR LA NOTA
let inputSL = await tp.system.prompt("Introduce el Nivel de Madurez Objetivo (ML 1-4)", "3");
let targetSL = parseInt(inputSL);
if (isNaN(targetSL) || targetSL < 1 || targetSL > 4) { targetSL = 3; }
-%>
---
tags:
  - auditoria
  - iec62443-4-1
  - ciclo-vida
  - evidencia
audit_file: <% tp.file.title %>
target_SL: <% targetSL %>
---

# IEC 62443-4-1: Ciclo de Vida Seguro - <% tp.file.title %>

> [!DANGER] INSTRUCCIONES
> **Nivel de Madurez Objetivo:** ML<% targetSL %>
> Esta nota evalúa los **Requisitos del Ciclo de Vida (SDLC)** según la norma IEC 62443-4-1.
> 1. Rellena los campos `::` con el estado y la justificación.
> 2. Los dashboards al final de la nota se actualizarán automáticamente.

## FR 1: Gestión de la seguridad

### SM-1: Proceso de desarrollo
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

### SM-2: Identificación de responsabilidades
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

### SM-3: Identificación de la aplicabilidad
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

### SM-4: Experiencia en seguridad
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

### SM-5: Determinación del alcance del proceso
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

### SM-6: Integridad del archivo
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

### SM-7: Seguridad del entorno de desarrollo
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

### SM-8: Controles para claves privadas
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

### SM-9: Requisitos de seguridad para los componentes suministrados externamente
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

### SM-10: Componentes desarrollados a medida por proveedores externos
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

### SM-11: Evaluación y tratamiento de las cuestiones relacionadas con la seguridad
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

### SM-12: Verificación del proceso
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

### SM-13: Mejora continua
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

## FR 2: Especificación de los requisitos de seguridad

### SR-1: Contexto de seguridad del producto
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

### SR-2: Modelo de amenaza
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

### SR-3: Requisitos de seguridad del producto
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

### SR-4: Contenido de los requisitos de seguridad del producto
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

### SR-5: Revisión de los requisitos de seguridad
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

## FR 3: Seguridad por diseño

### SD-1: Contexto de seguridad del producto
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

### SD-2: Diseño de defensa en profundidad
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

### SD-3: Revisión del diseño de seguridad
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

### SD-4: Mejores prácticas de diseño seguro
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

## FR 4: Implementación segura

### SI-1: Revisión de la implementación de la seguridad
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

### SI-2: Normas de codificación segura
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

## FR 5: Verificación de la seguridad y pruebas de validación

### SVV-1: Pruebas de los requisitos de seguridad
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

### SVV-2: Pruebas de mitigación de amenazas
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

### SVV-3: Pruebas de vulnerabilidad
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

### SVV-4: Ensayo de penetración
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

### SVV-5: Independencia de los probadores
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

## FR 6: Gestión de las cuestiones relacionadas con la seguridad

### DM-1: Recepción de notificaciones de cuestiones relacionadas con la seguridad
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

### DM-2: Examen de las cuestiones relacionadas con la seguridad
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

### DM-3: Evaluación de las cuestiones relacionadas con la seguridad
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

### DM-4: Tratamiento de las cuestiones relacionadas con la seguridad
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

### DM-5: Divulgación de cuestiones relacionadas con la seguridad
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

### DM-6: Revisión periódica de las prácticas de gestión de defectos de seguridad
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

## FR 7: Gestión de actualizaciones de seguridad

### SUM-1: Calificación de actualización de seguridad
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

### SUM-2: Documentación de actualización de seguridad
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

### SUM-3: Documentación de actualización de seguridad de componentes o sistemas operativos disponibles
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

### SUM-4: Entrega de actualizaciones de seguridad
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

### SUM-5: Entrega oportuna de los parches de seguridad
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

## FR 8: Directrices de seguridad

### SG-1: Defensa del producto en profundidad
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

### SG-2: Medidas de defensa en profundidad esperadas en el entorno
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

### SG-3: Directrices para el fortalecimiento de la seguridad
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

### SG-4: Directrices para una eliminación segura
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

### SG-5: Directrices para una operación segura
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

### SG-6: Directrices para la gestión de cuentas
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>

### SG-7: Revisión de la documentación
> [!EXAMPLE] Evidencia de Cumplimiento
> **Opciones:** `Cumple` / `No cumple` / `Parcial` / `Pendiente` / `Cumple con contramedidas` / `No aplica`
>
> ---
> ### Nivel 1 (SL1)
> - SL1_Estado:: ...
> - SL1_Justificacion:: ...
> - SL1_Evidencias:: ...
<%* if (targetSL >= 2) { -%>
>
> ---
> ### Nivel 2 (SL2)
> - SL2_Estado:: ...
> - SL2_Justificacion:: ...
> - SL2_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 3) { -%>
>
> ---
> ### Nivel 3 (SL3)
> - SL3_Estado:: ...
> - SL3_Justificacion:: ...
> - SL3_Evidencias:: ...
<%* } -%>
<%* if (targetSL >= 4) { -%>
>
> ---
> ### Nivel 4 (SL4)
> - SL4_Estado:: ...
> - SL4_Justificacion:: ...
> - SL4_Evidencias:: ...
<%* } -%>


# DASHBOARD

## ESTADO DE CUMPLIMIENTO

```dataviewjs
// ============================================================
// DASHBOARD INTEGRADO DE CUMPLIMIENTO IEC 62443
// ============================================================

// 1. CONFIGURACIÓN
// ------------------------------------------------------------
// Nivel de seguridad objetivo (Por defecto 4 si no se define en YAML)
let targetSL = dv.current().target_SL || 4;

// Diccionario para mapear siglas a Familias (FR)
const MAPA_4_1 = {
    "SM": 1, "SR": 2, "SD": 3, "SI": 4, 
    "SVV": 5, "DM": 6, "SUM": 7, "SG": 8
};

// Prefijos válidos para detectar controles en los encabezados
const PREFIJOS = "CR|SR|SM|SD|SI|SVV|DM|SUM|SG";

// 2. PROCESAMIENTO DEL CONTENIDO ACTUAL
// ------------------------------------------------------------
// Cargamos el texto crudo de la nota actual
let contenido = await dv.io.load(dv.current().file.path);

// Regex para cortar por encabezados de nivel 3 (### CR...)
let splitRegex = new RegExp(`^###\\s+(?=${PREFIJOS})`, "m");
let bloques = contenido.split(splitRegex);

let grupos = {};
let totalControles = 0;
let totalCompletados = 0; 

// Recorremos cada bloque de texto (cada control)
for (let bloque of bloques) {
    // Limpiamos espacios y validamos que empiece por un prefijo real
    let bloqueTrim = bloque.trim();
    let checkPrefixRegex = new RegExp(`^(${PREFIJOS})`);
    
    // Si el bloque no empieza por CR, SR, etc., lo saltamos (ej. introducción)
    if (!checkPrefixRegex.test(bloqueTrim)) continue;

    // Extraemos la primera línea que es el título (Ej: "CR 1.1: Human user...")
    let lineaTitulo = bloque.split("\n")[0].trim();

    // --- LÓGICA DE AGRUPACIÓN (FAMILIAS) ---
    let numFamilia = 99; 
    let nombreFamilia = "Otros";

    // Caso A: Estilo Numérico (CR 1.1) -> Familia 1
    let matchNum = lineaTitulo.match(/^(?:CR|SR)\s+(\d+)\./);
    
    // Caso B: Estilo Siglas (SM-1) -> Familia según mapa
    let matchSigla = lineaTitulo.match(/^([A-Z]+)-/);

    if (matchNum) {
        numFamilia = parseInt(matchNum[1]);
        nombreFamilia = `FR ${numFamilia}`;
    } 
    else if (matchSigla) {
        let sigla = matchSigla[1];
        if (MAPA_4_1[sigla]) {
            numFamilia = MAPA_4_1[sigla];
            nombreFamilia = `FR ${numFamilia} (${sigla})`;
        } else {
            nombreFamilia = `Práctica ${sigla}`;
        }
    }

    // Clave para ordenar correctamente en el dashboard
    let keyGrupo = `${numFamilia.toString().padStart(2, '0')}_${nombreFamilia}`;
    if (!grupos[keyGrupo]) { grupos[keyGrupo] = []; }

    // --- EXTRACCIÓN DE ESTADOS (REGEX) ---
    // Busca líneas como: "- SL1_Estado:: Cumple" o "> SL1_Estado:: ..."
    const getField = (nivel, campo) => {
        let regex = new RegExp(`[>-].*?SL${nivel}_${campo}::\\s*(.*)$`, "m");
        let match = bloque.match(regex);
        return match ? match[1].trim() : "...";
    };

    // Función para determinar el icono del semáforo
    const checkNivel = (n) => {
        let s = getField(n, "Estado");
        let j = getField(n, "Justificacion");
        let e = getField(n, "Evidencias");
        
        let sLimpio = s.toLowerCase().replace(/`/g, "").trim(); // Quitar tildes markdown

        // Lógica de Semáforo
        if (sLimpio.includes("no aplica")) return "⚪ N/A";
        if (sLimpio.includes("cumple") && !sLimpio.includes("no cumple")) return "✅ OK";
        if (sLimpio.includes("parcial") || sLimpio.includes("contramedidas")) return "⚠️ PAR";
        if (sLimpio.includes("no cumple")) return "❌ NO";
        
        // Si está vacío (los tres puntos por defecto)
        if (s === "..." && j === "..." && e === "...") return "🔴";
        
        // Si hay algo escrito pero no coincide con lo anterior
        return "📝 Rev";
    };

    // Evaluamos los niveles hasta el target
    let estados = [];
    for(let i=1; i<=targetSL; i++) {
        estados.push(checkNivel(i));
    }

    // Cálculo de progreso (Solo cuentan los ✅ OK y ⚪ N/A como completados para la barra)
    let completados = estados.filter(x => x.includes("OK") || x.includes("N/A")).length;
    totalCompletados += completados;
    totalControles++;

    // Creamos el link interno al encabezado
    let link = `[[#${lineaTitulo}|${lineaTitulo}]]`;
    grupos[keyGrupo].push([link, ...estados]);
}

// 3. RENDERIZADO DEL DASHBOARD
// ------------------------------------------------------------

let maxPuntos = totalControles * targetSL; 
let porcentajeGlobal = maxPuntos > 0 ? Math.round((totalCompletados / maxPuntos) * 100) : 0;

// Barra de progreso visual
let bloquesLlenos = Math.round((porcentajeGlobal / 100) * 20);
let barraGlobal = "▓".repeat(bloquesLlenos) + "░".repeat(20 - bloquesLlenos);

// Cabecera Principal
dv.header(2, `📊 ${dv.current().file.name}`);

dv.paragraph(`
> [!NOTE] Resumen Ejecutivo
> **Objetivo:** SL${targetSL}
> **Progreso Global:** ${barraGlobal} **${porcentajeGlobal}%**
>
> - Controles Totales: **${totalControles}**
> - Requisitos Cumplidos (o N/A): **${totalCompletados}** de **${maxPuntos}**
`);

dv.paragraph("---"); 

// Renderizado de Tablas por Familia
let clavesOrdenadas = Object.keys(grupos).sort();

// Generar cabeceras dinámicas según el Target SL
let cabecerasTabla = ["Control"];
for(let i=1; i<=targetSL; i++) cabecerasTabla.push(`SL${i}`);

for (let key of clavesOrdenadas) {
    // Quitamos el prefijo de ordenación "01_" para el título
    let tituloVisible = key.substring(3); 
    
    dv.header(3, `📂 ${tituloVisible}`);
    dv.table(cabecerasTabla, grupos[key]);
}
```

## RESUMEN


```dataviewjs
// ============================================================
// RESUMEN DETALLADO DE CUMPLIMIENTO (MISMA NOTA)
// ============================================================

// 1. CONFIGURACIÓN
// ------------------------------------------------------------
// Si no hay target_SL definido en YAML, por defecto muestra hasta SL 4
let targetSL = dv.current().target_SL || 4; 

// Prefijos para detectar los bloques de control
const PREFIJOS = "CR|SR|SM|DM|SG|SI|IC|AM|ED|FR";

// 2. PROCESAMIENTO
// ------------------------------------------------------------
// Cargamos el contenido de la nota actual
let contenido = await dv.io.load(dv.current().file.path);

// Regex para cortar por encabezados de nivel 3 (### CR...)
let splitRegex = new RegExp(`^###\\s+(?=${PREFIJOS})`, "m");
let bloques = contenido.split(splitRegex);

let filas = [];

for (let bloque of bloques) {
    // Validamos que sea un bloque de control real (y no texto introductorio)
    let bloqueTrim = bloque.trim();
    let checkPrefixRegex = new RegExp(`^(${PREFIJOS})`);
    if (!checkPrefixRegex.test(bloqueTrim)) continue;

    // Extraemos el título del control
    let lineaTitulo = bloque.split("\n")[0].trim();
    
    // Función para extraer el texto limpio de los campos ::
    const getField = (nivel, campo) => {
        let regex = new RegExp(`[>-].*?SL${nivel}_${campo}::\\s*(.*)$`, "m");
        let match = bloque.match(regex);
        return match ? match[1].trim() : "...";
    };

    // Generamos el enlace interno (ancla)
    let link = `[[#${lineaTitulo}|${lineaTitulo}]]`;

    // --- BUCLE DE NIVELES ---
    // Generamos una fila independiente para cada SL hasta el Target
    for (let i = 1; i <= targetSL; i++) {
        let s = getField(i, "Estado");
        let j = getField(i, "Justificacion");
        let e = getField(i, "Evidencias"); // Extraemos evidencias también por si acaso

        // LIMPIEZA VISUAL:
        // Si el estado es "...", lo mostramos vacío o como "Pendiente"
        // Si la justificación es "...", la mostramos vacía
        let sShow = (s === "...") ? "🔴" : s;
        let jShow = (j === "...") ? "" : j;
        
        // Concatenamos Justificación y Evidencias si existen
        let textoDetalle = jShow;
        if (e !== "..." && e !== "") {
            textoDetalle += (textoDetalle ? "<br><i>Evidencia: " + e + "</i>" : "<i>Evidencia: " + e + "</i>");
        }

        // FILTRO OPCIONAL: 
        // Si quieres ocultar las filas que no se han tocado (siguen en "..."), descomenta la línea de abajo:
        // if (s === "..." && j === "...") continue;

        // Añadimos la fila a la tabla
        filas.push([link, `**SL ${i}**`, sShow, textoDetalle]);
    }
}

// 3. RENDERIZADO
// ------------------------------------------------------------
dv.header(3, "📑 Detalle de Cumplimiento por Nivel");
dv.table(
    ["Control", "Nivel", "Estado", "Justificación / Evidencia"],
    filas
);
```



## EVIDENCIAS

```dataviewjs
// ============================================================
// GALERÍA DE EVIDENCIAS (VISTA POR TÍTULOS)
// ============================================================

// 1. CONFIGURACIÓN
let targetSL = dv.current().target_SL || 4; 
const PREFIJOS = "CR|SR|SM|DM|SG|SI|IC|AM|ED|FR";

// 2. PROCESAMIENTO
let contenido = await dv.io.load(dv.current().file.path);
let splitRegex = new RegExp(`^###\\s+(?=${PREFIJOS})`, "m");
let bloques = contenido.split(splitRegex);

let galeria = [];

// Regex para capturar nombre de archivo (ignorando el tamaño |300 si existe)
const imgRegexInternal = /!\[\[(.*?)(?:\|.*?)?\]\]/g; 
const imgRegexExternal = /!\[(.*?)\]\((.*?)\)/g;

for (let bloque of bloques) {
    let bloqueTrim = bloque.trim();
    let checkPrefixRegex = new RegExp(`^(${PREFIJOS})`);
    if (!checkPrefixRegex.test(bloqueTrim)) continue;

    let lineaTitulo = bloque.split("\n")[0].trim();
    
    // Creamos un link al control para poder saltar a él si hacemos clic en el título
    let linkControl = `[[#${lineaTitulo}|${lineaTitulo}]]`;

    for (let i = 1; i <= targetSL; i++) {
        let regexField = new RegExp(`[>-].*?SL${i}_Evidencias::\\s*(.*)$`, "m");
        let match = bloque.match(regexField);
        
        if (match && match[1]) {
            let textoEvidencia = match[1].trim();
            if (textoEvidencia === "..." || textoEvidencia === "") continue;

            // --- IMÁGENES INTERNAS ---
            let matchInternal;
            while ((matchInternal = imgRegexInternal.exec(textoEvidencia)) !== null) {
                let nombreArchivo = matchInternal[1];
                // Guardamos objeto con datos para pintar luego
                galeria.push({
                    titulo: linkControl,
                    nivel: `SL ${i}`,
                    imagen: dv.fileLink(nombreArchivo, true), // true = Embed
                    tipo: "internal"
                });
            }

            // --- IMÁGENES EXTERNAS ---
            let matchExternal;
            while ((matchExternal = imgRegexExternal.exec(textoEvidencia)) !== null) {
                galeria.push({
                    titulo: linkControl,
                    nivel: `SL ${i}`,
                    imagen: matchExternal[0], // Markdown directo
                    tipo: "external"
                });
            }
        }
    }
}

// 3. RENDERIZADO (FORMATO TÍTULOS)
if (galeria.length === 0) {
    dv.paragraph("ℹ️ *No se han detectado imágenes adjuntas.*");
} else {
    dv.header(3, `📸 Galería de Evidencias (${galeria.length})`);
    
    for (let item of galeria) {
        // Pintamos un separador
        dv.paragraph("---");
        
        // Pintamos el Título del Control y el Nivel
        dv.header(4, `${item.titulo} (Nivel ${item.nivel})`);
        
        // Pintamos la imagen
        // Si es interna (objeto Link), Dataview la renderiza.
        // Si es externa (texto markdown), Dataview la procesa.
        dv.paragraph(item.imagen);
    }
}
```