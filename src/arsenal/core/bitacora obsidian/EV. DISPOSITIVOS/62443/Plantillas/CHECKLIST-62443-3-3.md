<%*
// 1. PREGUNTAR EL NIVEL DE SEGURIDAD AL CREAR LA NOTA
let inputSL = await tp.system.prompt("Introduce el Nivel de Seguridad Objetivo (1-4)", "3");
let targetSL = parseInt(inputSL);
if (isNaN(targetSL) || targetSL < 1 || targetSL > 4) { targetSL = 3; }
-%>
---
tags:
  - auditoria
  - iec62443-3-3
  - sistema
  - evidencia
audit_file: <% tp.file.title %>
target_SL: <% targetSL %>
---

# IEC 62443-3-3: Auditoría de Sistema - <% tp.file.title %>

> [!DANGER] INSTRUCCIONES
> **Nivel de Seguridad Objetivo:** SL<% targetSL %>
> Esta nota evalúa los **Requisitos del Sistema (SR)** según la norma IEC 62443-3-3.
> 1. Rellena los campos `::` con el estado y la justificación.
> 2. Los dashboards al final de la nota se actualizarán automáticamente.

## FR 1: Identification and authentication control

### SR 1.1: Human user identification and authentication
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

### SR 1.2: Software process and device identification and authentication
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

### SR 1.3: Account management
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

### SR 1.4: Identifier management
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

### SR 1.5: Authenticator management
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

### SR 1.6: Wireless access management
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

### SR 1.7: Strength of password-based authentication
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

### SR 1.8: Public key infrastructure certificates
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

### SR 1.9: Strength of public key-based authentication
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

### SR 1.10: Authenticator feedback
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

### SR 1.11: Unsuccessful login attempts
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

### SR 1.12: System use notification
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

### SR 1.13: Access via untrusted networks
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

## FR 2: Use control

### SR 2.1: Authorization enforcement
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

### SR 2.2: Wireless use control
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

### SR 2.3: Use control for portable and mobile devices
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

### SR 2.4: Mobile code
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

### SR 2.5: Session lock
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

### SR 2.6: Remote session termination
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

### SR 2.7: Concurrent session control
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

### SR 2.8: Auditable events
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

### SR 2.9: Audit storage capacity
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

### SR 2.10: Response to audit processing failures
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

### SR 2.11: Timestamps
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

### SR 2.12: Non-repudiation
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

## FR 3: System integrity

### SR 3.1: Communication integrity
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

### SR 3.2: Protection from malicious code
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

### SR 3.3: Security functionality verification
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

### SR 3.4: Software and information integrity
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

### SR 3.5: Input validation
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

### SR 3.6: Deterministic output
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

### SR 3.7: Error handling
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

### SR 3.8: Session integrity
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

### SR 3.9: Protection of audit information
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

## FR 4: Data confidentiality

### SR 4.1: Information confidentiality
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

### SR 4.2: Information persistence
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

### SR 4.3: Use of cryptography
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

## FR 5: Restricted data flow

### SR 5.1: Network segmentation
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

### SR 5.2: Zone boundary protection
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

### SR 5.3: General purpose person-to-person communication restrictions
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

### SR 5.4: Application partitioning
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

## FR 6: Timely response to events

### SR 6.1: Audit log accessibility
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

### SR 6.2: Continuous monitoring
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

## FR 7: Resource availability

### SR 7.1: Denial of service protection
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

### SR 7.2: Resource management
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

### SR 7.3: Control system backup
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

### SR 7.4: Control system recovery and reconstitution
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

### SR 7.5: Emergency power
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

### SR 7.6: Network and security configuration settings
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

### SR 7.7: Least functionality
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

### SR 7.8: Control system component inventory
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