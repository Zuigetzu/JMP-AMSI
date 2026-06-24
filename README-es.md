[![Telegram](https://badgen.net/badge/icon/telegram?icon=telegram&label)](https://t.me/MalwareBit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![LinkedIn](https://img.shields.io/static/v1.svg?label=LinkedIn&message=@anibal&logo=linkedin&style=flat&color=blue)](https://www.linkedin.com/in/anibal-5a3870278/)

# JMP-AMSI (JIT Hooking PoC)

> ⚠️ **Aviso Legal:** Esta herramienta es estrictamente para **fines educativos, investigación académica y operaciones autorizadas de Red Team / Blue Team**. El autor no se hace responsable de ningún mal uso, daño o actividad ilegal causada por el uso de este software. No utilice esta herramienta en sistemas que no sean de su propiedad o para los que no tenga permiso explícito de prueba.

*Read this document in English: [README.md](README.md)*

---

## Descripción

**JMP-AMSI** es un script de Prueba de Concepto (PoC) que demuestra cómo manipular punteros de código administrado en tiempo de ejecución utilizando Reflexión en .NET y desvíos JIT (JIT Detouring / Hooking). En lugar de apuntar a las DLLs nativas tradicionales, esta herramienta intercepta el flujo de ejecución de los métodos de la interfaz AMSI dentro de PowerShell, forzándola a devolver un estado limpio.

Este proyecto es un recurso educativo para comprender cómo los adversarios modernos manipulan la memoria para evadir telemetría, y cómo los defensores (Blue Teams) pueden monitorizar asignaciones de memoria `PAGE_EXECUTE_READWRITE` y el abuso de P/Invoke.

## ¿Cómo Funciona?

A diferencia de los bypasses tradicionales que sobrescriben `AmsiScanBuffer` (lo cual está altamente monitorizado por AV/EDR), JMP-AMSI opera directamente sobre la memoria compilada JIT (Just-In-Time) del dominio de la aplicación.

1. **Reflexión:** Utiliza `.NET Reflection` para localizar el método objetivo `ScanContent` y genera dinámicamente un método "Dummy" benigno.

2. **P/Invoke:** Evita envolturas ruidosas importando dinámicamente APIs nativas de Windows como `VirtualProtect` y `FlushInstructionCache`.

3. **Desvío JIT (JMP):** Obtiene los punteros de memoria nativos de ambos métodos y sobrescribe los primeros bytes del método original con un salto (`JMP` o `PUSH/RET` según la arquitectura) que apunta a nuestro método generado dinámicamente.

## Características

* **Manipulación de Memoria Nativa:** Utiliza APIs nativas precisas, evitando por completo funciones altamente vigiladas como `WriteProcessMemory`.

* **Ejecución 100% en Memoria:** No deja artefactos en disco. Al evitar el uso del cmdlet `Add-Type` (que compila código en una DLL temporal en el disco), evade la detección de firmas estáticas.

* **Multi-Arquitectura:** Calcula automáticamente los tamaños de los punteros para desplegar parches de Ensamblador (Assembly) de 64 o 32 bits sobre la marcha.

* **Parcheo de ETW (Opcional):** Incluye una opción para aplicar un parche directamente a `NtTraceEvent` en `ntdll.dll` mediante un sigiloso Tail Jump (parcheo `RET`), interrumpiendo la telemetría de eventos de Windows a bajo nivel.

## Uso

Ejecuta los siguientes comandos directamente en una sesión de PowerShell:

**1. Desvío JIT de AMSI básico:**
```powershell
Invoke-JMPAMSI
```

**2. Interrupción de telemetría de AMSI + ETW:**
```powershell
Invoke-JMPAMSI -etw
```

**3. Modo Detallado (Recomendado para depuración e investigación):**
Muestra direcciones de memoria, desplazamientos (offsets) y ubicaciones de punteros JIT en tiempo real.
```powershell
Invoke-JMPAMSI -v -etw
```

## Ejemplo de Ejecución (PoC)
Al ejecutar la herramienta en modo "Verbose" (-v), el script revelará dinámicamente las direcciones de memoria administradas y los desplazamientos en ensamblador antes de inyectar el parche:
<img width="1066" height="788" alt="image" src="https://github.com/user-attachments/assets/83d3f7bf-5d5b-4e21-8590-b0b14794cf9a" />

## Créditos

* Técnicas de reflexión de PowerShell inspiradas en la investigación de Matt Graeber [@mattifestation](https://github.com/mattifestation/mattifestation).
* Lógica de parcheo de memoria base estudiada a partir de los conceptos de PracSec [@pracsec](https://github.com/pracsec/AmsiBypassHookManagedAPI).