[![Telegram](https://badgen.net/badge/icon/telegram?icon=telegram&label)](https://t.me/MalwareBit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![LinkedIn](https://img.shields.io/static/v1.svg?label=LinkedIn&message=@anibal&logo=linkedin&style=flat&color=blue)](https://www.linkedin.com/in/anibal-5a3870278/)

# JMP-AMSI (JIT Hooking PoC)

> ⚠️ **Disclaimer:** This tool is strictly for **educational purposes, academic research, and authorized Red Team / Blue Team operations**. The author is not responsible for any misuse, damage, or illegal activities caused by the use of this software. Do not use this tool on systems you do not own or have explicit permission to test.

*Lee este documento en Español: [README-es.md](README-es.md)*

---

## Description

**JMP-AMSI** is a Proof of Concept (PoC) script that demonstrates how to manipulate managed code pointers at runtime using .NET Reflection and JIT Detouring (Hooking). Instead of targeting traditional native DLLs, this tool intercepts the execution flow of the Antimalware Scan Interface (AMSI) managed methods within the PowerShell runtime, forcing it to return a clean status.

This project serves as an educational resource to understand how modern adversaries manipulate memory to bypass telemetry and how defenders can monitor `PAGE_EXECUTE_READWRITE` memory allocations and P/Invoke abuse.

## How it Works

Unlike traditional AMSI bypasses that overwrite `AmsiScanBuffer` (which is highly monitored and flagged by AV/EDR), JMP-AMSI operates directly on the compiled JIT (Just-In-Time) memory of the PowerShell application domain.

1. **Reflection:** It uses `.NET Reflection` to locate the target `ScanContent` method and dynamically generates a benign "Dummy" method.

2. **P/Invoke:** It avoids noisy wrappers by dynamically importing native Windows APIs like `VirtualProtect` and `FlushInstructionCache`.

3. **JIT Detour (JMP):** It obtains the native memory pointers of both methods and overwrites the first bytes of the original method with a relative jump (`JMP` or `PUSH/RET` depending on the architecture) pointing to our dynamically generated dummy method.

## Features

* **Native Memory Manipulation:** Uses precise native APIs, completely avoiding highly monitored functions like `WriteProcessMemory`.

* **In-Memory Execution:** Leaves no artifacts on disk. By avoiding the `Add-Type` cmdlet (which compiles code to a temporary DLL on disk), it evades static signature detection.

* **Multi-Architecture:** Automatically calculates pointer sizes to deploy 64-bit or 32-bit Assembly patches on the fly.

* **ETW Tail Jump Patching (Optional):** Includes an option to patch `NtTraceEvent` in `ntdll.dll` via a stealthy Tail Jump (`RET` patching) to interrupt Event Tracing for Windows telemetry at a low level.

## Usage

Run the following commands directly in a PowerShell session:

**1. Basic AMSI JIT Detour:**
```powershell
Invoke-JMPAMSI
```

**2. AMSI + ETW Telemetry Interruption:**
```powershell
Invoke-JMPAMSI -etw
```

**3. Verbose Mode (Recommended for debugging & research):**
Shows memory addresses, offsets, and JIT pointer locations in real-time.
```powershell
Invoke-JMPAMSI -v -etw
```

## Execution Example (PoC)
When running the tool in "Verbose" mode (-v), the script will dynamically reveal the managed memory addresses and assembly offsets before injecting the patch:
<img width="1066" height="788" alt="image" src="https://github.com/user-attachments/assets/83d3f7bf-5d5b-4e21-8590-b0b14794cf9a" />

## Credits
 * PowerShell Reflection techniques inspired by the research of Matt Graeber [@mattifestation](https://github.com/mattifestation/mattifestation).
 * Base memory patching logic studied from the concepts of PracSec [@pracsec](https://github.com/pracsec/AmsiBypassHookManagedAPI). 
