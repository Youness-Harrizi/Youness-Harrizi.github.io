---
layout: post
title: "EDR Bypass: A Complete Methodology"
date: 2026-05-14 10:00:00 +0000
categories: [windows, edr, red-team]
tags: [edr-bypass, syscalls, unhooking, byovd, hell-gate, red-team]
description: "A structured deep-dive into EDR bypass techniques — from API unhooking and direct syscalls to BYOVD, Godfault, and hardware breakpoints."
permalink: /windows/edr/red-team/2026/05/14/EDR-Bypass.html
---

# EDR Bypass: A Complete Methodology
*From Userland Hooks to Kernel Silencing*

---

<div class="key-concept" markdown="1">
**Executive Summary:**
Modern EDRs (Endpoint Detection & Response) monitor process behaviour by hooking Windows API calls, injecting into processes, and deploying kernel-mode drivers. This post walks through the full spectrum of bypass techniques — ordered from the simplest userland tricks to the most invasive kernel-level approaches — based on red team research and operational tradecraft.
</div>

---

## How EDR Works

Before bypassing anything, you need to understand what you're bypassing.

### User Mode vs. Kernel Mode

Windows execution happens in two rings:

| Ring | Name | What runs there |
|------|------|-----------------|
| Ring 3 | User Mode | Processes, Win32 API, NTDLL |
| Ring 0 | Kernel Mode | Windows kernel, drivers, EDR kernel components |

When your malware calls `VirtualAllocEx` or `NtCreateThread`, execution flows through:

```
Your code → Win32 API (kernel32.dll) → Native API (ntdll.dll) → syscall → kernel
```

EDRs intercept this chain at the **ntdll.dll** boundary by **hooking**.

### What is a Hook?

An EDR hook is a 5-byte `JMP` instruction patched at the start of sensitive NTDLL functions (e.g., `NtWriteVirtualMemory`). Instead of executing the real syscall stub, execution is redirected to the EDR's analysis DLL loaded inside your process.

```nasm
; Hooked NtAllocateVirtualMemory (patched by EDR)
NtAllocateVirtualMemory:
    jmp 0x7ff812340000    ; → EDR analysis code
    ...

; Clean NtAllocateVirtualMemory (original)
NtAllocateVirtualMemory:
    mov r10, rcx
    mov eax, 0x18         ; SSN (System Service Number)
    syscall
    ret
```

<div class="vulnerability-alert" markdown="1">
**Key insight:** EDR hooks only exist in **user mode** (Ring 3). If you can avoid going through hooked NTDLL stubs, the EDR is blind to your syscall.
</div>

---

## Technique 1: API Unhooking

The oldest approach — restore the original NTDLL bytes to remove the hooks.

### How it works

1. Load a fresh copy of `ntdll.dll` from disk (or `KnownDlls`)
2. Read the `.text` section of the clean copy
3. Overwrite the in-memory `.text` section of the hooked ntdll with the clean bytes

```c
// Simplified unhooking flow
HANDLE hFile = CreateFile("C:\\Windows\\System32\\ntdll.dll", ...);
HANDLE hMap  = CreateFileMapping(hFile, NULL, PAGE_READONLY | SEC_IMAGE, ...);
LPVOID pClean = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);

// Copy .text section from clean ntdll over in-memory ntdll
memcpy(ntdllBase + textSectionOffset, cleanNtdll + textSectionOffset, textSectionSize);
```

<div class="warning-box" markdown="1">
**Detection surface:** Reading ntdll from disk generates file I/O telemetry. Overwriting in-memory pages triggers write-access hooks or guard page violations that some EDRs monitor. Modern EDRs re-hook ntdll after detecting unhooking attempts.
</div>

---

## Technique 2: Direct Syscalls

Skip NTDLL entirely. Write the syscall stub inline in your own code.

### The concept

Rather than calling `NtAllocateVirtualMemory` through ntdll (which is hooked), embed the syscall instructions directly:

```nasm
; x64 MASM — direct syscall stub
NtAllocateVirtualMemory_Direct PROC
    mov r10, rcx
    mov eax, 0x18    ; hardcoded SSN for NtAllocateVirtualMemory
    syscall
    ret
NtAllocateVirtualMemory_Direct ENDP
```

<div class="key-concept" markdown="1">
**Why this works:** The EDR hook lives in ntdll's memory. If you never jump there, the hook is never triggered. The kernel receives the syscall directly.
</div>

### The problem: hardcoded SSNs

System Service Numbers change between Windows builds. Hardcoding `0x18` works on one OS version but fails on another — which leads to dynamic SSN retrieval techniques below.

<div class="warning-box" markdown="1">
**Detection surface:** EDRs and ETW (Event Tracing for Windows) can flag `syscall` instructions executed from memory regions that are not backed by a known module (ntdll). Call stack analysis will show the origin as an anonymous RWX region — a strong IOC.
</div>

---

## Technique 3: Indirect Syscalls

A refinement of direct syscalls: execute the `syscall` instruction from **inside ntdll** to produce a clean call stack.

### Direct vs. Indirect

```
Direct syscall:   [your shellcode] → syscall instruction (in your RWX memory)
Indirect syscall: [your shellcode] → jump into ntdll stub just before syscall → syscall (in ntdll)
```

With indirect syscalls, the `syscall` instruction fires from inside ntdll's memory, making the call stack look legitimate to EDR call-stack inspectors.

```nasm
; Indirect syscall — jump into the middle of an ntdll stub
NtAllocateVirtualMemory_Indirect PROC
    mov r10, rcx
    mov eax, SSN          ; resolved at runtime
    jmp qword ptr [syscallAddr]  ; points to the 'syscall; ret' gadget in ntdll
NtAllocateVirtualMemory_Indirect ENDP
```

<div class="key-concept" markdown="1">
The `jmp` target is the address of the `syscall` + `ret` gadget inside the real ntdll stub — so from the kernel's perspective (and the EDR's call stack view), the syscall originates from ntdll.
</div>

---

## SSN Retrieval: The Gate Family

Since SSNs vary per OS build, you need to resolve them dynamically at runtime. This spawned an evolution of techniques.

### Hell's Gate (original)

Parse the in-memory ntdll to extract SSNs from the function stubs:

```c
// Hell's Gate — read the mov eax, <SSN> instruction from the ntdll stub
WORD HellsGate(LPCWSTR funcName) {
    PVOID funcAddr = GetProcAddress(ntdll, funcName);
    // Check bytes: mov r10,rcx (4c 8b d1) + mov eax,XX (b8 XX 00 00 00)
    if (*(PBYTE)(funcAddr+3) == 0xb8) {
        return *(PWORD)((PBYTE)funcAddr + 4);
    }
}
```

**Problem:** If the function is hooked, the first bytes are a `JMP` — the SSN is gone.

### Halo's Gate

If a function is hooked, scan **neighboring functions** in the syscall table (which are sequential) and calculate the target SSN by offset:

```c
// Halo's Gate — if hooked, look at adjacent syscall stubs and add/subtract offset
if (stub is hooked) {
    scan stubs above/below until clean one found;
    SSN = neighbor_SSN +/- distance;
}
```

### Tartarus Gate

An evolution of Halo's Gate that handles edge cases where multiple adjacent functions are also hooked.

### Syswhispers2 / FreshyCalls

Automated tooling that generates ASM stubs with runtime SSN resolution baked in. Syswhispers2 supports Hell's Gate, Halo's Gate, and randomised syscall ordering to hinder pattern matching.

<div class="key-concept" markdown="1">
**The progression:** Hell's Gate → Halo's Gate → Tartarus Gate → Syswhispers2 is a direct response to EDR vendors adding hooks to adjacent stubs as a countermeasure.
</div>

---

## NTDLL Refresh: Perun's Fart

Instead of resolving SSNs from a hooked ntdll, load a **completely clean copy** of ntdll and resolve everything from there.

### Sources for a clean ntdll

| Source | Method | Notes |
|--------|--------|-------|
| Disk | `CreateFile` on `ntdll.dll` | Generates file I/O events |
| KnownDlls | `\KnownDlls\ntdll.dll` object | Cleaner, less monitored |
| Suspended process | Spawn notepad, read its ntdll before EDR hooks it | Reliable, noisier |
| `NtOpenSection` | Open the ntdll section object directly | Low noise |

The loaded clean ntdll is mapped into a private memory region. SSNs and stub bytes are read from this clean copy, keeping the runtime ntdll (and its hooks) completely untouched.

---

## Blocking 3rd-Party DLLs: `blockdlls` + ACG

Prevent the EDR from injecting its hooking DLL into your process in the first place.

### Process Mitigation Policies

Windows provides process-level protections that can be set at spawn time:

```c
// Block DLLs not signed by Microsoft
PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sig = {0};
sig.MicrosoftSignedOnly = 1;
SetProcessMitigationPolicy(ProcessSignaturePolicy, &sig, sizeof(sig));

// ACG — Arbitrary Code Guard: prevents code page modification
PROCESS_MITIGATION_DYNAMIC_CODE_POLICY acg = {0};
acg.ProhibitDynamicCode = 1;
SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &acg, sizeof(acg));
```

With `blockdlls` active, the EDR cannot load its analysis DLL into the process — no injection, no hooks.

<div class="warning-box" markdown="1">
**Caveat:** These policies must be applied **before** the EDR hooks your process. They are best set as an inherited policy when spawning a sacrificial child process.
</div>

---

## BYOVD: Bring Your Own Vulnerable Driver

When user-mode techniques aren't enough, go to the kernel.

### The concept

EDRs with kernel-mode components (drivers) are immune to user-mode tricks. BYOVD loads a **legitimately signed but vulnerable** driver, then exploits its vulnerability to execute arbitrary kernel code — including terminating the EDR's kernel driver.

### Attack flow

```
1. Drop a known-vulnerable signed driver (e.g., GIGABYTE, Intel, RTCore64)
2. Load it via sc.exe or NtLoadDriver
3. Exploit the IOCTL vulnerability to get kernel R/W or code execution
4. Walk the kernel's driver list and unload/kill the EDR kernel component
5. EDR is now blind at both user and kernel level
```

<div class="vulnerability-alert" markdown="1">
**Reference tool:** EDRSandblast automates BYOVD — it ships with a vulnerable RTCore64 driver and implements the full kill chain against multiple EDR vendors.
</div>

<div class="warning-box" markdown="1">
**Microsoft's countermeasure:** The Windows Vulnerable Driver Blocklist (`DriverSiPolicy.p7b`) blocks known-bad drivers. BYOVD becomes a race between attackers finding new LOL drivers and Microsoft adding them to the blocklist.
</div>

---

## Godfault: Admin is All You Need

A technique published in 2023 that disables EDR kernel drivers using only **administrator privileges** — no vulnerable driver required.

### How it works

Godfault abuses the Windows `IDebugObject` mechanism and the way kernel page faults are handled to achieve kernel code execution from user mode, given admin rights. It targets the kernel callback table used by EDRs (`PsSetCreateProcessNotifyRoutine`, etc.) and removes their registered callbacks.

<div class="danger-box" markdown="1">
**Patched:** Microsoft addressed Godfault in **KB5034466** (released 13 April 2024). Unpatched systems (or systems where the update was rolled back) remain vulnerable.
</div>

<div class="key-concept" markdown="1">
**Impact:** Unlike BYOVD, Godfault requires no dropped file — no driver binary on disk, no `sc.exe` call. The only prerequisite is a local admin token.
</div>

---

## Hardware Breakpoints: Blindside

Use CPU debug registers (DR0–DR3) to intercept EDR hooks before they execute.

### The technique

x86/x64 CPUs have four hardware debug registers that trigger a debug exception (`#DB`) when execution hits a watched address. Blindside sets a hardware breakpoint on the EDR's hook handler, then registers a Vectored Exception Handler (VEH) to intercept the exception and redirect execution to the real syscall:

```
Execution hits hooked ntdll function
→ Hardware breakpoint fires (#DB exception)
→ VEH handler catches it before EDR's hook runs
→ VEH redirects to real syscall stub
→ EDR never sees the call
```

<div class="key-concept" markdown="1">
**Why it's powerful:** The hardware breakpoint fires before any software hook executes. The EDR's analysis code is bypassed at the CPU level, with no memory patching required.
</div>

---

## Pool Party: Windows Thread Pool Injection

A 2023 research technique (presented at Black Hat) that abuses the Windows thread pool for process injection, bypassing EDR injection detection heuristics.

### Core idea

Traditional injection (`VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread`) is heavily monitored. Pool Party injects shellcode by submitting work items to a **remote process's thread pool** — a legitimate OS mechanism that EDRs historically under-monitor.

Eight distinct variants exist, using different thread pool work item types:

- `TP_WORK` callback
- `TP_TIMER` callback
- `TP_IO` callback
- `TP_WAIT` callback
- and four more via `TpAllocAlpcCompletion`, `TpAllocJobNotification`, etc.

<div class="key-concept" markdown="1">
**Why it matters:** Each variant uses a different Windows internals path, making blanket detection difficult. EDRs must instrument each thread pool work item type individually.
</div>

---

## Advanced Techniques

### Call Stack Spoofing

EDRs inspect the call stack when a sensitive API is called. If `NtAllocateVirtualMemory` is called from an anonymous RWX region, it's flagged. Call stack spoofing manipulates return addresses on the stack to make the call appear to originate from a legitimate module (e.g., `ntdll.dll`, `kernelbase.dll`).

### APC Shellcode Execution

Queue shellcode execution via **Asynchronous Procedure Calls** (APCs) rather than creating threads. APCs fire in the context of an alertable thread, avoiding `CreateRemoteThread`-based detection.

```c
// Queue APC to an alertable thread in the target process
QueueUserAPC((PAPCFUNC)shellcodeAddr, hThread, 0);
// Force alertable state:
SleepEx(0, TRUE);
```

### Thread/Process State Manipulation

Suspend and resume threads in target processes to execute shellcode during the window where the thread is in a suspended, non-monitored state.

---

## Misc: EDR Service Rename

<div class="warning-box" markdown="1">
**Requires:** Local administrator rights and a reboot.
</div>

If you have admin rights and can tolerate a reboot, renaming the EDR service executable and rebooting removes it from the startup chain entirely. The cleanest method is safe mode:

```
1. bcdedit /set {current} safeboot minimal
2. Reboot into safe mode — EDR service does not start
3. Rename or delete the EDR executable
4. bcdedit /deletevalue {current} safeboot
5. Reboot normally — EDR is gone
```

If the drive is BitLocker-encrypted, retrieve the recovery key before rebooting (you have admin rights):

```powershell
(Get-BitLockerVolume -MountPoint C).KeyProtector
```

<div class="danger-box" markdown="1">
**Warning:** Incorrect manipulation of the boot configuration or EDR service files has bricked machines in real-world ops. Test in a lab first.
</div>

---

## Technique Summary

| Technique | EDR layer targeted | Requires kernel? | Patched / mitigated? |
|-----------|-------------------|------------------|----------------------|
| API Unhooking | User-mode hooks | No | EDR re-hooks; guard pages |
| Direct Syscalls | User-mode hooks | No | Call stack analysis |
| Indirect Syscalls | User-mode hooks | No | Partial (call stack) |
| Hell's/Halo's Gate | SSN resolution | No | Hooks on adjacent stubs |
| Perun's Fart | User-mode hooks | No | I/O telemetry |
| blockdlls + ACG | EDR DLL injection | No | Must be set early |
| BYOVD | Kernel driver | Yes | Driver blocklist |
| Godfault | Kernel callbacks | Yes | KB5034466 (Apr 2024) |
| Hardware Breakpoints | Hook execution | No | Limited detection |
| Pool Party | Injection detection | No | Per-variant telemetry |

---

## Resources

**Foundations**
- [A tale of EDR bypass methods](https://alice.climent-pommeret.red/posts/a-tale-of-edr-bypass-methods/) — intro to assembly, Windows architecture, user/kernel mode, and an overview of bypass history
- [Bypass EDR's memory protection, introduction to hooking](https://perception-point.io/blog/anti-edr-hooks/) — what hooks are and how they work

**Unhooking**
- [Bypassing Cylance and other AVs/EDRs by Unhooking Windows APIs](https://www.mdsec.co.uk/2019/03/silencing-cylance-a-case-study-in-modern-edrs/) — the classic 2019 Cylance bypass

**Syscalls**
- [AV/EDR Evasion Using Direct System Calls (User-Mode vs Kernel-Mode)](https://www.ired.team/offensive-security/defense-evasion/using-syscalls-directly-from-visual-studio-to-bypass-avs-edrs) — direct syscall fundamentals
- [Direct Syscalls vs Indirect Syscalls](https://redops.at/en/blog/direct-syscalls-vs-indirect-syscalls) — excellent comparison with code snippets
- [Hiding Your Syscalls](https://passthehashbrowns.github.io/hiding-your-syscalls) — advanced syscall concealment
- [Syscalls via Vectored Exception Handling](https://research.nccgroup.com/2021/01/23/rift-analysing-a-lazarus-shellcode-execution-method/) — used by GULOADER

**SSN Retrieval**
- [EDR Bypass: Retrieving Syscall ID with Hell's Gate, Halo's Gate, FreshyCalls and Syswhispers2](https://alice.climent-pommeret.red/posts/direct-syscalls-hells-halos-syswhispers2/) — the definitive progression guide
- [Tartarus Gate](https://github.com/trickster0/TartarusGate) — Halo's Gate evolution for multi-hooked environments

**NTDLL Refresh**
- [Perun's Fart — Sektor7 explanation](https://institute.sektor7.net/rto-maldev-intermediate) — clean ntdll loading
- [C# implementation](https://github.com/snovvcrash/NtFarante)
- [Rust implementation](https://github.com/trickster0/OffensiveRust)

**Kernel-level**
- [EDRSandblast](https://github.com/wavestone-cdt/EDRSandblast) — BYOVD + kernel callback removal
- [Forget vulnerable drivers - Admin is all you need](https://www.elastic.co/security-labs/forget-vulnerable-drivers-admin-is-all-you-need) — Godfault technical write-up
- [EDRSandblast with Godfault](https://github.com/wavestone-cdt/EDRSandblast) — no-driver variant

**Advanced**
- [Blindside: A New Technique for EDR Evasion with Hardware Breakpoints](https://cymulate.com/blog/blindside-a-new-technique-for-edr-evasion-with-hardware-breakpoints/) — DR register abuse
- [The Pool Party You Will Never Forget: New Process Injection Techniques Using Windows Thread Pools](https://www.safebreach.com/blog/process-injection-using-windows-thread-pools/) — full Pool Party research
- [Spoofing Call Stacks To Confuse EDRs](https://www.unknowncheats.me/forum/anti-cheat-bypass/268124-x64-call-stack-spoofing.html) — call stack manipulation
- [Shellcode Execution via Asynchronous Procedure Calls](https://www.ired.team/offensive-security/code-injection-process-injection/apc-queue-code-injection) — APC injection

**Reference / Aggregators**
- [ired.team](https://www.ired.team/) — comprehensive offensive security blog
- [unprotect.it](https://unprotect.it/) — MITRE-tagged bypass techniques with snippets and detection rules
- [edr-telemetry.com/windows](https://www.edr-telemetry.com/windows) — per-EDR telemetry comparison matrix
- [Bypassing User-Mode Hooks and Direct Invocation of System Calls for Red Teams](https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/) — red team-focused overview with C++ implementations
