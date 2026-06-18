---
layout: post
title: "Evading EDR Callstack Telemetry: Module Stomping, Spoofing & Proxy Loading"
date: 2026-05-14 01:00:00 +0000
categories: [windows, edr, red-team]
tags: [edr-bypass, callstack, module-stomping, callstack-spoofing, proxy-loading, red-team]
description: "How EDRs use the callstack to spot shellcode loaders — and the three families of techniques used to defeat it: module stomping/overloading, callstack spoofing, and library proxy loading."
permalink: /windows/edr/callstack-evasion/2026/05/14/Callstack-Evasion.html
---

# Evading EDR Callstack Telemetry
*Module Stomping, Callstack Spoofing, and Library Proxy Loading*

---

<div class="key-concept" markdown="1">
**Executive Summary:**
Modern EDRs no longer rely solely on API hooks — they walk the **callstack** of every sensitive API call and look for anomalies: unbacked memory frames, missing NTDLL stubs, suspicious caller chains. This post breaks down how callstack inspection works and the three families of techniques used to defeat it: module stomping/overloading, callstack spoofing, and library proxy loading.
</div>

---

## Part 1: How EDRs Work

### Core components

An EDR (Endpoint Detection & Response) agent is a collection of cooperating components:

| Component | Role |
|-----------|------|
| **Agent service** | Aggregates telemetry, correlates events, sends alerts to the central server |
| **Static scanner** | Analyzes PE files and arbitrary memory regions for malicious patterns |
| **Hooking DLL** | Injected into target processes to intercept Windows API calls |
| **Kernel driver** | Injects the hooking DLL and collects kernel-level telemetry |

When the agent observes suspicious activity, it can log it, block the action, or even feed the attacker false data.

### API hooking — the user-mode reality

Hooking was historically done in the kernel, but since **PatchGuard / KPP**, this is no longer possible on x64 Windows. EDRs now hook user-mode functions — primarily the Win32 API and the native API (`ntdll.dll`), because every application interacts with them.

A hooked function gets its first bytes replaced with a `JMP` to the EDR's analysis routine:

```nasm
; Clean NtAllocateVirtualMemory
mov r10, rcx
mov eax, 0x18      ; SSN
syscall
ret

; Hooked NtAllocateVirtualMemory (EDR has patched the prologue)
jmp <EDR_handler>
...
```

### Three categories of hook evasion

| Strategy | Example technique |
|----------|------------------|
| Prevent the EDR DLL from loading | Binary signature policy (`blockdlls`) |
| Avoid the hook entirely | Direct & indirect syscalls |
| Remove the hook before calling | Perun's Fart (clean NTDLL refresh) |

These are covered in [the EDR Bypass methodology post](/windows/edr/red-team/2026/05/14/EDR-Bypass.html). What follows is the next layer of evasion — beating the **callstack telemetry** that fires even when hooks are bypassed.

---

## Part 2: PE Structure & Memory Mapping

To understand callstack-based detection, you need to know how Windows lays out a process in memory.

### PE sections that matter

| Section | Contents |
|---------|----------|
| `.text` | Executable code |
| `.data` | Initialized data |
| `.bss` | Uninitialized data |
| `.rdata` | Read-only data |
| `.edata` / `.idata` | Export / import tables |
| `.reloc` | Relocation information |
| `.rsrc` | Resources (icons, manifests) |
| `.tls` | Thread-local storage |

### Backed vs. unbacked memory

This is the single most important concept for callstack evasion:

<div class="key-concept" markdown="1">
**Backed memory:** A memory region whose contents come from a file mapping on disk — typically the `.text` section of a loaded EXE or DLL.

**Unbacked memory:** A region allocated dynamically (e.g. via `VirtualAlloc`, `malloc`) whose contents are *not* backed by any file on disk.
</div>

A shellcode loader typically does this:

```c
// Allocate RWX memory and copy shellcode into it
void *mem = VirtualAlloc(NULL, sizeof(code),
                         MEM_COMMIT | MEM_RESERVE,
                         PAGE_EXECUTE_READWRITE);
memcpy(mem, code, sizeof(code));
((void(*)())mem)();   // execute
```

The shellcode runs from an **unbacked** RWX region — and that fact alone is a strong IOC.

---

## Part 3: The Callstack

### What it is

A callstack is a LIFO stack of stack frames recording every active call in a thread. Each frame contains:

- The return address
- The function parameters
- Local variables

### Legitimate vs. suspicious callstacks

A clean call to `CreateFileA` from notepad looks like:

```
0: ntdll.dll!NtCreateFile+0x14
1: kernel32.dll!CreateFileA+0x7e
2: notepad.exe+0x109c
3: notepad.exe+0x21ef
4: notepad.exe+0x23da
```

Compare with the callstack of a beacon impersonating notepad:

```
0:  ntdll.dll!NtRequestWaitReplyPort+0x14
1:  kernel32.dll!WaitForSingleObjectEx+0x23
2:  wininet.dll!InternetReadFile+0xA7
3:  wininet.dll!HttpSendRequestW+0x1F2
4:  wininet.dll!InternetConnectW+0x138
5:  wininet.dll!InternetOpenW+0xC4
6:  notepad.exe+0x4F12
7:  notepad.exe+0x2A8E
...
```

<div class="vulnerability-alert" markdown="1">
**Detection:** notepad making outbound HTTP requests is a textbook indicator of process injection. EDRs walking the stack at the moment `InternetConnectW` is called will immediately flag this as a C2 beacon.
</div>

### Stack walking

The technique of reconstructing the chain of calls from stack frames is called **stack walking**. It is the EDR's primary tool for catching:

- Shellcode running from unbacked RWX memory (anonymous return addresses)
- Direct syscalls (no `ntdll.dll` frame at all)
- Indirect syscalls (`ntdll.dll` is there, but no high-level Win32 layer above it)

### Syscall fingerprints in the callstack

| Type | Callstack signature |
|------|---------------------|
| Direct syscall | No `ntdll.dll` frame at all → strong IOC |
| Indirect syscall | `ntdll.dll` present, but no `kernel32.dll` / `user32.dll` → suspicious |
| Normal API call | Full chain: `ntdll` → `kernelbase` → `kernel32` → caller |

This is why bypassing hooks alone is not enough. The callstack tells the EDR what really happened.

---

## Part 4: Family 1 — Module Stomping

Trick the EDR into thinking unbacked memory is actually backed.

### The idea

Instead of allocating RWX memory with `VirtualAlloc`, we **load a real, signed DLL** and overwrite its entry point with our shellcode. Execution then happens from inside the DLL's `.text` section — i.e. from backed memory.

### The steps

1. Map an arbitrary sacrificial DLL into memory
2. Resolve the address of its entry point (it sits in `.text`)
3. Change page protection to writable
4. Overwrite the entry point bytes with the shellcode
5. Restore page protection to executable
6. Call the entry point — the shellcode runs from `.text`

### Callstack effect

| Before stomping | After stomping |
|-----------------|----------------|
| `2: 0x228bcd16ef` (anonymous unbacked address) | `2: mylibrary.dll!funcA+0x12` |

The mysterious `0x228bcd16ef` frame disappears, replaced by what looks like a legitimate library function.

<div class="warning-box" markdown="1">
**Constraint:** the sacrificial DLL's `.text` section must be **larger** than your shellcode. Otherwise you risk overflowing into the next section or out of the module entirely — instant crash, instant detection. For large payloads, see module overloading below.
</div>

---

## Part 5: Family 1b — Module Overloading

A close cousin of module stomping, used when the payload is a full PE binary (EXE or DLL) rather than raw shellcode.

### Steps

1. Map an arbitrary sacrificial module in memory
2. Get the address of its base
3. Make the memory writable
4. **Overwrite the entire mapped module** with the malicious binary
5. Manually map the malicious binary (fix section protections, handle relocations)
6. Call the malicious binary's entry point

The result is the same goal as module stomping — execute from a region that appears to be a legitimately loaded module — but with enough room for a full reflective DLL.

<div class="warning-box" markdown="1">
**Caveat:** the sacrificial module must be larger than the payload. Manually performing the PE mapping (relocations, IAT resolution, section protections) is non-trivial — bugs here cause loud crashes that EDRs love.
</div>

---

## Part 6: Family 2 — Callstack Spoofing

Rather than fixing the unbacked frame, alter the callstack itself to hide it.

Two sub-families exist:

### Synthetic spoofing — non-unwindable stacks

Cheaper to implement but produces a callstack that breaks unwind algorithms. An EDR that simulates the unwinding process will notice the anomaly.

#### ThreadStackSpoofer

Overwrite the return address of the first frame under our control with `0`. Every frame below it is then ignored by stack walkers — they "disappear."

| Without spoofing | With spoofing |
|-----------------|--------------|
| 4 unbacked addresses visible (#8, #9, #10, #11) | Stack cut after frame #8; no unbacked addresses remain |

Repo: [github.com/mgeeky/ThreadStackSpoofer](https://github.com/mgeeky/ThreadStackSpoofer)

#### VulcanRaven

Build a synthetic callstack from a library of legitimate-looking pre-recorded callstacks. Overwrite the actual stack with one of these at runtime.

Repo: [github.com/WithSecureLabs/CallStackSpoofer](https://github.com/WithSecureLabs/CallStackSpoofer)

### Real spoofing — unwindable stacks

The stack remains valid for the OS unwinder but no longer reveals the caller's true origin.

#### SilentMoonwalk & Moonwalk++

At runtime, locate **ROP gadgets** dynamically and use them to desynchronize the callstack — hiding the origin of the call while keeping the stack walkable.

The result: the loader's executable name (`SilentMoonwalk.exe` in the published example) is gone from the callstack, but the stack still unwinds cleanly.

Repos:
- [github.com/klezVirus/SilentMoonwalk](https://github.com/klezVirus/SilentMoonwalk)
- [github.com/klezVirus/Moonwalk--](https://github.com/klezVirus/Moonwalk--)

<div class="key-concept" markdown="1">
**Synthetic vs. real:** synthetic spoofing is easier to implement but fails against EDRs that simulate unwinding. Real spoofing survives unwinder validation — at the cost of significantly more complex implementation (runtime gadget discovery, ROP chain construction).
</div>

---

## Part 7: Family 3 — Library Proxy Loading

Make the OS perform sensitive API calls on your behalf, so your loader never appears in the callstack.

### The problem

`LoadLibraryW` / `LoadLibraryA` are heavily monitored. A loader that needs `wininet.dll` for C2 networking will trigger an event the moment it calls `LoadLibrary` — with the loader's unbacked address sitting in the callstack.

### The trick

Windows has several APIs that **execute a user-provided callback** after some event fires. If you register `LoadLibrary` *as the callback*, the OS thread pool will load the library for you, and your loader never touches the stack at the moment of the load.

| API | Trigger |
|-----|---------|
| `RtlCreateTimer` | Callback fires when a timer expires |
| `RtlQueueWorkItem` | Callback runs on a system thread pool worker |
| `RtlRegisterWait` | Callback fires when a kernel event is signalled |

### Flow

```
Loader.exe
   ↓ calls RtlCreateTimer(callback = LoadLibrary)
Timer fires
   ↓ system thread pool executes the callback
LoadLibraryW("wininet.dll")
   ↓ wininet.dll mapped
Module address returned to loader
```

When `LoadLibrary` is executed, the callstack contains thread-pool internals — not the loader. The EDR sees a system worker thread doing its job, not malware loading network primitives.

---

## Part 8: After All That — What Still Catches You

Even with hooks bypassed, callstacks spoofed, and proxy loads in place, EDRs have one more weapon: **memory scanning**.

### Why the alert still fires

A Metasploit reverse shell will eventually call `CreateProcessW` to spawn `cmd.exe`. Process-creation APIs are extremely sensitive and trigger an **on-access memory scan** of the calling process.

The static scanner inspects the loader and the in-memory shellcode. Three Metasploit signatures match. The kernel driver receives the verdict and tells the agent to kill the process.

### Flow

```
Shellcode → CreateProcessW
              ↓ captured by kernel driver
            EDR agent → static scanner → memory scan
              ↓ 3 Metasploit signatures match
            Verdict sent back
              ↓
            Process killed
```

<div class="vulnerability-alert" markdown="1">
**Initial state:** the Metasploit payload is encrypted/obfuscated in the loader or on a web server — not detected.

**After execution:** it's decrypted, written to memory, executed. The first call to a sensitive API (process creation, in this case) triggers a memory scan that finds the now-cleartext payload sitting in RWX memory.
</div>

### Mitigations on the loader side

| Approach | What it does |
|----------|-------------|
| Patch the detected signatures | Surgical, fragile, version-dependent |
| Re-encrypt memory after execution (PE Fluctuation) | Shellcode is decrypted just-in-time and re-encrypted after use |
| Compile with **LLVM / Clang** | Different code emission patterns evade signature-based scanners written for MSVC output |

PE Fluctuation in particular addresses the root cause — the payload spending long stretches of time in memory as plaintext where a scan can catch it.

---

## Technique Summary

| Family | Technique | Defeats |
|--------|-----------|---------|
| Stomping | Module stomping | Unbacked frame detection (small payloads) |
| Stomping | Module overloading | Unbacked frame detection (full PEs) |
| Spoofing (synthetic) | ThreadStackSpoofer | Stack walkers that don't simulate unwinding |
| Spoofing (synthetic) | VulcanRaven | Same — but with realistic-looking stacks |
| Spoofing (real) | SilentMoonwalk / Moonwalk++ | Unwinder-validating EDRs |
| Proxy loading | RtlCreateTimer / RtlQueueWorkItem / RtlRegisterWait | LoadLibrary monitoring |
| Memory scan defence | PE Fluctuation, LLVM, signature patching | Triggered memory scans |

---

## Closing Thoughts

Bypassing hooks is the entry ticket. Beating the callstack telemetry is what separates a noisy POC from a loader that survives a mature EDR. The progression looks like this:

1. **Avoid the hook** — direct/indirect syscalls
2. **Hide the unbacked frame** — module stomping/overloading
3. **Hide the call origin** — callstack spoofing
4. **Don't appear at all** — library proxy loading
5. **Survive memory scans** — PE Fluctuation, encrypted shellcode lifetimes, LLVM-compiled loaders

Each layer addresses a specific telemetry source. Skipping any of them gives the EDR exactly what it needs.

---

*Based on internal red team training material by Olivier Bredin (PwC Cyber Training, January 2026), restructured and expanded for public publication.*
