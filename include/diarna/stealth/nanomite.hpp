#pragma once
#include <diarna/compiler_port.hpp>
#include <string>
#include <cstdint>
#include <vector>
#include <functional>
#include <atomic>
#include <mutex>

namespace diarna::stealth {

class NanomiteEngine {
public:
    static NanomiteEngine& instance();

    enum class EmulatorType {
        None,
        QEMU_Userspace,
        QEMU_System,
        Unicorn,
        Triton,
        Pin,
        DynamoRIO,
        Windbg_Emulation,
        x64dbg_ScyllaHide,
        Hypervisor_Emulation,
        UnknownEmulator
    };

    struct EmulatorCheck {
        std::string name;
        EmulatorType detected;
        double confidence;
        std::string evidence;
    };

    bool is_emulated();
    std::vector<EmulatorCheck> full_emulator_scan();
    EmulatorType identify_emulator();
    void install_traps();
    void remove_traps();

    bool install_rdtsc_nanomite();
    bool install_cpuid_nanomite();
    bool install_cache_nanomite();
    bool install_fpu_nanomite();
    bool install_sse_nanomite();
    bool install_branch_prediction_trap();
    bool install_cr8_access_trap();
    bool install_sidt_sgdt_trap();
    bool install_cache_coherency_trap();
    bool install_memory_timing_trap();
    bool install_stack_pivot_trap();

private:
    NanomiteEngine();
    ~NanomiteEngine();

    static LONG WINAPI emulation_veh(EXCEPTION_POINTERS* ex_info);

    bool check_xgetbv_support();
    bool check_tsx_support();
    bool check_smap_support();
    bool check_memory_discrepancy();
    bool check_instruction_timing();
    bool check_cache_line_size();
    bool check_tlb_behavior();
    bool check_prefetch_behavior();
    bool check_fxsave_size();
    bool check_xsave_size();
    bool check_msr_behavior();
    bool check_ldmxcsr_exceptions();
    bool check_denormal_floats();
    bool check_modr_m_discrepancy();
    bool check_lock_prefix_behavior();

    std::atomic<bool> traps_installed_{false};
    void* veh_handle_;
    mutable std::mutex check_mutex_;
    std::vector<EmulatorCheck> cached_results_;
    std::chrono::steady_clock::time_point last_full_scan_;
};

struct NanoTrap {
    void* code_addr;
    uint8_t original_byte;
    bool is_substituted;
    std::function<bool()> validator;
};

} // namespace diarna::stealth
