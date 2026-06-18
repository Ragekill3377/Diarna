#pragma once
#include <diarna/compiler_port.hpp>
#include <string>
#include <chrono>
#include <span>

namespace diarna::exec {

class PowerShellRunner {
public:
    PowerShellRunner();
    ~PowerShellRunner();

    bool initialize();
    std::string execute(const std::string& script);
    bool is_available() const;

private:
    void* clr_host_;
    bool initialized_;
};

class Executor {
public:
    struct Result {
        uint32_t exit_code;
        std::string stdout_data;
        std::string stderr_data;
        bool timed_out;
        std::chrono::milliseconds duration;
    };

    Result execute(const std::string& command,
                   std::chrono::milliseconds timeout = std::chrono::seconds(300));
    Result execute_powershell(const std::string& script,
                              std::chrono::milliseconds timeout = std::chrono::seconds(300));
    Result execute_as_user(const std::string& command, const std::string& user,
                           const std::string& pass,
                           std::chrono::milliseconds timeout = std::chrono::seconds(300));

    bool run_file(const std::wstring& path, const std::wstring& args = L"",
                  bool hidden = true);
    bool run_file_elevated(const std::wstring& path, const std::wstring& args = L"");

    static std::string whoami();
};

} // namespace diarna::exec
