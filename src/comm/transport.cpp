#include <diarna/compiler_port.hpp>
#include <diarna/comm/transport.hpp>
#include <winhttp.h>
#include <cstring>

DIARNA_LINK_LIB("winhttp.lib")

namespace diarna::comm {

StealthTransport::StealthTransport() : sock_(INVALID_SOCKET), connected_(false) { memset(&stats_,0,sizeof(stats_)); }
StealthTransport::~StealthTransport() { disconnect(); }
bool StealthTransport::configure(const FrontingConfig& cfg) { cfg_ = cfg; return true; }

bool StealthTransport::connect() {
    if (connect_fronted()) { stats_.using_doh = false; return true; }
    return false;
}

void StealthTransport::disconnect() {
    connected_ = false;
    if (sock_ != INVALID_SOCKET) { closesocket(sock_); sock_ = INVALID_SOCKET; }
}

bool StealthTransport::is_connected() const { return connected_; }

bool StealthTransport::connect_fronted() {
    HINTERNET sess = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!sess) return false;

    int wlen = MultiByteToWideChar(CP_UTF8, 0, cfg_.cdn_front.c_str(), -1, nullptr, 0);
    std::wstring wfront(wlen, 0);
    MultiByteToWideChar(CP_UTF8, 0, cfg_.cdn_front.c_str(), -1, &wfront[0], wlen);

    HINTERNET conn = WinHttpConnect(sess, wfront.c_str(), cfg_.cdn_port, 0);
    if (!conn) { WinHttpCloseHandle(sess); return false; }

    HINTERNET req = WinHttpOpenRequest(conn, L"POST", L"/", nullptr,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        cfg_.use_tls ? WINHTTP_FLAG_SECURE : 0);
    if (!req) { WinHttpCloseHandle(conn); WinHttpCloseHandle(sess); return false; }

    int hlen = MultiByteToWideChar(CP_UTF8, 0, cfg_.cdn_host.c_str(), -1, nullptr, 0);
    std::wstring whost(hlen, 0);
    MultiByteToWideChar(CP_UTF8, 0, cfg_.cdn_host.c_str(), -1, &whost[0], hlen);
    std::wstring host_hdr = L"Host: " + whost + L"\r\n";

    WinHttpAddRequestHeaders(req, host_hdr.c_str(), (DWORD)host_hdr.size(), WINHTTP_ADDREQ_FLAG_ADD);

    DWORD tmo = 30000;
    WinHttpSetOption(req, WINHTTP_OPTION_SEND_TIMEOUT, &tmo, sizeof(tmo));

    if (!WinHttpSendRequest(req, nullptr, 0, nullptr, 0, 0, 0)) {
        WinHttpCloseHandle(req); WinHttpCloseHandle(conn); WinHttpCloseHandle(sess); return false;
    }

    WinHttpCloseHandle(req); WinHttpCloseHandle(conn); WinHttpCloseHandle(sess);
    connected_ = true;
    return true;
}

bool StealthTransport::connect_doh() {
    connected_ = true; sock_ = INVALID_SOCKET;
    return true;
}

bool StealthTransport::send(std::span<const uint8_t> data) {
    if (!connected_) return false;
    stats_.fronted_sent++;
    return true;
}

std::vector<uint8_t> StealthTransport::recv(std::chrono::milliseconds) {
    if (!connected_) return {};
    stats_.fronted_recv++;
    return {};
}

StealthTransport::TransportStats StealthTransport::stats() const { return stats_; }

} // namespace diarna::comm
