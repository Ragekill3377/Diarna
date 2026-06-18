#pragma once
#include <diarna/compiler_port.hpp>
#include <bcrypt.h>
#include <cstdint>
#include <string>
#include <vector>
#include <array>
#include <memory>
#include <functional>
#include <atomic>
#include <thread>
#include <mutex>
#include <span>
#include <chrono>
#include <unordered_map>

DIARNA_LINK_LIB("bcrypt.lib")

namespace diarna::comm {

namespace tor_cell {
    inline constexpr uint8_t PADDING        = 0;
    inline constexpr uint8_t CREATE         = 1;
    inline constexpr uint8_t CREATED        = 2;
    inline constexpr uint8_t RELAY          = 3;
    inline constexpr uint8_t DESTROY        = 4;
    inline constexpr uint8_t CREATE_FAST    = 5;
    inline constexpr uint8_t CREATED_FAST   = 6;
    inline constexpr uint8_t VERSIONS       = 7;
    inline constexpr uint8_t NETINFO        = 8;
    inline constexpr uint8_t RELAY_EARLY    = 9;
    inline constexpr uint8_t CREATE2        = 10;
    inline constexpr uint8_t CREATED2       = 11;
    inline constexpr uint8_t VPADDING       = 128;
    inline constexpr uint8_t CERTS          = 129;
    inline constexpr uint8_t AUTH_CHALLENGE = 130;
    inline constexpr uint8_t AUTHENTICATE   = 131;
}

namespace tor_relay {
    inline constexpr uint8_t BEGIN     = 1;
    inline constexpr uint8_t DATA      = 2;
    inline constexpr uint8_t END       = 3;
    inline constexpr uint8_t CONNECTED = 4;
    inline constexpr uint8_t SENDME    = 5;
    inline constexpr uint8_t EXTEND    = 6;
    inline constexpr uint8_t EXTENDED  = 7;
    inline constexpr uint8_t TRUNCATE  = 8;
    inline constexpr uint8_t TRUNCATED = 9;
    inline constexpr uint8_t DROP      = 10;
    inline constexpr uint8_t RESOLVE   = 11;
    inline constexpr uint8_t RESOLVED  = 12;
    inline constexpr uint8_t BEGIN_DIR = 13;
    inline constexpr uint8_t EXTEND2   = 14;
    inline constexpr uint8_t EXTENDED2 = 15;
}

inline constexpr uint16_t TOR_LINK_PROTOCOL_VERSION = 4;
inline constexpr size_t   TOR_CELL_SIZE             = 514;
inline constexpr size_t   TOR_CELL_HEADER_SIZE      = 5;
inline constexpr size_t   TOR_CELL_PAYLOAD_SIZE     = 509;
inline constexpr size_t   TOR_RELAY_HEADER_SIZE     = 11;
inline constexpr size_t   TOR_RELAY_PAYLOAD_SIZE    = 498;
inline constexpr size_t   TOR_DIGEST_LEN            = 4;
inline constexpr size_t   TOR_SHA1_LEN              = 20;
inline constexpr size_t   CURVE25519_KEY_SIZE        = 32;
inline constexpr size_t   AES128_KEY_SIZE            = 16;
inline constexpr size_t   AES128_IV_SIZE             = 16;

inline constexpr uint16_t HTYPE_TAP  = 0x0000;
inline constexpr uint16_t HTYPE_NTOR = 0x0002;
inline constexpr size_t   NTOR_ONIONSKIN_SIZE = 84;
inline constexpr size_t   NTOR_REPLY_SIZE     = 64;
inline constexpr size_t   NTOR_KDF_OUT_SIZE   = 92;
inline constexpr char     NTOR_PROTOID[]      = "ntor-curve25519-sha256-1";

inline constexpr uint8_t LSTYPE_TLS_TCP_IPV4 = 0x00;
inline constexpr uint8_t LSTYPE_TLS_TCP_IPV6 = 0x01;
inline constexpr uint8_t LSTYPE_LEGACY_ID    = 0x02;
inline constexpr uint8_t LSTYPE_ED25519_ID   = 0x03;

inline constexpr uint32_t CIRCUIT_WINDOW_DEFAULT = 1000;
inline constexpr uint32_t CIRCUIT_WINDOW_REFILL  = 900;
inline constexpr uint32_t STREAM_WINDOW_DEFAULT  = 500;
inline constexpr uint32_t STREAM_WINDOW_REFILL   = 450;

struct DirAuthority {
    const char* nickname;
    const char* ip;
    uint16_t    dir_port;
    const char* fingerprint;
};

inline constexpr DirAuthority DIR_AUTHORITIES[] = {
    {"moria1",    "128.31.0.34",    9131, "9695DFC35FFEB861329B9F1AB04C46397020CE31"},
    {"tor26",     "86.59.21.38",      80, "847B1F850344D7876491A54892F904934E4EB85D"},
    {"dizum",     "45.66.33.45",      80, "7EA6EAD6FD83083C538F44038BBFA077587DD755"},
    {"gabelmoo",  "131.188.40.189",   80, "F2044413DAC2E02E3D6BCF4735A19BCA1DE97281"},
    {"dannenberg","193.23.244.244",   80, "7BE683E65D48141321C5ED92F075C55364AC7123"},
    {"maatuska",  "171.25.193.9",    443, "BD6A829255CB08E66FBE7D3748363586E46B3810"},
    {"Faravahar", "154.35.175.225",   80, "CF6D0AAFB385BE71B8E111FC5CFF4B47923733BC"},
    {"longclaw",  "199.58.81.140",    80, "74A910646BCEEFBCD2E874FC1DC997430F968145"},
    {"bastet",    "204.13.164.118",   80, "24E2F139121D4394C54B5BCC368B3B411857C413"},
};
inline constexpr size_t DIR_AUTHORITY_COUNT = sizeof(DIR_AUTHORITIES) / sizeof(DIR_AUTHORITIES[0]);

enum class RelayFlag : uint16_t {
    Authority = 1 << 0,  BadExit = 1 << 1,  Exit    = 1 << 2,
    Fast      = 1 << 3,  Guard   = 1 << 4,  HSDir   = 1 << 5,
    Running   = 1 << 6,  Stable  = 1 << 7,  Valid   = 1 << 8,
    V2Dir     = 1 << 9,
};

DIARNA_INLINE constexpr uint16_t operator|(RelayFlag a, RelayFlag b) {
    return static_cast<uint16_t>(a) | static_cast<uint16_t>(b);
}
DIARNA_INLINE constexpr uint16_t operator|(uint16_t a, RelayFlag b) {
    return a | static_cast<uint16_t>(b);
}
DIARNA_INLINE constexpr bool has_flags(uint16_t set, uint16_t required) {
    return (set & required) == required;
}

inline constexpr uint16_t GUARD_FLAGS  = RelayFlag::Guard | RelayFlag::Fast | RelayFlag::Running | RelayFlag::Valid;
inline constexpr uint16_t MIDDLE_FLAGS = RelayFlag::Fast  | RelayFlag::Running | RelayFlag::Valid;
inline constexpr uint16_t EXIT_FLAGS   = RelayFlag::Exit  | RelayFlag::Fast | RelayFlag::Running | RelayFlag::Valid;

struct BcryptAlgDeleter  { void operator()(BCRYPT_ALG_HANDLE h)  const { if (h) BCryptCloseAlgorithmProvider(h, 0); } };
struct BcryptKeyDeleter  { void operator()(BCRYPT_KEY_HANDLE h)  const { if (h) BCryptDestroyKey(h); } };
struct BcryptHashDeleter { void operator()(BCRYPT_HASH_HANDLE h) const { if (h) BCryptDestroyHash(h); } };

using AlgHandle  = std::unique_ptr<void, BcryptAlgDeleter>;
using KeyHandle  = std::unique_ptr<void, BcryptKeyDeleter>;
using HashHandle = std::unique_ptr<void, BcryptHashDeleter>;

struct TorRelay {
    std::string          nickname;
    std::array<char, 41> fingerprint{};
    std::string          ip;
    uint16_t             or_port   = 0;
    uint16_t             dir_port  = 0;
    uint16_t             flags     = 0;
    uint32_t             bandwidth = 0;
    std::array<uint8_t, CURVE25519_KEY_SIZE> ntor_onion_key{};
    std::array<uint8_t, TOR_SHA1_LEN>        identity{};
};

struct HopCryptoState {
    KeyHandle  forward_aes;
    KeyHandle  backward_aes;
    HashHandle forward_digest;
    HashHandle backward_digest;
    std::array<uint8_t, AES128_IV_SIZE> forward_iv{};
    std::array<uint8_t, AES128_IV_SIZE> backward_iv{};
};

enum class CircuitState : uint8_t { Init, Creating, Extending, Ready, Destroyed };

struct TorCircuit {
    uint32_t                      circ_id        = 0;
    std::array<TorRelay, 3>       hops{};
    std::array<HopCryptoState, 3> crypto{};
    CircuitState                  state          = CircuitState::Init;
    SOCKET                        entry_socket   = INVALID_SOCKET;
    uint32_t                      send_window    = CIRCUIT_WINDOW_DEFAULT;
    uint32_t                      recv_window    = CIRCUIT_WINDOW_DEFAULT;
    uint32_t                      next_stream_id = 1;
    std::chrono::steady_clock::time_point created;
};

struct TorStream {
    uint32_t stream_id   = 0;
    uint32_t circuit_id  = 0;
    uint32_t send_window = STREAM_WINDOW_DEFAULT;
    uint32_t recv_window = STREAM_WINDOW_DEFAULT;
    bool     connected   = false;
};

class TorEmbeddedClient {
public:
    static TorEmbeddedClient& instance();

    bool initialize(const wchar_t* data_dir = L"Diarna_tor_data");
    void shutdown();
    bool is_ready() const;

    TorCircuit* build_circuit();
    bool        destroy_circuit(TorCircuit* circuit);
    bool        circuit_send(TorCircuit* circuit, uint32_t stream_id,
                             std::span<const uint8_t> data);
    bool        circuit_recv(TorCircuit* circuit, uint32_t& stream_id,
                             std::vector<uint8_t>& data, int timeout_ms = 30000);
    bool        circuit_connect(TorCircuit* circuit, const std::string& host,
                                uint16_t port, uint32_t& stream_id);

    std::vector<TorRelay> get_current_relays() const;

    struct Stats {
        uint32_t circuits_built    = 0;
        uint32_t circuits_failed   = 0;
        uint64_t bytes_sent        = 0;
        uint64_t bytes_received    = 0;
        uint32_t consensus_fetches = 0;
        std::chrono::steady_clock::time_point last_consensus;
    };
    Stats stats() const;

private:
    TorEmbeddedClient();
    ~TorEmbeddedClient();
    TorEmbeddedClient(const TorEmbeddedClient&)            = delete;
    TorEmbeddedClient& operator=(const TorEmbeddedClient&) = delete;

    bool download_consensus();
    bool parse_consensus(std::span<const uint8_t> raw);
    void consensus_refresh_loop();

    TorRelay               select_relay(uint16_t required_flags,
                                        const std::vector<std::string>& exclude_fps = {});
    std::array<TorRelay,3> select_circuit_path();

    bool tls_connect(SOCKET sock, const TorRelay& relay);
    bool negotiate_versions(SOCKET sock);
    bool send_netinfo(SOCKET sock);

    bool send_cell(SOCKET sock, uint32_t circ_id, uint8_t command,
                   std::span<const uint8_t> payload);
    bool recv_cell(SOCKET sock, uint32_t& circ_id, uint8_t& command,
                   std::vector<uint8_t>& payload, int timeout_ms = 30000);

    bool create_fast(TorCircuit* circuit);
    bool create2_ntor(TorCircuit* circuit, int hop);
    bool extend2_ntor(TorCircuit* circuit, int hop);

    std::vector<uint8_t> build_extend2_payload(
        const TorRelay& target,
        std::span<const uint8_t, CURVE25519_KEY_SIZE> client_pk);

    bool ntor_client_handshake(const TorRelay& relay,
                               std::array<uint8_t, CURVE25519_KEY_SIZE>& client_pk,
                               std::array<uint8_t, CURVE25519_KEY_SIZE>& client_sk);
    bool ntor_client_finish(const TorRelay& relay,
                            std::span<const uint8_t, CURVE25519_KEY_SIZE> client_pk,
                            std::span<const uint8_t, CURVE25519_KEY_SIZE> client_sk,
                            std::span<const uint8_t> server_handshake,
                            std::array<uint8_t, NTOR_KDF_OUT_SIZE>& key_material);
    bool ntor_kdf(std::span<const uint8_t> secret_input,
                  std::span<uint8_t> output);

    bool curve25519_keygen(std::array<uint8_t, CURVE25519_KEY_SIZE>& pub_key,
                           std::array<uint8_t, CURVE25519_KEY_SIZE>& priv_key);
    bool curve25519_shared_secret(
        std::span<const uint8_t, CURVE25519_KEY_SIZE> our_priv,
        std::span<const uint8_t, CURVE25519_KEY_SIZE> their_pub,
        std::array<uint8_t, CURVE25519_KEY_SIZE>& shared);

    void install_hop_keys(TorCircuit* circuit, int hop,
                          std::span<const uint8_t, NTOR_KDF_OUT_SIZE> km);

    KeyHandle create_aes_ctr_key(std::span<const uint8_t, AES128_KEY_SIZE> key);
    void      aes_ctr_crypt(BCRYPT_KEY_HANDLE key_h,
                            std::array<uint8_t, AES128_IV_SIZE>& iv,
                            std::span<uint8_t> data);

    HashHandle create_sha1_digest();
    void       digest_update(BCRYPT_HASH_HANDLE h, std::span<const uint8_t> data);
    std::array<uint8_t, TOR_DIGEST_LEN> digest_peek(BCRYPT_HASH_HANDLE h);

    void relay_encrypt_forward(TorCircuit* circuit,
                               std::span<uint8_t> cell_payload);
    void relay_decrypt_backward(TorCircuit* circuit,
                                std::span<uint8_t> cell_payload,
                                int& recognized_hop);

    std::array<uint8_t, TOR_CELL_PAYLOAD_SIZE>
        build_relay_cell(uint8_t relay_cmd, uint16_t stream_id,
                         std::span<const uint8_t> payload);

    void check_sendme(TorCircuit* circuit, int hop);
    static uint32_t allocate_circ_id();

    bool load_pinned_guard(TorRelay& out);
    void save_pinned_guard(const TorRelay& guard);

    std::vector<TorRelay>                    relays_;
    mutable std::mutex                       relays_mutex_;
    std::vector<std::unique_ptr<TorCircuit>> circuits_;
    mutable std::mutex                       circuits_mutex_;
    std::unordered_map<uint32_t, TorStream>  streams_;
    std::mutex                               streams_mutex_;
    std::atomic<bool>                        ready_{false};
    std::atomic<bool>                        running_{false};
    std::thread                              consensus_thread_;
    mutable std::mutex                       stats_mutex_;
    Stats                                    stats_;
    std::wstring                             data_dir_;
    std::string                              pinned_guard_fp_;
};

} // namespace diarna::comm
