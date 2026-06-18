#include <diarna/compiler_port.hpp>
#include <diarna/comm/tor_client.hpp>

#include <winhttp.h>
#include <algorithm>
#include <cstring>

DIARNA_LINK_LIB("ws2_32.lib")
DIARNA_LINK_LIB("winhttp.lib")
DIARNA_LINK_LIB("bcrypt.lib")

#ifndef BCRYPT_ECDH_ALGORITHM
#define BCRYPT_ECDH_ALGORITHM L"ECDH"
#endif
#ifndef BCRYPT_ECC_CURVE_NAME
#define BCRYPT_ECC_CURVE_NAME L"ECCCurveName"
#endif
#ifndef BCRYPT_ECC_CURVE_25519
#define BCRYPT_ECC_CURVE_25519 L"curve25519"
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

namespace diarna::comm {

static BCRYPT_ALG_HANDLE aes_ecb_alg() {
    static BCRYPT_ALG_HANDLE h = [] {
        BCRYPT_ALG_HANDLE a = nullptr;
        BCryptOpenAlgorithmProvider(&a, BCRYPT_AES_ALGORITHM, nullptr, 0);
        BCryptSetProperty(a, BCRYPT_CHAINING_MODE,
                          reinterpret_cast<PUCHAR>(
                              const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_ECB)),
                          sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
        return a;
    }();
    return h;
}

static BCRYPT_ALG_HANDLE sha1_alg() {
    static BCRYPT_ALG_HANDLE h = [] {
        BCRYPT_ALG_HANDLE a = nullptr;
        BCryptOpenAlgorithmProvider(&a, BCRYPT_SHA1_ALGORITHM, nullptr, 0);
        return a;
    }();
    return h;
}

static BCRYPT_ALG_HANDLE hmac256_alg() {
    static BCRYPT_ALG_HANDLE h = [] {
        BCRYPT_ALG_HANDLE a = nullptr;
        BCryptOpenAlgorithmProvider(&a, BCRYPT_SHA256_ALGORITHM, nullptr,
                                    BCRYPT_ALG_HANDLE_HMAC_FLAG);
        return a;
    }();
    return h;
}

static bool gen_random(void* buf, uint32_t len) {
    return NT_SUCCESS(BCryptGenRandom(nullptr,
        static_cast<PUCHAR>(buf), len, BCRYPT_USE_SYSTEM_PREFERRED_RNG));
}

static void pack_be32(uint8_t* d, uint32_t v) {
    d[0] = static_cast<uint8_t>(v >> 24); d[1] = static_cast<uint8_t>(v >> 16);
    d[2] = static_cast<uint8_t>(v >> 8);  d[3] = static_cast<uint8_t>(v);
}

static uint32_t unpack_be32(const uint8_t* s) {
    return (uint32_t(s[0]) << 24) | (uint32_t(s[1]) << 16) |
           (uint32_t(s[2]) << 8)  |  uint32_t(s[3]);
}

static void pack_be16(uint8_t* d, uint16_t v) {
    d[0] = static_cast<uint8_t>(v >> 8); d[1] = static_cast<uint8_t>(v);
}

static uint16_t unpack_be16(const uint8_t* s) {
    return static_cast<uint16_t>((s[0] << 8) | s[1]);
}

static bool sock_send_all(SOCKET s, const uint8_t* p, int n) {
    int sent = 0;
    while (sent < n) {
        int r = ::send(s, reinterpret_cast<const char*>(p + sent), n - sent, 0);
        if (r <= 0) return false;
        sent += r;
    }
    return true;
}

static bool sock_recv_all(SOCKET s, uint8_t* p, int n) {
    int got = 0;
    while (got < n) {
        int r = ::recv(s, reinterpret_cast<char*>(p + got), n - got, 0);
        if (r <= 0) return false;
        got += r;
    }
    return true;
}

static bool sha1_hash(const uint8_t* data, size_t len, uint8_t out[20]) {
    BCRYPT_HASH_HANDLE h = nullptr;
    if (!NT_SUCCESS(BCryptCreateHash(sha1_alg(), &h, nullptr, 0,
                                      nullptr, 0, 0)))
        return false;
    bool ok = NT_SUCCESS(BCryptHashData(h, const_cast<PUCHAR>(data),
                                         static_cast<ULONG>(len), 0)) &&
              NT_SUCCESS(BCryptFinishHash(h, out, 20, 0));
    BCryptDestroyHash(h);
    return ok;
}

static bool hmac_sha256(const uint8_t* key, size_t klen,
                         const uint8_t* data, size_t dlen,
                         uint8_t out[32]) {
    BCRYPT_HASH_HANDLE h = nullptr;
    if (!NT_SUCCESS(BCryptCreateHash(hmac256_alg(), &h, nullptr, 0,
                                      const_cast<PUCHAR>(key),
                                      static_cast<ULONG>(klen), 0)))
        return false;
    bool ok = NT_SUCCESS(BCryptHashData(h, const_cast<PUCHAR>(data),
                                         static_cast<ULONG>(dlen), 0)) &&
              NT_SUCCESS(BCryptFinishHash(h, out, 32, 0));
    BCryptDestroyHash(h);
    return ok;
}

static uint16_t flag_from_string(const std::string& s) {
    if (s == "Authority") return static_cast<uint16_t>(RelayFlag::Authority);
    if (s == "BadExit")   return static_cast<uint16_t>(RelayFlag::BadExit);
    if (s == "Exit")      return static_cast<uint16_t>(RelayFlag::Exit);
    if (s == "Fast")      return static_cast<uint16_t>(RelayFlag::Fast);
    if (s == "Guard")     return static_cast<uint16_t>(RelayFlag::Guard);
    if (s == "HSDir")     return static_cast<uint16_t>(RelayFlag::HSDir);
    if (s == "Running")   return static_cast<uint16_t>(RelayFlag::Running);
    if (s == "Stable")    return static_cast<uint16_t>(RelayFlag::Stable);
    if (s == "Valid")     return static_cast<uint16_t>(RelayFlag::Valid);
    if (s == "V2Dir")     return static_cast<uint16_t>(RelayFlag::V2Dir);
    return 0;
}

static uint32_t ip_to_net(const std::string& ip) {
    struct in_addr a{};
    inet_pton(AF_INET, ip.c_str(), &a);
    uint32_t v;
    std::memcpy(&v, &a, 4);
    return v;
}

TorEmbeddedClient& TorEmbeddedClient::instance() {
    static TorEmbeddedClient c;
    return c;
}

TorEmbeddedClient::TorEmbeddedClient() {
    WSADATA w;
    WSAStartup(MAKEWORD(2, 2), &w);
}

TorEmbeddedClient::~TorEmbeddedClient() { shutdown(); }

bool TorEmbeddedClient::initialize(const wchar_t* data_dir) {
    data_dir_ = data_dir;
    CreateDirectoryW(data_dir, nullptr);
    if (!download_consensus()) return false;
    {
        std::lock_guard lk(relays_mutex_);
        if (relays_.size() < 1000) return false;
    }
    ready_ = true;
    running_ = true;
    consensus_thread_ = std::thread(&TorEmbeddedClient::consensus_refresh_loop, this);
    return true;
}

void TorEmbeddedClient::shutdown() {
    running_ = false;
    ready_ = false;
    if (consensus_thread_.joinable()) consensus_thread_.join();
    {
        std::lock_guard lk(circuits_mutex_);
        for (auto& c : circuits_) {
            if (c && c->entry_socket != INVALID_SOCKET) {
                closesocket(c->entry_socket);
                c->entry_socket = INVALID_SOCKET;
            }
        }
        circuits_.clear();
    }
}

bool TorEmbeddedClient::is_ready() const { return ready_; }

void TorEmbeddedClient::consensus_refresh_loop() {
    while (running_) {
        Sleep(3600000);
        if (running_) download_consensus();
    }
}

bool TorEmbeddedClient::download_consensus() {
    for (size_t i = 0; i < DIR_AUTHORITY_COUNT && running_; ++i) {
        wchar_t host[64];
        MultiByteToWideChar(CP_ACP, 0, DIR_AUTHORITIES[i].ip, -1,
                            host, 64);

        HINTERNET ses = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, nullptr, nullptr, 0);
        if (!ses) continue;

        DWORD tmo = 30000;
        WinHttpSetTimeouts(ses, tmo, tmo, tmo, tmo);

        uint16_t port = DIR_AUTHORITIES[i].dir_port;
        HINTERNET con = WinHttpConnect(ses, host, port, 0);
        if (!con) { WinHttpCloseHandle(ses); continue; }

        DWORD flags = (port == 443) ? WINHTTP_FLAG_SECURE : 0;
        HINTERNET req = WinHttpOpenRequest(con, L"GET",
            L"/tor/status-vote/current/consensus",
            nullptr, nullptr, nullptr, flags);
        if (!req) { WinHttpCloseHandle(con); WinHttpCloseHandle(ses); continue; }

        bool ok = false;
        if (WinHttpSendRequest(req, nullptr, 0, nullptr, 0, 0, 0) &&
            WinHttpReceiveResponse(req, nullptr)) {
            std::vector<uint8_t> body;
            body.reserve(4u << 20);
            char buf[8192]; DWORD rd = 0;
            while (WinHttpReadData(req, buf, sizeof(buf), &rd) && rd > 0) {
                body.insert(body.end(), buf, buf + rd);
                rd = 0;
            }
            if (body.size() > 500000 && parse_consensus(body)) {
                std::lock_guard lk(stats_mutex_);
                stats_.last_consensus = std::chrono::steady_clock::now();
                stats_.consensus_fetches++;
                ok = true;
            }
        }
        WinHttpCloseHandle(req);
        WinHttpCloseHandle(con);
        WinHttpCloseHandle(ses);
        if (ok) return true;
    }
    return false;
}

bool TorEmbeddedClient::parse_consensus(std::span<const uint8_t> raw) {
    std::string text(raw.begin(), raw.end());
    std::vector<TorRelay> parsed;
    parsed.reserve(8000);
    TorRelay cur{};
    bool have = false;

    size_t pos = 0;
    while (pos < text.size()) {
        size_t eol = text.find('\n', pos);
        if (eol == std::string::npos) eol = text.size();
        size_t len = eol - pos;
        if (len > 0 && text[eol - 1] == '\r') --len;
        std::string line = text.substr(pos, len);
        pos = eol + 1;
        if (line.empty()) continue;

        if (line.size() > 2 && line[0] == 'r' && line[1] == ' ') {
            if (have && cur.or_port != 0) parsed.push_back(std::move(cur));
            cur = TorRelay{};
            have = true;

            std::vector<size_t> sp;
            sp.push_back(2);
            for (size_t p = 2; p < line.size(); ++p)
                if (line[p] == ' ') sp.push_back(p + 1);

            auto field = [&](int idx) -> std::string {
                if (idx >= static_cast<int>(sp.size())) return {};
                size_t start = sp[idx];
                size_t end = (idx + 1 < static_cast<int>(sp.size()))
                    ? sp[idx + 1] - 1 : line.size();
                return line.substr(start, end - start);
            };

            cur.nickname = field(0);

            std::string fp_b64 = field(1);
            (void)fp_b64;

            if (sp.size() > 5) cur.ip = field(4);
            if (sp.size() > 6) cur.or_port = static_cast<uint16_t>(
                std::strtoul(field(5).c_str(), nullptr, 10));
            if (sp.size() > 7) cur.dir_port = static_cast<uint16_t>(
                std::strtoul(field(6).c_str(), nullptr, 10));

        } else if (line.size() > 2 && line[0] == 's' && line[1] == ' ') {
            size_t sp = 2;
            while (sp < line.size()) {
                size_t ne = line.find(' ', sp);
                if (ne == std::string::npos) ne = line.size();
                if (ne > sp)
                    cur.flags |= flag_from_string(line.substr(sp, ne - sp));
                sp = ne + 1;
            }
        } else if (line.size() > 2 && line[0] == 'w' && line[1] == ' ') {
            auto eq = line.find('=');
            if (eq != std::string::npos)
                cur.bandwidth = static_cast<uint32_t>(
                    std::strtoul(line.c_str() + eq + 1, nullptr, 10));
        }
    }
    if (have && cur.or_port != 0) parsed.push_back(std::move(cur));

    if (parsed.size() < 1000) return false;

    {
        std::lock_guard lk(relays_mutex_);
        relays_ = std::move(parsed);
    }
    return true;
}

TorRelay TorEmbeddedClient::select_relay(
        uint16_t required_flags,
        const std::vector<std::string>& exclude_fps) {
    std::lock_guard lk(relays_mutex_);
    std::vector<TorRelay*> cands;
    cands.reserve(relays_.size());

    for (auto& r : relays_) {
        if (r.or_port == 0 || r.ip.empty()) continue;
        if (!has_flags(r.flags, required_flags)) continue;
        bool excluded = false;
        for (auto& fp : exclude_fps)
            if (r.fingerprint.data() == fp) { excluded = true; break; }
        if (!excluded) cands.push_back(&r);
    }

    if (cands.empty()) return relays_.front();

    uint64_t total = 0;
    for (auto* c : cands) total += c->bandwidth ? c->bandwidth : 1;

    uint64_t rnd = __rdtsc();
    uint64_t pick = rnd % total, cum = 0;
    for (auto* c : cands) {
        cum += c->bandwidth ? c->bandwidth : 1;
        if (cum > pick) return *c;
    }
    return *cands.back();
}

std::array<TorRelay, 3> TorEmbeddedClient::select_circuit_path() {
    std::array<TorRelay, 3> path{};

    TorRelay guard;
    if (!load_pinned_guard(guard))
        guard = select_relay(GUARD_FLAGS);

    path[0] = guard;
    std::vector<std::string> excl = {guard.fingerprint.data()};

    path[1] = select_relay(MIDDLE_FLAGS, excl);
    excl.emplace_back(path[1].fingerprint.data());

    path[2] = select_relay(EXIT_FLAGS, excl);
    return path;
}

bool TorEmbeddedClient::tls_connect(SOCKET sock, const TorRelay& relay) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(relay.or_port);
    inet_pton(AF_INET, relay.ip.c_str(), &addr.sin_addr);

    u_long nb = 1;
    ioctlsocket(sock, FIONBIO, &nb);
    ::connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));

    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(sock, &wfds);
    timeval tv{15, 0};
    if (select(0, nullptr, &wfds, nullptr, &tv) <= 0) return false;

    nb = 0;
    ioctlsocket(sock, FIONBIO, &nb);

    DWORD tmo = 30000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<char*>(&tmo), sizeof(tmo));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,
               reinterpret_cast<char*>(&tmo), sizeof(tmo));
    return true;
}

bool TorEmbeddedClient::negotiate_versions(SOCKET sock) {
    uint16_t versions[] = {3, 4};
    uint16_t net_versions[2];
    for (int i = 0; i < 2; ++i)
        pack_be16(reinterpret_cast<uint8_t*>(&net_versions[i]), versions[i]);

    uint8_t hdr[7];
    pack_be32(hdr, 0);
    hdr[4] = tor_cell::VERSIONS;
    pack_be16(hdr + 5, 4);

    if (!sock_send_all(sock, hdr, 7)) return false;
    if (!sock_send_all(sock, reinterpret_cast<uint8_t*>(net_versions), 4))
        return false;

    uint8_t resp_hdr[5];
    if (!sock_recv_all(sock, resp_hdr, 5)) return false;

    uint8_t cmd = resp_hdr[4];
    if (cmd == tor_cell::VERSIONS) {
        uint8_t len_buf[2];
        if (!sock_recv_all(sock, len_buf, 2)) return false;
        uint16_t vlen = unpack_be16(len_buf);
        std::vector<uint8_t> vdata(vlen);
        if (vlen > 0 && !sock_recv_all(sock, vdata.data(), vlen))
            return false;
    } else {
        std::vector<uint8_t> skip(TOR_CELL_PAYLOAD_SIZE);
        if (!sock_recv_all(sock, skip.data(),
                           static_cast<int>(TOR_CELL_PAYLOAD_SIZE)))
            return false;
    }

    for (int i = 0; i < 3; ++i) {
        uint8_t cell_hdr[5];
        fd_set rds;
        FD_ZERO(&rds);
        FD_SET(sock, &rds);
        timeval tv{5, 0};
        if (select(0, &rds, nullptr, nullptr, &tv) <= 0) break;
        if (!sock_recv_all(sock, cell_hdr, 5)) break;
        uint8_t c = cell_hdr[4];
        if (c >= 128) {
            uint8_t lb[2];
            if (!sock_recv_all(sock, lb, 2)) break;
            uint16_t plen = unpack_be16(lb);
            std::vector<uint8_t> tmp(plen);
            if (plen > 0) sock_recv_all(sock, tmp.data(), plen);
        } else {
            std::vector<uint8_t> tmp(TOR_CELL_PAYLOAD_SIZE);
            sock_recv_all(sock, tmp.data(),
                          static_cast<int>(TOR_CELL_PAYLOAD_SIZE));
            if (c == tor_cell::NETINFO) break;
        }
    }
    return true;
}

bool TorEmbeddedClient::send_netinfo(SOCKET sock) {
    uint8_t body[TOR_CELL_PAYLOAD_SIZE];
    std::memset(body, 0, TOR_CELL_PAYLOAD_SIZE);

    uint32_t now = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    pack_be32(body, now);

    body[4] = 0x04;
    body[5] = 4;
    std::memset(body + 6, 0, 4);

    body[10] = 1;
    body[11] = 0x04;
    body[12] = 4;
    std::memset(body + 13, 0, 4);

    return send_cell(sock, 0, tor_cell::NETINFO,
                     std::span<const uint8_t>(body, TOR_CELL_PAYLOAD_SIZE));
}

bool TorEmbeddedClient::send_cell(SOCKET sock, uint32_t circ_id,
                                   uint8_t command,
                                   std::span<const uint8_t> payload) {
    uint8_t cell[TOR_CELL_SIZE];
    std::memset(cell, 0, TOR_CELL_SIZE);
    pack_be32(cell, circ_id);
    cell[4] = command;
    size_t n = (std::min)(payload.size(),
                          static_cast<size_t>(TOR_CELL_PAYLOAD_SIZE));
    if (n > 0) std::memcpy(cell + TOR_CELL_HEADER_SIZE, payload.data(), n);

    if (!sock_send_all(sock, cell, TOR_CELL_SIZE)) return false;
    {
        std::lock_guard lk(stats_mutex_);
        stats_.bytes_sent += TOR_CELL_SIZE;
    }
    return true;
}

bool TorEmbeddedClient::recv_cell(SOCKET sock, uint32_t& circ_id,
                                   uint8_t& command,
                                   std::vector<uint8_t>& payload,
                                   int timeout_ms) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    if (select(0, &fds, nullptr, nullptr, &tv) <= 0) return false;

    uint8_t cell[TOR_CELL_SIZE];
    if (!sock_recv_all(sock, cell, TOR_CELL_SIZE)) return false;

    circ_id = unpack_be32(cell);
    command = cell[4];
    payload.assign(cell + TOR_CELL_HEADER_SIZE,
                   cell + TOR_CELL_SIZE);

    {
        std::lock_guard lk(stats_mutex_);
        stats_.bytes_received += TOR_CELL_SIZE;
    }
    return true;
}

uint32_t TorEmbeddedClient::allocate_circ_id() {
    static std::atomic<uint32_t> ctr{0};
    uint32_t base = ctr.fetch_add(1, std::memory_order_relaxed);
    uint8_t rnd[4];
    gen_random(rnd, 4);
    uint32_t id = (base ^ unpack_be32(rnd)) | 0x80000000u;
    return id ? id : 0x80000001u;
}

bool TorEmbeddedClient::curve25519_keygen(
        std::array<uint8_t, CURVE25519_KEY_SIZE>& pub_key,
        std::array<uint8_t, CURVE25519_KEY_SIZE>& priv_key) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDH_ALGORITHM,
                                                nullptr, 0)))
        return false;
    if (!NT_SUCCESS(BCryptSetProperty(alg, BCRYPT_ECC_CURVE_NAME,
            reinterpret_cast<PUCHAR>(
                const_cast<wchar_t*>(BCRYPT_ECC_CURVE_25519)),
            sizeof(BCRYPT_ECC_CURVE_25519), 0))) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    BCRYPT_KEY_HANDLE key = nullptr;
    if (!NT_SUCCESS(BCryptGenerateKeyPair(alg, &key, 255, 0)) ||
        !NT_SUCCESS(BCryptFinalizeKeyPair(key, 0))) {
        if (key) BCryptDestroyKey(key);
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    ULONG sz = 0;
    BCryptExportKey(key, nullptr, BCRYPT_ECCPUBLIC_BLOB,
                    nullptr, 0, &sz, 0);
    std::vector<uint8_t> pub_blob(sz);
    BCryptExportKey(key, nullptr, BCRYPT_ECCPUBLIC_BLOB,
                    pub_blob.data(), sz, &sz, 0);

    if (pub_blob.size() >= sizeof(BCRYPT_ECCKEY_BLOB) + CURVE25519_KEY_SIZE)
        std::memcpy(pub_key.data(),
                    pub_blob.data() + sizeof(BCRYPT_ECCKEY_BLOB),
                    CURVE25519_KEY_SIZE);

    sz = 0;
    BCryptExportKey(key, nullptr, BCRYPT_ECCPRIVATE_BLOB,
                    nullptr, 0, &sz, 0);
    std::vector<uint8_t> priv_blob(sz);
    BCryptExportKey(key, nullptr, BCRYPT_ECCPRIVATE_BLOB,
                    priv_blob.data(), sz, &sz, 0);

    if (priv_blob.size() >= sizeof(BCRYPT_ECCKEY_BLOB) + CURVE25519_KEY_SIZE * 2)
        std::memcpy(priv_key.data(),
                    priv_blob.data() + sizeof(BCRYPT_ECCKEY_BLOB) +
                        CURVE25519_KEY_SIZE,
                    CURVE25519_KEY_SIZE);

    BCryptDestroyKey(key);
    BCryptCloseAlgorithmProvider(alg, 0);
    return true;
}

bool TorEmbeddedClient::curve25519_shared_secret(
        std::span<const uint8_t, CURVE25519_KEY_SIZE> our_priv,
        std::span<const uint8_t, CURVE25519_KEY_SIZE> their_pub,
        std::array<uint8_t, CURVE25519_KEY_SIZE>& shared) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDH_ALGORITHM,
                                                nullptr, 0)))
        return false;
    BCryptSetProperty(alg, BCRYPT_ECC_CURVE_NAME,
                      reinterpret_cast<PUCHAR>(
                          const_cast<wchar_t*>(BCRYPT_ECC_CURVE_25519)),
                      sizeof(BCRYPT_ECC_CURVE_25519), 0);

    BCRYPT_ECCKEY_BLOB priv_hdr{};
    priv_hdr.dwMagic = BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC;
    priv_hdr.cbKey = CURVE25519_KEY_SIZE;
    std::vector<uint8_t> priv_blob(sizeof(BCRYPT_ECCKEY_BLOB) +
                                    CURVE25519_KEY_SIZE * 2);
    std::memcpy(priv_blob.data(), &priv_hdr, sizeof(priv_hdr));
    std::memset(priv_blob.data() + sizeof(priv_hdr), 0, CURVE25519_KEY_SIZE);
    std::memcpy(priv_blob.data() + sizeof(priv_hdr) + CURVE25519_KEY_SIZE,
                our_priv.data(), CURVE25519_KEY_SIZE);

    BCRYPT_KEY_HANDLE priv_key = nullptr;
    if (!NT_SUCCESS(BCryptImportKeyPair(alg, nullptr, BCRYPT_ECCPRIVATE_BLOB,
            &priv_key, priv_blob.data(),
            static_cast<ULONG>(priv_blob.size()), 0))) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    BCRYPT_ECCKEY_BLOB pub_hdr{};
    pub_hdr.dwMagic = BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC;
    pub_hdr.cbKey = CURVE25519_KEY_SIZE;
    std::vector<uint8_t> pub_blob(sizeof(BCRYPT_ECCKEY_BLOB) +
                                   CURVE25519_KEY_SIZE);
    std::memcpy(pub_blob.data(), &pub_hdr, sizeof(pub_hdr));
    std::memcpy(pub_blob.data() + sizeof(pub_hdr),
                their_pub.data(), CURVE25519_KEY_SIZE);

    BCRYPT_KEY_HANDLE pub_key = nullptr;
    if (!NT_SUCCESS(BCryptImportKeyPair(alg, nullptr, BCRYPT_ECCPUBLIC_BLOB,
            &pub_key, pub_blob.data(),
            static_cast<ULONG>(pub_blob.size()), 0))) {
        BCryptDestroyKey(priv_key);
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    BCRYPT_SECRET_HANDLE sec = nullptr;
    bool ok = false;
    if (NT_SUCCESS(BCryptSecretAgreement(priv_key, pub_key, &sec, 0))) {
        ULONG rlen = 0;
        ok = NT_SUCCESS(BCryptDeriveKey(sec, BCRYPT_KDF_RAW_SECRET,
                                         nullptr, shared.data(),
                                         CURVE25519_KEY_SIZE,
                                         &rlen, 0));
        BCryptDestroySecret(sec);
    }

    BCryptDestroyKey(pub_key);
    BCryptDestroyKey(priv_key);
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

bool TorEmbeddedClient::ntor_client_handshake(
        const TorRelay& relay,
        std::array<uint8_t, CURVE25519_KEY_SIZE>& client_pk,
        std::array<uint8_t, CURVE25519_KEY_SIZE>& client_sk) {
    return curve25519_keygen(client_pk, client_sk);
}

bool TorEmbeddedClient::ntor_client_finish(
        const TorRelay& relay,
        std::span<const uint8_t, CURVE25519_KEY_SIZE> client_pk,
        std::span<const uint8_t, CURVE25519_KEY_SIZE> client_sk,
        std::span<const uint8_t> server_hs,
        std::array<uint8_t, NTOR_KDF_OUT_SIZE>& key_material) {
    if (server_hs.size() < NTOR_REPLY_SIZE) return false;

    const uint8_t* Y = server_hs.data();
    const uint8_t* auth_recv = server_hs.data() + CURVE25519_KEY_SIZE;

    std::array<uint8_t, CURVE25519_KEY_SIZE> exp_yx{}, exp_bx{};
    if (!curve25519_shared_secret(client_sk,
            std::span<const uint8_t, CURVE25519_KEY_SIZE>(Y, CURVE25519_KEY_SIZE),
            exp_yx))
        return false;
    if (!curve25519_shared_secret(client_sk,
            std::span<const uint8_t, CURVE25519_KEY_SIZE>(
                relay.ntor_onion_key.data(), CURVE25519_KEY_SIZE),
            exp_bx))
        return false;

    constexpr size_t PID_LEN = sizeof(NTOR_PROTOID) - 1;
    std::vector<uint8_t> si;
    si.reserve(32 + 32 + TOR_SHA1_LEN + CURVE25519_KEY_SIZE +
               CURVE25519_KEY_SIZE + CURVE25519_KEY_SIZE + PID_LEN);
    si.insert(si.end(), exp_yx.begin(), exp_yx.end());
    si.insert(si.end(), exp_bx.begin(), exp_bx.end());
    si.insert(si.end(), relay.identity.begin(), relay.identity.end());
    si.insert(si.end(), relay.ntor_onion_key.begin(),
              relay.ntor_onion_key.end());
    si.insert(si.end(), client_pk.begin(), client_pk.end());
    si.insert(si.end(), Y, Y + CURVE25519_KEY_SIZE);
    si.insert(si.end(), NTOR_PROTOID, NTOR_PROTOID + PID_LEN);

    const char t_key[] = "ntor-curve25519-sha256-1:key_extract";
    const char t_verify[] = "ntor-curve25519-sha256-1:verify";
    const char t_mac[] = "ntor-curve25519-sha256-1:mac";

    uint8_t verify[32];
    hmac_sha256(reinterpret_cast<const uint8_t*>(t_verify),
                sizeof(t_verify) - 1,
                si.data(), si.size(), verify);

    std::vector<uint8_t> ai;
    ai.reserve(32 + TOR_SHA1_LEN + CURVE25519_KEY_SIZE * 3 + 6);
    ai.insert(ai.end(), verify, verify + 32);
    ai.insert(ai.end(), relay.identity.begin(), relay.identity.end());
    ai.insert(ai.end(), relay.ntor_onion_key.begin(),
              relay.ntor_onion_key.end());
    ai.insert(ai.end(), Y, Y + CURVE25519_KEY_SIZE);
    ai.insert(ai.end(), client_pk.begin(), client_pk.end());
    const char srv[] = "Server";
    ai.insert(ai.end(), srv, srv + 6);

    uint8_t auth_check[32];
    hmac_sha256(reinterpret_cast<const uint8_t*>(t_mac),
                sizeof(t_mac) - 1,
                ai.data(), ai.size(), auth_check);

    if (std::memcmp(auth_check, auth_recv, 32) != 0) return false;

    uint8_t key_seed[32];
    hmac_sha256(reinterpret_cast<const uint8_t*>(t_key),
                sizeof(t_key) - 1,
                si.data(), si.size(), key_seed);

    return ntor_kdf(std::span<const uint8_t>(key_seed, 32), key_material);
}

bool TorEmbeddedClient::ntor_kdf(std::span<const uint8_t> secret_input,
                                  std::span<uint8_t> output) {
    const char m_expand[] = "ntor-curve25519-sha256-1:key_expand";
    const size_t m_len = sizeof(m_expand) - 1;
    size_t done = 0;
    uint8_t prev[32];
    uint32_t prev_len = 0;

    for (uint8_t i = 1; done < output.size(); ++i) {
        std::vector<uint8_t> info;
        info.reserve(prev_len + m_len + 1);
        if (prev_len > 0) info.insert(info.end(), prev, prev + prev_len);
        info.insert(info.end(), m_expand, m_expand + m_len);
        info.push_back(i);

        uint8_t block[32];
        if (!hmac_sha256(secret_input.data(),
                         static_cast<uint32_t>(secret_input.size()),
                         info.data(), info.size(), block))
            return false;

        size_t n = (std::min)(static_cast<size_t>(32), output.size() - done);
        std::memcpy(output.data() + done, block, n);
        done += n;
        std::memcpy(prev, block, 32);
        prev_len = 32;
    }
    return true;
}

void TorEmbeddedClient::install_hop_keys(
        TorCircuit* circuit, int hop,
        std::span<const uint8_t, NTOR_KDF_OUT_SIZE> km) {
    auto& cs = circuit->crypto[hop];

    std::array<uint8_t, AES128_KEY_SIZE> fwd_key{}, bwd_key{};
    std::memcpy(fwd_key.data(), km.data() + 40, AES128_KEY_SIZE);
    std::memcpy(bwd_key.data(), km.data() + 56, AES128_KEY_SIZE);

    cs.forward_aes  = create_aes_ctr_key(fwd_key);
    cs.backward_aes = create_aes_ctr_key(bwd_key);
    cs.forward_iv   = {};
    cs.backward_iv  = {};

    cs.forward_digest  = create_sha1_digest();
    cs.backward_digest = create_sha1_digest();

    digest_update(cs.forward_digest.get(),
                  std::span<const uint8_t>(km.data(), 20));
    digest_update(cs.backward_digest.get(),
                  std::span<const uint8_t>(km.data() + 20, 20));
}

KeyHandle TorEmbeddedClient::create_aes_ctr_key(
        std::span<const uint8_t, AES128_KEY_SIZE> key) {
    BCRYPT_KEY_HANDLE hk = nullptr;
    BCryptGenerateSymmetricKey(aes_ecb_alg(), &hk, nullptr, 0,
                               const_cast<PUCHAR>(key.data()),
                               AES128_KEY_SIZE, 0);
    return KeyHandle(hk);
}

void TorEmbeddedClient::aes_ctr_crypt(
        BCRYPT_KEY_HANDLE key_h,
        std::array<uint8_t, AES128_IV_SIZE>& iv,
        std::span<uint8_t> data) {
    size_t off = 0;
    while (off < data.size()) {
        uint8_t ks[16];
        ULONG written = 0;
        uint8_t ctr_copy[16];
        std::memcpy(ctr_copy, iv.data(), 16);
        BCryptEncrypt(key_h, ctr_copy, 16, nullptr, nullptr, 0,
                      ks, 16, &written, 0);

        for (int j = 15; j >= 0; --j) {
            if (++iv[j] != 0) break;
        }

        size_t chunk = (std::min)(static_cast<size_t>(16), data.size() - off);
        for (size_t i = 0; i < chunk; ++i)
            data[off + i] ^= ks[i];
        off += chunk;
    }
}

HashHandle TorEmbeddedClient::create_sha1_digest() {
    BCRYPT_HASH_HANDLE h = nullptr;
    BCryptCreateHash(sha1_alg(), &h, nullptr, 0, nullptr, 0, 0);
    return HashHandle(h);
}

void TorEmbeddedClient::digest_update(BCRYPT_HASH_HANDLE h,
                                       std::span<const uint8_t> data) {
    BCryptHashData(h, const_cast<PUCHAR>(data.data()),
                   static_cast<ULONG>(data.size()), 0);
}

std::array<uint8_t, TOR_DIGEST_LEN>
TorEmbeddedClient::digest_peek(BCRYPT_HASH_HANDLE h) {
    std::array<uint8_t, TOR_DIGEST_LEN> result{};
    BCRYPT_HASH_HANDLE dup = nullptr;
    if (NT_SUCCESS(BCryptDuplicateHash(h, &dup, nullptr, 0, 0))) {
        uint8_t full[TOR_SHA1_LEN];
        BCryptFinishHash(dup, full, TOR_SHA1_LEN, 0);
        std::memcpy(result.data(), full, TOR_DIGEST_LEN);
        BCryptDestroyHash(dup);
    }
    return result;
}

std::array<uint8_t, TOR_CELL_PAYLOAD_SIZE>
TorEmbeddedClient::build_relay_cell(uint8_t relay_cmd, uint16_t stream_id,
                                     std::span<const uint8_t> payload) {
    std::array<uint8_t, TOR_CELL_PAYLOAD_SIZE> cell{};
    cell[0] = relay_cmd;
    cell[1] = 0; cell[2] = 0;
    pack_be16(cell.data() + 3, stream_id);
    std::memset(cell.data() + 5, 0, 4);
    uint16_t dlen = static_cast<uint16_t>(
        (std::min)(payload.size(),
                   static_cast<size_t>(TOR_RELAY_PAYLOAD_SIZE)));
    pack_be16(cell.data() + 9, dlen);
    if (dlen > 0)
        std::memcpy(cell.data() + TOR_RELAY_HEADER_SIZE,
                    payload.data(), dlen);
    return cell;
}

void TorEmbeddedClient::relay_encrypt_forward(
        TorCircuit* circuit, std::span<uint8_t> cell_payload) {
    for (int h = 0; h < 3; ++h) {
        auto& cs = circuit->crypto[h];
        if (!cs.forward_aes) continue;
        aes_ctr_crypt(cs.forward_aes.get(), cs.forward_iv, cell_payload);
    }
}

void TorEmbeddedClient::relay_decrypt_backward(
        TorCircuit* circuit, std::span<uint8_t> cell_payload,
        int& recognized_hop) {
    recognized_hop = -1;
    for (int h = 2; h >= 0; --h) {
        auto& cs = circuit->crypto[h];
        if (!cs.backward_aes) continue;
        aes_ctr_crypt(cs.backward_aes.get(), cs.backward_iv, cell_payload);

        uint16_t rec = unpack_be16(cell_payload.data() + 1);
        if (rec == 0) {
            recognized_hop = h;
            return;
        }
    }
}

void TorEmbeddedClient::check_sendme(TorCircuit* circuit, int hop) {
    if (circuit->recv_window <= CIRCUIT_WINDOW_REFILL) {
        auto cell = build_relay_cell(tor_relay::SENDME, 0, {});

        if (hop >= 0 && hop < 3 && circuit->crypto[hop].forward_digest) {
            digest_update(circuit->crypto[hop].forward_digest.get(), cell);
            auto dg = digest_peek(circuit->crypto[hop].forward_digest.get());
            std::memcpy(cell.data() + 5, dg.data(), TOR_DIGEST_LEN);
        }

        std::span<uint8_t> sp(cell.data(), cell.size());
        relay_encrypt_forward(circuit, sp);
        send_cell(circuit->entry_socket, circuit->circ_id,
                  tor_cell::RELAY,
                  std::span<const uint8_t>(cell.data(), cell.size()));
        circuit->recv_window = CIRCUIT_WINDOW_DEFAULT;
    }
}

std::vector<uint8_t> TorEmbeddedClient::build_extend2_payload(
        const TorRelay& target,
        std::span<const uint8_t, CURVE25519_KEY_SIZE> client_pk) {
    std::vector<uint8_t> body;
    body.reserve(128);

    body.push_back(2);

    body.push_back(LSTYPE_TLS_TCP_IPV4);
    body.push_back(6);
    uint32_t ipn = ip_to_net(target.ip);
    uint8_t ipb[4];
    std::memcpy(ipb, &ipn, 4);
    body.insert(body.end(), ipb, ipb + 4);
    uint8_t pb[2];
    pack_be16(pb, target.or_port);
    body.insert(body.end(), pb, pb + 2);

    body.push_back(LSTYPE_LEGACY_ID);
    body.push_back(TOR_SHA1_LEN);
    body.insert(body.end(), target.identity.begin(), target.identity.end());

    uint8_t ht[2];
    pack_be16(ht, HTYPE_NTOR);
    body.insert(body.end(), ht, ht + 2);
    uint8_t hl[2];
    pack_be16(hl, NTOR_ONIONSKIN_SIZE);
    body.insert(body.end(), hl, hl + 2);

    body.insert(body.end(), target.identity.begin(), target.identity.end());
    body.insert(body.end(), target.ntor_onion_key.begin(),
                target.ntor_onion_key.end());
    body.insert(body.end(), client_pk.begin(), client_pk.end());

    return body;
}

bool TorEmbeddedClient::create_fast(TorCircuit* circuit) {
    std::array<uint8_t, TOR_SHA1_LEN> X{};
    if (!gen_random(X.data(), TOR_SHA1_LEN)) return false;

    if (!send_cell(circuit->entry_socket, circuit->circ_id,
                   tor_cell::CREATE_FAST,
                   std::span<const uint8_t>(X.data(), TOR_SHA1_LEN)))
        return false;

    uint32_t cid; uint8_t cmd;
    std::vector<uint8_t> resp;
    if (!recv_cell(circuit->entry_socket, cid, cmd, resp, 30000))
        return false;
    if (cmd != tor_cell::CREATED_FAST || cid != circuit->circ_id)
        return false;
    if (resp.size() < 40) return false;

    std::vector<uint8_t> seed;
    seed.insert(seed.end(), X.begin(), X.end());
    seed.insert(seed.end(), resp.begin(), resp.begin() + TOR_SHA1_LEN);

    uint8_t verify[TOR_SHA1_LEN];
    sha1_hash(seed.data(), static_cast<uint32_t>(seed.size()), verify);
    if (std::memcmp(verify, resp.data() + TOR_SHA1_LEN, TOR_SHA1_LEN) != 0)
        return false;

    std::array<uint8_t, NTOR_KDF_OUT_SIZE> km{};
    if (!ntor_kdf(seed, km)) return false;
    install_hop_keys(circuit, 0, km);
    return true;
}

bool TorEmbeddedClient::create2_ntor(TorCircuit* circuit, int hop) {
    std::array<uint8_t, CURVE25519_KEY_SIZE> pk{}, sk{};
    if (!ntor_client_handshake(circuit->hops[hop], pk, sk)) return false;

    std::vector<uint8_t> body;
    uint8_t ht[2]; pack_be16(ht, HTYPE_NTOR);
    uint8_t hl[2]; pack_be16(hl, NTOR_ONIONSKIN_SIZE);
    body.insert(body.end(), ht, ht + 2);
    body.insert(body.end(), hl, hl + 2);
    body.insert(body.end(), circuit->hops[hop].identity.begin(),
                circuit->hops[hop].identity.end());
    body.insert(body.end(), circuit->hops[hop].ntor_onion_key.begin(),
                circuit->hops[hop].ntor_onion_key.end());
    body.insert(body.end(), pk.begin(), pk.end());

    if (!send_cell(circuit->entry_socket, circuit->circ_id,
                   tor_cell::CREATE2,
                   std::span<const uint8_t>(body.data(), body.size())))
        return false;

    uint32_t cid; uint8_t cmd;
    std::vector<uint8_t> resp;
    if (!recv_cell(circuit->entry_socket, cid, cmd, resp, 30000))
        return false;
    if (cmd != tor_cell::CREATED2 || cid != circuit->circ_id)
        return false;

    if (resp.size() < 2) return false;
    uint16_t hlen = unpack_be16(resp.data());
    if (resp.size() < 2u + hlen) return false;
    std::span<const uint8_t> server_hs(resp.data() + 2, hlen);

    std::array<uint8_t, NTOR_KDF_OUT_SIZE> km{};
    if (!ntor_client_finish(circuit->hops[hop], pk, sk, server_hs, km))
        return false;
    install_hop_keys(circuit, hop, km);
    return true;
}

bool TorEmbeddedClient::extend2_ntor(TorCircuit* circuit, int hop) {
    std::array<uint8_t, CURVE25519_KEY_SIZE> pk{}, sk{};
    if (!ntor_client_handshake(circuit->hops[hop], pk, sk)) return false;

    auto ext = build_extend2_payload(circuit->hops[hop], pk);
    auto cell = build_relay_cell(tor_relay::EXTEND2, 0, ext);

    auto& cs = circuit->crypto[hop - 1];
    if (cs.forward_digest) {
        std::array<uint8_t, TOR_CELL_PAYLOAD_SIZE> tmp = cell;
        std::memset(tmp.data() + 5, 0, TOR_DIGEST_LEN);
        digest_update(cs.forward_digest.get(), tmp);
        auto dg = digest_peek(cs.forward_digest.get());
        std::memcpy(cell.data() + 5, dg.data(), TOR_DIGEST_LEN);
    }

    std::span<uint8_t> sp(cell.data(), cell.size());
    relay_encrypt_forward(circuit, sp);

    if (!send_cell(circuit->entry_socket, circuit->circ_id,
                   tor_cell::RELAY_EARLY,
                   std::span<const uint8_t>(cell.data(), cell.size())))
        return false;

    uint32_t cid; uint8_t cmd;
    std::vector<uint8_t> resp;
    if (!recv_cell(circuit->entry_socket, cid, cmd, resp, 30000))
        return false;
    if (cid != circuit->circ_id || cmd != tor_cell::RELAY)
        return false;
    if (resp.size() < TOR_CELL_PAYLOAD_SIZE) return false;

    int recognized_hop = -1;
    std::span<uint8_t> rsp(resp.data(), TOR_CELL_PAYLOAD_SIZE);
    relay_decrypt_backward(circuit, rsp, recognized_hop);

    if (resp[0] != tor_relay::EXTENDED2) return false;

    uint16_t dlen = unpack_be16(resp.data() + 9);
    if (dlen < 2 || TOR_RELAY_HEADER_SIZE + dlen > TOR_CELL_PAYLOAD_SIZE)
        return false;

    const uint8_t* ext_data = resp.data() + TOR_RELAY_HEADER_SIZE;
    uint16_t hlen = unpack_be16(ext_data);
    if (hlen + 2u > dlen) return false;
    std::span<const uint8_t> server_hs(ext_data + 2, hlen);

    std::array<uint8_t, NTOR_KDF_OUT_SIZE> km{};
    if (!ntor_client_finish(circuit->hops[hop], pk, sk, server_hs, km))
        return false;
    install_hop_keys(circuit, hop, km);
    return true;
}

TorCircuit* TorEmbeddedClient::build_circuit() {
    if (!ready_) return nullptr;

    auto path = select_circuit_path();

    auto circuit = std::make_unique<TorCircuit>();
    circuit->circ_id = allocate_circ_id();
    circuit->hops = path;
    circuit->created = std::chrono::steady_clock::now();
    circuit->state = CircuitState::Creating;

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        std::lock_guard lk(stats_mutex_);
        stats_.circuits_failed++;
        return nullptr;
    }

    if (!tls_connect(sock, path[0])) {
        closesocket(sock);
        std::lock_guard lk(stats_mutex_);
        stats_.circuits_failed++;
        return nullptr;
    }

    circuit->entry_socket = sock;

    if (!negotiate_versions(sock) || !send_netinfo(sock)) {
        closesocket(sock);
        std::lock_guard lk(stats_mutex_);
        stats_.circuits_failed++;
        return nullptr;
    }

    if (!create_fast(circuit.get())) {
        closesocket(sock);
        std::lock_guard lk(stats_mutex_);
        stats_.circuits_failed++;
        return nullptr;
    }

    circuit->state = CircuitState::Extending;
    for (int hop = 1; hop < 3; ++hop) {
        if (!extend2_ntor(circuit.get(), hop)) {
            closesocket(sock);
            circuit->entry_socket = INVALID_SOCKET;
            std::lock_guard lk(stats_mutex_);
            stats_.circuits_failed++;
            return nullptr;
        }
    }

    circuit->state = CircuitState::Ready;
    save_pinned_guard(path[0]);

    {
        std::lock_guard lk(stats_mutex_);
        stats_.circuits_built++;
    }

    TorCircuit* raw = circuit.get();
    {
        std::lock_guard lk(circuits_mutex_);
        circuits_.push_back(std::move(circuit));
    }
    return raw;
}

bool TorEmbeddedClient::destroy_circuit(TorCircuit* circuit) {
    if (!circuit) return false;

    if (circuit->entry_socket != INVALID_SOCKET) {
        send_cell(circuit->entry_socket, circuit->circ_id,
                  tor_cell::DESTROY, {});
        closesocket(circuit->entry_socket);
        circuit->entry_socket = INVALID_SOCKET;
    }

    circuit->state = CircuitState::Destroyed;

    {
        std::lock_guard lk(circuits_mutex_);
        circuits_.erase(
            std::remove_if(circuits_.begin(), circuits_.end(),
                [circuit](const std::unique_ptr<TorCircuit>& p) {
                    return p.get() == circuit;
                }),
            circuits_.end());
    }
    return true;
}

bool TorEmbeddedClient::circuit_send(TorCircuit* circuit,
                                      uint32_t stream_id,
                                      std::span<const uint8_t> data) {
    if (!circuit || circuit->state != CircuitState::Ready) return false;

    size_t off = 0;
    while (off < data.size()) {
        size_t chunk = (std::min)(data.size() - off,
                                  static_cast<size_t>(TOR_RELAY_PAYLOAD_SIZE));
        auto cell = build_relay_cell(
            tor_relay::DATA, static_cast<uint16_t>(stream_id),
            std::span<const uint8_t>(data.data() + off, chunk));

        auto& cs = circuit->crypto[2];
        if (cs.forward_digest) {
            std::array<uint8_t, TOR_CELL_PAYLOAD_SIZE> tmp = cell;
            std::memset(tmp.data() + 5, 0, TOR_DIGEST_LEN);
            digest_update(cs.forward_digest.get(), tmp);
            auto dg = digest_peek(cs.forward_digest.get());
            std::memcpy(cell.data() + 5, dg.data(), TOR_DIGEST_LEN);
        }

        std::span<uint8_t> sp(cell.data(), cell.size());
        relay_encrypt_forward(circuit, sp);

        if (!send_cell(circuit->entry_socket, circuit->circ_id,
                       tor_cell::RELAY,
                       std::span<const uint8_t>(cell.data(), cell.size())))
            return false;

        off += chunk;
        circuit->send_window--;

        if (circuit->send_window == 0) return false;
    }
    return true;
}

bool TorEmbeddedClient::circuit_recv(TorCircuit* circuit,
                                      uint32_t& stream_id,
                                      std::vector<uint8_t>& data,
                                      int timeout_ms) {
    if (!circuit || circuit->state != CircuitState::Ready) return false;

    uint32_t cid; uint8_t cmd;
    std::vector<uint8_t> resp;
    if (!recv_cell(circuit->entry_socket, cid, cmd, resp, timeout_ms))
        return false;
    if (cid != circuit->circ_id || cmd != tor_cell::RELAY) return false;
    if (resp.size() < TOR_CELL_PAYLOAD_SIZE) return false;

    int hop = -1;
    std::span<uint8_t> rsp(resp.data(), TOR_CELL_PAYLOAD_SIZE);
    relay_decrypt_backward(circuit, rsp, hop);

    uint8_t relay_cmd = resp[0];
    stream_id = unpack_be16(resp.data() + 3);
    uint16_t dlen = unpack_be16(resp.data() + 9);

    if (relay_cmd == tor_relay::SENDME) {
        circuit->send_window += 100;
        data.clear();
        return true;
    }

    if (relay_cmd == tor_relay::DATA) {
        circuit->recv_window--;
        check_sendme(circuit, hop);
        if (dlen > 0 && TOR_RELAY_HEADER_SIZE + dlen <= TOR_CELL_PAYLOAD_SIZE)
            data.assign(resp.begin() + TOR_RELAY_HEADER_SIZE,
                        resp.begin() + TOR_RELAY_HEADER_SIZE + dlen);
        else
            data.clear();
        return true;
    }

    if (relay_cmd == tor_relay::END) {
        data.clear();
        return false;
    }

    data.assign(resp.begin() + TOR_RELAY_HEADER_SIZE,
                resp.begin() + TOR_RELAY_HEADER_SIZE +
                    (std::min)(static_cast<size_t>(dlen),
                               TOR_RELAY_PAYLOAD_SIZE));
    return true;
}

bool TorEmbeddedClient::circuit_connect(TorCircuit* circuit,
                                         const std::string& host,
                                         uint16_t port,
                                         uint32_t& stream_id) {
    if (!circuit || circuit->state != CircuitState::Ready) return false;

    stream_id = circuit->next_stream_id++;
    if (stream_id == 0) stream_id = circuit->next_stream_id++;

    std::string addr = host + ":" + std::to_string(port);
    addr.push_back('\0');
    std::vector<uint8_t> payload(addr.begin(), addr.end());

    auto cell = build_relay_cell(tor_relay::BEGIN,
                                  static_cast<uint16_t>(stream_id), payload);

    auto& cs = circuit->crypto[2];
    if (cs.forward_digest) {
        std::array<uint8_t, TOR_CELL_PAYLOAD_SIZE> tmp = cell;
        std::memset(tmp.data() + 5, 0, TOR_DIGEST_LEN);
        digest_update(cs.forward_digest.get(), tmp);
        auto dg = digest_peek(cs.forward_digest.get());
        std::memcpy(cell.data() + 5, dg.data(), TOR_DIGEST_LEN);
    }

    std::span<uint8_t> sp(cell.data(), cell.size());
    relay_encrypt_forward(circuit, sp);

    if (!send_cell(circuit->entry_socket, circuit->circ_id,
                   tor_cell::RELAY_EARLY,
                   std::span<const uint8_t>(cell.data(), cell.size())))
        return false;

    uint32_t cid; uint8_t cmd;
    std::vector<uint8_t> resp;
    if (!recv_cell(circuit->entry_socket, cid, cmd, resp, 30000))
        return false;
    if (cid != circuit->circ_id || cmd != tor_cell::RELAY) return false;
    if (resp.size() < TOR_CELL_PAYLOAD_SIZE) return false;

    int hop = -1;
    std::span<uint8_t> rsp(resp.data(), TOR_CELL_PAYLOAD_SIZE);
    relay_decrypt_backward(circuit, rsp, hop);

    if (resp[0] != tor_relay::CONNECTED) return false;

    {
        std::lock_guard lk(streams_mutex_);
        TorStream ts;
        ts.stream_id = stream_id;
        ts.circuit_id = circuit->circ_id;
        ts.connected = true;
        streams_[stream_id] = ts;
    }
    return true;
}

bool TorEmbeddedClient::load_pinned_guard(TorRelay& out) {
    if (pinned_guard_fp_.empty()) return false;
    std::lock_guard lk(relays_mutex_);
    for (auto& r : relays_) {
        if (r.fingerprint.data() == pinned_guard_fp_ &&
            has_flags(r.flags, GUARD_FLAGS)) {
            out = r;
            return true;
        }
    }
    return false;
}

void TorEmbeddedClient::save_pinned_guard(const TorRelay& guard) {
    pinned_guard_fp_ = guard.fingerprint.data();
}

TorEmbeddedClient::Stats TorEmbeddedClient::stats() const {
    std::lock_guard lk(stats_mutex_);
    return stats_;
}

std::vector<TorRelay> TorEmbeddedClient::get_current_relays() const {
    std::lock_guard lk(relays_mutex_);
    return relays_;
}

} // namespace diarna::comm
