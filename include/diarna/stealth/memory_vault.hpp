#pragma once
#include <diarna/compiler_port.hpp>
#include <cstdint>
#include <functional>
#include <atomic>
#include <vector>
#include <mutex>

namespace diarna::stealth {

struct VaultPage {
    void* address = nullptr;
    size_t size = 0;
    uint32_t old_protect = 0;
    std::vector<uint8_t> encrypted_data;
    bool is_locked = true;
    uint32_t access_count = 0;
    uint8_t page_key[32] = {};
    uint8_t fill_byte = 0xCC;
    DWORD guard_protect = PAGE_NOACCESS;
    bool is_decoy = false;
};

class MemoryVault {
public:
    static MemoryVault& instance();

    void* vault_alloc(size_t size);
    bool vault_free(void* ptr);
    void lock_all();
    void unlock_all();
    void cycle_reencrypt();

    template<typename F>
    auto guarded_access(F&& fn) -> decltype(fn()) {
        volatile uint32_t pre = _guard_ctr++;
        auto result = fn();
        volatile uint32_t post = ++_guard_ctr;
        if (pre + 1 != post) __debugbreak();
        cycle_reencrypt();
        return result;
    }

    size_t page_count() const { return pages_.size(); }
    uint64_t access_count() const { return total_accesses_; }
    void set_trap_threshold(uint32_t threshold) { trap_threshold_ = threshold; }
    void set_honeytrap_callback(std::function<void(void*)> cb) { honeytrap_cb_ = std::move(cb); }

private:
    MemoryVault();
    ~MemoryVault();
    MemoryVault(const MemoryVault&) = delete;
    MemoryVault& operator=(const MemoryVault&) = delete;

    static LONG WINAPI veh_handler(EXCEPTION_POINTERS* ex_info);
    void encrypt_page(VaultPage& page);
    void decrypt_page(VaultPage& page);
    void generate_page_key(VaultPage& page);
    void derive_master_key(uint8_t out[32]);
    void xor_page_key(uint8_t* key);
    void* install_trampoline();
    void deploy_decoys(size_t count);
    static void timing_jitter();
    static void secure_zero(void* p, size_t n);

    std::vector<VaultPage> pages_;
    std::mutex pages_mutex_;
    std::atomic<uint64_t> total_accesses_{0};
    std::atomic<uint32_t> _guard_ctr{0};
    uint32_t trap_threshold_{0};
    void* veh_handle_ = nullptr;
    void* trampoline_page_ = nullptr;
    bool initialized_ = false;
    std::function<void(void*)> honeytrap_cb_;
};

void memory_guard_start();
void memory_guard_stop();
void* guarded_malloc(size_t size);
void guarded_free(void* ptr);
void guard_lock_region(void* ptr, size_t size);
void guard_unlock_region(void* ptr, size_t size);

class StackObfuscator {
public:
    StackObfuscator();
    ~StackObfuscator();
    void push(uint64_t val);
    uint64_t pop();
    void scramble();

private:
    volatile uint64_t slots_[16];
    volatile uint8_t xor_key_;
    volatile size_t depth_;
};

} // namespace diarna::stealth
