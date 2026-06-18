#include <diarna/stealth/syscalls.hpp>
#include <diarna/compiler_port.hpp>
#include <diarna/stealth/syscalls.hpp>
#include <diarna/stealth/memory_vault.hpp>

#include <diarna/stealth/syscalls.hpp>
#include <algorithm>

#include <diarna/stealth/syscalls.hpp>
#include <obfuscation/obfusheader.h>
namespace diarna::stealth {

static DIARNA_NOINLINE void hw_entropy(void* buf, size_t len) {
    using RtlGenRandom_t = BOOLEAN(NTAPI*)(PVOID, ULONG);
    static auto fn = (RtlGenRandom_t)GetProcAddress(
        GetModuleHandleW(L"advapi32.dll"), "SystemFunction036");
    if (fn && fn(buf, (ULONG)len)) return;
    auto* p = (uint8_t*)buf;
    for (size_t i = 0; i < len; i++) {
        p[i] = (uint8_t)(__rdtsc() >> ((i & 7) * 4));
        for (volatile int j = 0; j < 7; j++);
    }
}

MemoryVault& MemoryVault::instance() {
    static MemoryVault vault;
    return vault;
}

void MemoryVault::secure_zero(void* p, size_t n) {
    volatile uint8_t* vp = (volatile uint8_t*)p;
    while (n--) *vp++ = 0;
}

void MemoryVault::timing_jitter() {
    volatile uint32_t spins = (uint32_t)(__rdtsc() & 0x1FF) + 64;
    for (volatile uint32_t i = 0; i < spins; ++i)
        DIARNA_PAUSE();
}

void MemoryVault::derive_master_key(uint8_t out[32]) {
    DWORD pid = GetCurrentProcessId();
    uintptr_t base = (uintptr_t)GetModuleHandle(nullptr);
    FILETIME ct, et, kt, ut;
    GetProcessTimes(GetCurrentProcess(), &ct, &et, &kt, &ut);

    uint8_t seed[32] = {};
    memcpy(seed, &pid, 4);
    memcpy(seed + 4, &base, sizeof(base));
    memcpy(seed + 4 + sizeof(base), &ct, sizeof(ct));
    for (int i = 20; i < 32; i++)
        seed[i] = seed[i % 20] ^ (uint8_t)(i * 0x9E);

    memcpy(out, seed, 32);
    for (int round = 0; round < 16; round++) {
        for (int i = 0; i < 32; i++) {
            out[i] ^= out[(i + 13) % 32];
            out[i] = (uint8_t)((out[i] << 3) | (out[i] >> 5));
            out[i] = (uint8_t)(out[i] + out[(i + 7) % 32]);
        }
    }
}

void MemoryVault::xor_page_key(uint8_t* key) {
    uint8_t mk[32];
    derive_master_key(mk);
    for (int i = 0; i < 32; i++)
        key[i] ^= mk[i];
    secure_zero(mk, 32);
}

void MemoryVault::generate_page_key(VaultPage& page) {
    hw_entropy(page.page_key, 32);
    xor_page_key(page.page_key);
}

void* MemoryVault::install_trampoline() {
    void* tramp = VirtualAlloc(nullptr, 4096,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!tramp) return nullptr;

    for (size_t i = 0; i < 4096; i++)
        ((uint8_t*)tramp)[i] = (uint8_t)(__rdtsc() ^ (i * 0x37));

    uint32_t stub_off = (uint32_t)((__rdtsc() & 0x1F0) + 0x100);
    uint32_t data_off = (uint32_t)(0x800 + ((__rdtsc() & 0x1F) * 8));

    uintptr_t target = (uintptr_t)&veh_handler;
    memcpy((uint8_t*)tramp + data_off, &target, 8);

    uint8_t* stub = (uint8_t*)tramp + stub_off;
    int32_t disp = (int32_t)(data_off - (stub_off + 6));
    stub[0] = 0xFF;
    stub[1] = 0x25;
    memcpy(stub + 2, &disp, 4);

    DWORD old;
    VirtualProtect(tramp, 4096, PAGE_EXECUTE_READ, &old);

    return (void*)stub;
}

void MemoryVault::deploy_decoys(size_t count) {
    for (size_t d = 0; d < count; d++) {
        size_t decoy_size = 4096 * (1 + (__rdtsc() % 4));
        void* mem = VirtualAlloc(nullptr, decoy_size,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!mem) continue;

        for (size_t i = 0; i < decoy_size; i++)
            ((uint8_t*)mem)[i] = (uint8_t)(__rdtsc() ^ (i * 0x5D));

        VaultPage page;
        page.address = mem;
        page.size = decoy_size;
        page.is_locked = true;
        page.is_decoy = true;
        page.encrypted_data.resize(decoy_size);
        page.access_count = 0;
        page.fill_byte = (uint8_t)(0x90 + (__rdtsc() % 0x40));

        DWORD prots[] = { PAGE_NOACCESS,
                          PAGE_READWRITE | PAGE_GUARD,
                          PAGE_READONLY | PAGE_GUARD };
        page.guard_protect = prots[d % 3];

        DWORD old;
        VirtualProtect(mem, decoy_size, page.guard_protect, &old);
        pages_.push_back(page);
    }
}

MemoryVault::MemoryVault() {
    trampoline_page_ = nullptr;
    void* stub = install_trampoline();
    if (stub) {
        trampoline_page_ = (void*)((uintptr_t)stub & ~(uintptr_t)0xFFF);
        veh_handle_ = AddVectoredExceptionHandler(1,
            (PVECTORED_EXCEPTION_HANDLER)stub);
    }
    deploy_decoys(2 + (__rdtsc() % 3));
    initialized_ = true;
}

MemoryVault::~MemoryVault() {
    if (veh_handle_)
        RemoveVectoredExceptionHandler(veh_handle_);
    for (auto& page : pages_) {
        if (page.address)
            VirtualFree(page.address, 0, MEM_RELEASE);
    }
    if (trampoline_page_)
        VirtualFree(trampoline_page_, 0, MEM_RELEASE);
}

LONG WINAPI MemoryVault::veh_handler(EXCEPTION_POINTERS* ex_info) {
    auto& vault = instance();
    if (!vault.initialized_) return EXCEPTION_CONTINUE_SEARCH;

    DWORD code = ex_info->ExceptionRecord->ExceptionCode;
    if (code != EXCEPTION_ACCESS_VIOLATION &&
        code != EXCEPTION_GUARD_PAGE)
        return EXCEPTION_CONTINUE_SEARCH;

    void* access_addr = (void*)ex_info->ExceptionRecord->ExceptionInformation[1];

    std::lock_guard lock(vault.pages_mutex_);

    for (auto& page : vault.pages_) {
        INDIRECT_BRANCH;
        if (access_addr >= page.address &&
            access_addr < (uint8_t*)page.address + page.size) {

            if (page.is_decoy) {
                if (vault.honeytrap_cb_)
                    vault.honeytrap_cb_(access_addr);
                return EXCEPTION_CONTINUE_SEARCH;
            }

            if (page.is_locked) {
                vault.decrypt_page(page);

                page.access_count++;
                vault.total_accesses_++;

                if (vault.trap_threshold_ > 0 &&
                    page.access_count >= vault.trap_threshold_) {
                    vault.encrypt_page(page);
                    page.is_locked = true;
                    return EXCEPTION_CONTINUE_SEARCH;
                }

                DWORD old;
                VirtualProtect(page.address, page.size,
                    PAGE_READWRITE, &old);
                page.is_locked = false;
                page.old_protect = old;

                return EXCEPTION_CONTINUE_EXECUTION;
            }
            break;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

void* MemoryVault::vault_alloc(size_t size) {
    size_t page_size = ((size + 4095) / 4096) * 4096;

    void* mem = VirtualAlloc(nullptr, page_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) return nullptr;

    static std::atomic<uint32_t> prot_idx{0};
    uint32_t idx = prot_idx.fetch_add(1);

    DWORD prots[] = {
        PAGE_NOACCESS,
        (DWORD)(PAGE_READWRITE | PAGE_GUARD),
        (DWORD)(PAGE_READONLY | PAGE_GUARD)
    };

    VaultPage page;
    page.address = mem;
    page.size = page_size;
    page.is_locked = false;
    page.is_decoy = false;
    page.encrypted_data.resize(page_size);
    page.access_count = 0;
    page.guard_protect = prots[idx % 3];
    page.fill_byte = (uint8_t)(0x90 + ((idx * 0x1B) % 0x70));

    {
        std::lock_guard lock(pages_mutex_);
        pages_.push_back(page);
    }

    DWORD old;
    if (!VirtualProtect(mem, page_size, page.guard_protect, &old)) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return nullptr;
    }

    return mem;
}

bool MemoryVault::vault_free(void* ptr) {
    std::lock_guard lock(pages_mutex_);

    auto it = std::find_if(pages_.begin(), pages_.end(),
        [ptr](const VaultPage& p) { return p.address == ptr; });

    if (it != pages_.end()) {
        if (it->is_decoy) return false;
        VirtualFree(it->address, 0, MEM_RELEASE);
        pages_.erase(it);
        return true;
    }
    return false;
}

void MemoryVault::lock_all() {
    std::lock_guard lock(pages_mutex_);
    for (auto& page : pages_) {
        if (page.is_decoy) continue;
        if (!page.is_locked) {
            encrypt_page(page);
            DWORD old;
            VirtualProtect(page.address, page.size,
                page.guard_protect, &old);
            page.is_locked = true;
            timing_jitter();
        }
    }
}

void MemoryVault::unlock_all() {
    std::lock_guard lock(pages_mutex_);
    for (auto& page : pages_) {
        if (page.is_decoy) continue;
        if (page.is_locked) {
            decrypt_page(page);
            DWORD old;
            VirtualProtect(page.address, page.size,
                PAGE_READWRITE, &old);
            page.is_locked = false;
        }
    }
}

void MemoryVault::cycle_reencrypt() {
    std::lock_guard lock(pages_mutex_);
    size_t relocked = 0;
    size_t max_per_cycle = 1 + (__rdtsc() % 3);

    for (auto& page : pages_) {
        if (page.is_decoy) {
            if ((__rdtsc() & 0xF) == 0) {
                DWORD old;
                VirtualProtect(page.address, page.size, PAGE_READWRITE, &old);
                timing_jitter();
                VirtualProtect(page.address, page.size, page.guard_protect, &old);
            }
            continue;
        }
        if (!page.is_locked && page.access_count > 0) {
            encrypt_page(page);
            DWORD old;
            VirtualProtect(page.address, page.size,
                page.guard_protect, &old);
            page.is_locked = true;
            page.access_count = 0;
            timing_jitter();
            if (++relocked >= max_per_cycle) break;
        }
    }
}

void MemoryVault::encrypt_page(VaultPage& page) {
    if (page.is_locked) return;

    memcpy(page.encrypted_data.data(), page.address, page.size);
    generate_page_key(page);

    uint8_t dk[32];
    memcpy(dk, page.page_key, 32);
    xor_page_key(dk);

    for (size_t i = 0; i < page.size; ++i) {
        uint8_t k = dk[i % 32] ^ (uint8_t)(i * 0xAD) ^ (uint8_t)((i >> 8) * 0x7B);
        page.encrypted_data[i] ^= k;
        page.encrypted_data[i] = (uint8_t)((page.encrypted_data[i] << 3) |
                                  (page.encrypted_data[i] >> 5));
    }

    memset(page.address, page.fill_byte, page.size);
    secure_zero(dk, 32);
    timing_jitter();
}

void MemoryVault::decrypt_page(VaultPage& page) {
    if (!page.is_locked) return;

    uint8_t dk[32];
    memcpy(dk, page.page_key, 32);
    xor_page_key(dk);

    for (size_t i = 0; i < page.size; ++i) {
        uint8_t val = page.encrypted_data[i];
        val = (uint8_t)((val >> 3) | (val << 5));
        uint8_t k = dk[i % 32] ^ (uint8_t)(i * 0xAD) ^ (uint8_t)((i >> 8) * 0x7B);
        val ^= k;
        ((uint8_t*)page.address)[i] = val;
    }

    secure_zero(dk, 32);
    timing_jitter();
}

void memory_guard_start() { MemoryVault::instance(); }

void memory_guard_stop() {
    MemoryVault::instance().lock_all();
}

void* guarded_malloc(size_t size) {
    return MemoryVault::instance().vault_alloc(size);
}

void guarded_free(void* ptr) {
    MemoryVault::instance().vault_free(ptr);
}

void guard_lock_region(void* ptr, size_t size) {
    DWORD old;
    VirtualProtect(ptr, size, PAGE_NOACCESS, &old);
}

void guard_unlock_region(void* ptr, size_t size) {
    DWORD old;
    VirtualProtect(ptr, size, PAGE_READWRITE, &old);
}

StackObfuscator::StackObfuscator() : depth_(0) {
    xor_key_ = (uint8_t)(__rdtsc() & 0xFF) | 0x13;
    memset((void*)slots_, 0, sizeof(slots_));
}

StackObfuscator::~StackObfuscator() {
    scramble();
}

void StackObfuscator::push(uint64_t val) {
    if (depth_ < 16) {
        slots_[depth_] = val ^ ((uint64_t)xor_key_ << 56) ^ (depth_ * 0x9E3779B97F4A7C15ULL);
        depth_++;
    }
}

uint64_t StackObfuscator::pop() {
    if (depth_ == 0) return 0;
    depth_--;
    uint64_t val = slots_[depth_];
    return val ^ ((uint64_t)xor_key_ << 56) ^ (depth_ * 0x9E3779B97F4A7C15ULL);
}

void StackObfuscator::scramble() {
    for (volatile size_t i = 0; i < 16; ++i) {
        slots_[i] ^= __rdtsc();
    }
    depth_ = 0;
    memset((void*)slots_, 0xCC, sizeof(slots_));
}

} // namespace diarna::stealth
