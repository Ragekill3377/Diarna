#pragma once
#include <diarna/compiler_port.hpp>
#include <cstdint>
#include <vector>
#include <span>
#include <string>
#include <functional>
#include <chrono>
#include <algorithm>

namespace diarna::stealth {

struct ROPGadget {
    void* address;
    uint64_t vaddr;
    std::vector<uint8_t> bytes;
    std::string disassembly;
    uint8_t stack_shift;
    bool clobbers_rax;
    bool clobbers_rcx;
    bool clobbers_rdx;
    bool preserves_rsp;
    bool is_ret_gadget;
    uint32_t hash;
};

struct ROPChain {
    std::vector<ROPGadget> gadgets;
    std::vector<uint64_t> stack_values;
    bool is_executable;
    uint32_t hash;
};

class ROPEngine {
public:
    static ROPEngine& instance();

    bool initialize(HMODULE base_module = nullptr);

    std::vector<ROPGadget> find_gadgets(HMODULE module, 
                                         const std::string& constraints = "");
    std::vector<ROPGadget> find_gadgets_in_range(void* start, size_t size,
                                                   const std::string& constraints = "");

    ROPChain build_function_call(void* func_addr,
                                  const std::vector<uint64_t>& args);
    ROPChain build_syscall_chain(uint16_t ssn,
                                  const std::vector<uint64_t>& args);
    bool execute_chain(const ROPChain& chain);
    ROPChain compile_chain(const std::vector<std::string>& gadget_ops);

    void* allocate_chain_stack(const ROPChain& chain);

    struct GadgetStats {
        size_t total_gadgets;
        size_t ret_terminated;
        size_t jmp_terminated;
        size_t call_terminated;
    };
    GadgetStats stats() const;

private:
    ROPEngine() = default;

    struct GadgetCache {
        HMODULE module;
        std::vector<ROPGadget> gadgets;
        std::chrono::steady_clock::time_point scanned_at;
    };

    std::vector<ROPGadget> scan_module(HMODULE module, 
                                         const std::string& constraints);
    bool validate_gadget(const ROPGadget& gadget);
    uint32_t hash_gadget_bytes(std::span<const uint8_t> bytes);
    bool is_ret_instruction(const std::vector<uint8_t>& bytes, size_t pos);

    std::vector<GadgetCache> gadget_cache_;
    void* chain_stack_region_;
    size_t chain_stack_size_;
    GadgetStats stats_;
};

} // namespace diarna::stealth
