#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <functional>
#include <atomic>
#include <mutex>
#include <map>
#include <random>
#include <thread>
#include <chrono>

namespace diarna::stealth {

struct MutationPass {
    enum Type : uint8_t {
        SUB_XOR_TO_SUB_ADD,
        SUB_ADD_TO_LEA,
        PUSH_POP_TO_MOV,
        MOV_REG_REG,
        JMP_JCC_INVERSION,
        REGISTER_SWAP,
        NOP_SLED_VAR,
        DEAD_CODE_INJECTION,
        INSTRUCTION_REORDER,
        CONSTANT_FOLDING_FAKE,
        CALL_TO_PUSH_RET,
        RET_TO_JMP,
        PREFIX_JUNK,
        OPCODE_SUBSTITUTION,
        BRANCH_OBFUSCATION,
        COUNT
    } type;
    uint32_t seed;
    bool operator()(std::vector<uint8_t>& code) const;
};

struct MetamorphicBlock {
    std::vector<uint8_t> original;
    std::vector<uint8_t> current;
    uint32_t mutation_counter;
    uint64_t last_mutation_ts;
    uint32_t seed;
    bool is_active;
    void* runtime_address;
    size_t runtime_size;
    uint32_t checksum;
};

class PolymorphicEngine {
public:
    static PolymorphicEngine& instance();

    void initialize(uint32_t seed = 0);

    void* metamorphic_alloc(size_t size, bool executable = true);
    bool metamorphic_free(void* ptr);

    template<typename F, typename... Args>
    auto mutate_and_execute(void* func_block, F&& original_fn,
                            Args&&... args) -> decltype(original_fn(args...)) {
        trigger_mutation(func_block);
        return original_fn(std::forward<Args>(args)...);
    }

    void trigger_mutation(void* block_addr);
    void mutate_all_active();
    void set_mutation_interval(std::chrono::milliseconds interval);

    std::vector<uint8_t> generate_polymorphic_stub(
        std::span<const uint8_t> payload,
        uint32_t num_variants = 5);

    std::vector<uint8_t> obfuscate_control_flow(
        std::span<const uint8_t> code);

    void* generate_thunk(void* target);
    void install_trampoline(void* orig, void* hook, void** trampoline);

    struct Stats {
        uint64_t mutations_performed;
        uint64_t bytes_mutated;
        uint64_t blocks_active;
        uint64_t transforms_applied;
    };
    Stats stats() const;

    friend class CodeMutationGuard;

private:
    PolymorphicEngine();
    ~PolymorphicEngine();
    PolymorphicEngine(const PolymorphicEngine&) = delete;
    PolymorphicEngine& operator=(const PolymorphicEngine&) = delete;

    static DWORD WINAPI mutation_worker(LPVOID param);
    void apply_mutation_pass(MetamorphicBlock& block, MutationPass::Type pass);
    void update_block_checksum(MetamorphicBlock& block);

    struct MutationTracker {
        void* addr;
        size_t size;
        uint32_t checksum;
        uint64_t last_seen;
        bool tainted;
    };

    std::map<void*, MetamorphicBlock> blocks_;
    std::mutex blocks_mutex_;
    std::atomic<bool> running_{false};
    std::thread monitor_thread_;
    std::chrono::milliseconds mutation_interval_{15000};
    std::mt19937_64 rng_;
    Stats stats_;
    std::mutex stats_mutex_;

    static constexpr size_t GADGET_POOL_SIZE = 4096;
    uint8_t* gadget_pool_;
    size_t gadget_pool_offset_;

    std::vector<uint8_t> x86_sub_add(const std::vector<uint8_t>& code);
    std::vector<uint8_t> x86_reg_swap(const std::vector<uint8_t>& code);
    std::vector<uint8_t> x86_junk_inject(const std::vector<uint8_t>& code, uint32_t seed);
    std::vector<uint8_t> x86_opcode_substitution(const std::vector<uint8_t>& code);
    std::vector<uint8_t> x86_branch_obfuscation(const std::vector<uint8_t>& code);
    std::vector<uint8_t> x86_dead_code(const std::vector<uint8_t>& code, uint32_t seed);
    std::vector<uint8_t> x86_register_shuffle(const std::vector<uint8_t>& code, uint32_t seed);
    std::vector<uint8_t> x86_push_pop(const std::vector<uint8_t>& code);
    std::vector<uint8_t> x86_instruction_shuffle(const std::vector<uint8_t>& code, uint32_t seed);

    struct X86Instruction {
        uint8_t opcode;
        uint8_t modrm;
        uint8_t sib;
        uint8_t displacement[4];
        uint8_t disp_size;
        uint8_t immediate[8];
        uint8_t imm_size;
        uint8_t prefix[4];
        uint8_t prefix_count;
        uint8_t length;
        uint64_t address;
        bool is_branch;
        bool is_call;
        bool is_ret;
        uint32_t branch_target_offset;
    };

    std::vector<X86Instruction> disassemble_chunk(const std::vector<uint8_t>& code);
    std::vector<uint8_t> assemble_chunk(const std::vector<X86Instruction>& instructions);
    uint32_t hash_buffer(std::span<const uint8_t> data);
};

class CodeMutationGuard {
public:
    CodeMutationGuard(void* block);
    ~CodeMutationGuard();

private:
    void* block_;
    bool was_locked_;
};

} // namespace diarna::stealth
