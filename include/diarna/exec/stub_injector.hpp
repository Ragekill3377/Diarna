#pragma once
#include <diarna/compiler_port.hpp>
#include <cstdint>
#include <string>
#include <vector>
#include <span>
#include <chrono>
#include <mutex>

namespace diarna::exec {

class StubInjector {
public:
    static StubInjector& instance();

    bool inject_into_process(const std::wstring& process_name,
                             std::span<const uint8_t> stub_code);
    bool extend_function(void* target_func, void* hook, void** trampoline);
    bool remove_all();

    struct StubInfo {
        uint32_t pid;
        std::wstring process_name;
        void* stub_address;
        size_t stub_size;
        std::chrono::steady_clock::time_point injected_at;
    };
    std::vector<StubInfo> active_stubs() const;

private:
    StubInjector();
    std::vector<StubInfo> stubs_;
    mutable std::mutex mutex_;
    uint32_t find_pid(const std::wstring& name);
};

} // namespace diarna::exec
