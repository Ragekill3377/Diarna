#pragma once
#include <diarna/compiler_port.hpp>
#include <cstdint>
#include <vector>
#include <span>
#include <string>
#include <functional>

namespace diarna::stealth {

struct KernelCallback {
    void* callback_address;
    uint64_t driver_object;
    std::string driver_name;
    std::string callback_type;
    bool is_active;
    bool is_edr;
};

class KernelOperations {
public:
    static KernelOperations& instance();

    bool initialize();

    std::vector<KernelCallback> enumerate_process_callbacks();
    std::vector<KernelCallback> enumerate_thread_callbacks();
    std::vector<KernelCallback> enumerate_image_load_callbacks();
    std::vector<KernelCallback> enumerate_registry_callbacks();

    bool remove_process_callback(void* callback_addr);
    bool remove_thread_callback(void* callback_addr);
    bool remove_image_callback(void* callback_addr);
    bool remove_all_edr_callbacks();

    bool disable_dse();
    bool enable_dse();
    bool load_driver(const std::wstring& driver_path);
    bool unload_driver(const std::wstring& driver_name);

    struct SystemModule {
        std::string name;
        void* base;
        size_t size;
        bool is_signed;
        std::string signer;
    };
    std::vector<SystemModule> enumerate_kernel_modules();

    bool query_system_information(uint32_t info_class,
                                   void* buffer, uint32_t size,
                                   uint32_t* ret_size);

    static constexpr uint32_t SystemModuleInformation = 11;
    static constexpr uint32_t SystemProcessInformation = 5;
    static constexpr uint32_t SystemHandleInformation = 16;
    static constexpr uint32_t SystemKernelDebuggerInformation = 35;
    static constexpr uint32_t SystemCodeIntegrityInformation = 103;

private:
    KernelOperations() = default;

    uint64_t resolve_kernel_export(const char* name);
    bool read_kernel_memory(uint64_t address, void* buffer, size_t size);
    bool write_kernel_memory(uint64_t address, const void* data, size_t size);

    bool initialized_;
    std::vector<KernelCallback> known_edr_callbacks_;
    void* ntdll_base_;
};

void* alloc_shared_memory(size_t size);
void free_shared_memory(void* addr);

class PebMirror {
public:
    static PebMirror& instance();

    bool initialize();
    void install_mirror();
    void remove_mirror();

    void* get_fake_peb();
    void update_peb_field(size_t offset, const void* data, size_t size);

    bool is_mirroring() const;

private:
    PebMirror();
    ~PebMirror();

    static LONG WINAPI peb_veh(EXCEPTION_POINTERS* ex);

    void* fake_peb_;
    void* real_peb_;
    size_t peb_size_;
    void* veh_handle_;
    bool mirroring_;
};

} // namespace diarna::stealth
