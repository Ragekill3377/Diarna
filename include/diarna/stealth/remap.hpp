#pragma once
#include <diarna/compiler_port.hpp>
#include <cstdint>

namespace diarna::stealth {

class ImageRemapper {
public:
    static ImageRemapper& instance();

    bool initialize();
    bool remap_image();
    bool is_remapped() const;

    void* remap_region() const;
    void* section_handle() const;

    struct RemapInfo {
        void* original_base;
        void* remapped_base;
        size_t image_size;
        uint32_t section_count;
        bool active;
        uint64_t remap_ticks;
    };
    RemapInfo info() const;

private:
    ImageRemapper();
    ~ImageRemapper();

    uintptr_t find_remap_routine(void* remap_base, size_t image_size);
    bool relocate_image(void* remap_base, void* original_base);

    void* remap_region_;
    void* section_handle_;
    void* remapped_image_base_;
    bool remapped_;
    RemapInfo info_;
    uint32_t granularity_;
};

void remap_stub_entry();

} // namespace diarna::stealth
