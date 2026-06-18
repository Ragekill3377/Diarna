#pragma once

// These macros must be defined BEFORE any Windows includes
// because headers that use them may be included before obfusheader.h
#ifndef RCAST
    #define RCAST(T, v) reinterpret_cast<T>(v)
#endif
#ifndef CCAST
    #define CCAST(T, v) const_cast<T>(v)
#endif
#ifndef STATUS_NOT_SUPPORTED
    #define STATUS_NOT_SUPPORTED ((NTSTATUS)0xC00000BBL)
#endif
#ifndef SERVICE_ERROR_RESTART
    #define SERVICE_ERROR_RESTART 1
#endif

// Prevent obfusheader.h from hardcoding CFLOW_BRANCHING=1
#ifndef CFLOW_BRANCHING
    #define CFLOW_BRANCHING 0
#endif

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #define NOMINMAX
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <winternl.h>
    #include <psapi.h>
    #include <shellapi.h>
    #include <shlobj.h>
    #include <intrin.h>
#endif

// Fallback macros for obfusheader.h (when it's not included or disabled)
#ifndef INDIRECT_BRANCH
    #define INDIRECT_BRANCH
#endif
#ifndef BLOCK_TRUE
    #define BLOCK_TRUE(x) x
#endif
#ifndef BLOCK_FALSE
    #define BLOCK_FALSE(x)
#endif
#ifndef WATERMARK
    #define WATERMARK(...)
#endif
#ifndef OBF
    #define OBF(x) x
#endif
#ifndef HIDE_PTR
    #define HIDE_PTR(x) (x)
#endif
#ifndef CALL
    #define CALL(x, ...) (x)(__VA_ARGS__)
#endif
#ifndef CALL_EXPORT
    #define CALL_EXPORT(lib, name, type, ret) ((type)GetProcAddress(GetModuleHandleA(lib), name))
#endif
#ifndef MAKEOBF
    #define MAKEOBF(x) x
#endif

#ifdef _MSC_VER
    #define DIARNA_MSVC
#elif defined(__MINGW32__) || defined(__MINGW64__)
    #define DIARNA_MINGW
#elif defined(__GNUC__) || defined(__clang__)
    #define DIARNA_GCC
#else
    #error "Diarna: unsupported compiler. Use MSVC (VS 2019+) or MinGW-w64 (GCC 12+)"
#endif

#if defined(_WIN64) || defined(__x86_64__) || defined(_M_X64) || defined(_M_AMD64)
    #define DIARNA_ARCH_X64
#elif defined(_M_IX86) || defined(__i386__) || defined(_X86_)
    #define DIARNA_ARCH_X86
#else
    #warning "Diarna: architecture not detected, defaulting to x64"
    #define DIARNA_ARCH_X64
#endif

#ifdef DIARNA_MSVC
    #define DIARNA_INLINE      __forceinline
    #define DIARNA_NOINLINE    __declspec(noinline)
    #define DIARNA_NORETURN    __declspec(noreturn)
    #define DIARNA_ALIGN(n)    __declspec(align(n))
    #define DIARNA_SECTION(x)  __declspec(allocate(x))
    #define DIARNA_DLLEXPORT   __declspec(dllexport)
    #define DIARNA_DLLIMPORT   __declspec(dllimport)
    #define DIARNA_NAKED       __declspec(naked)
    #define DIARNA_RESTRICT    __restrict
    #define DIARNA_ASSUME(x)   __assume(x)
    #define DIARNA_UNREACHABLE __assume(0)
    #define DIARNA_BREAK()     __debugbreak()
    #define DIARNA_FASTFAIL(x) __fastfail(x)
#else
    #define DIARNA_INLINE      __attribute__((always_inline)) inline
    #define DIARNA_NOINLINE    __attribute__((noinline))
    #define DIARNA_NORETURN    __attribute__((noreturn))
    #define DIARNA_ALIGN(n)    __attribute__((aligned(n)))
    #define DIARNA_SECTION(x)  __attribute__((section(x)))
    #define DIARNA_DLLEXPORT   __attribute__((dllexport))
    #define DIARNA_DLLIMPORT   __attribute__((dllimport))
    #define DIARNA_NAKED       __attribute__((naked))
    #define DIARNA_RESTRICT    __restrict__
    #define DIARNA_ASSUME(x)   if(!(x)) __builtin_unreachable()
    #define DIARNA_UNREACHABLE __builtin_unreachable()
    #define DIARNA_BREAK()     __builtin_trap()
    #define DIARNA_FASTFAIL(x) __builtin_trap()
#endif

// --- LINKER PRAGMAS ---
#ifdef DIARNA_MSVC
    #define DIARNA_LINK_LIB(name) __pragma(comment(lib, name))
#else
    #define DIARNA_LINK_LIB(name)
#endif

#ifdef DIARNA_MSVC
    #define DIARNA_SECTION_START(name) __pragma(section(name, read, write))
#else
    #define DIARNA_SECTION_START(name)
#endif

// --- CPUID / RDTSC / SYSTEM INTRINSICS ---
#ifdef DIARNA_MSVC
    #include <intrin.h>
    #define DIARNA_CPUID(info, func)       __cpuid((int*)(info), (int)(func))
    #define DIARNA_CPUIDEX(info, func, sub) __cpuidex((int*)(info), (int)(func), (int)(sub))
    #define DIARNA_RDTSC()                 __rdtsc()
    #define DIARNA_RDTSCP(aux)             __rdtscp((unsigned int*)(aux))
    #define DIARNA_READ_GSQWORD(off)       __readgsqword((unsigned long)(off))
    #define DIARNA_WRITE_GSQWORD(off, v)   __writegsqword((unsigned long)(off), (unsigned __int64)(v))
    #define DIARNA_READMSR(msr)            __readmsr((unsigned long)(msr))
    #define DIARNA_WRITEMSR(msr, v)        __writemsr((unsigned long)(msr), (unsigned __int64)(v))
    #define DIARNA_READ_CR0()              __readcr0()
    #define DIARNA_READ_CR2()              __readcr2()
    #define DIARNA_READ_CR3()              __readcr3()
    #define DIARNA_READ_CR4()              __readcr4()
    #define DIARNA_WRITE_CR0(v)            __writecr0((unsigned __int64)(v))
    #define DIARNA_WRITE_CR4(v)            __writecr4((unsigned __int64)(v))
    #define DIARNA_READ_EFLGAS()           __readeflags()
    #define DIARNA_WRITE_EFLAGS(v)         __writeeflags((unsigned __int64)(v))
    #define DIARNA_INBYTE(p)               __inbyte((unsigned short)(p))
    #define DIARNA_OUTBYTE(p, d)           __outbyte((unsigned short)(p), (unsigned char)(d))
    #define DIARNA_STOSB(dst, val, cnt)    __stosb((unsigned char*)(dst), (unsigned char)(val), (size_t)(cnt))
    #define DIARNA_STOSW(dst, val, cnt)    __stosw((unsigned short*)(dst), (unsigned short)(val), (size_t)(cnt))
    #define DIARNA_STOSD(dst, val, cnt)    __stosd((unsigned long*)(dst), (unsigned long)(val), (size_t)(cnt))
    #define DIARNA_LIDT(addr)              __lidt((void*)(addr))
    #define DIARNA_SIDT(addr)              __sidt((void*)(addr))
    #define DIARNA_SGDT(addr)              __sgdt((void*)(addr))
    #define DIARNA_SLDT()                  __sldt()
    #define DIARNA_STR()                   __str()
    #define DIARNA_CLFLUSH(addr)           _mm_clflush((void const*)(addr))
    #define DIARNA_CLFLUSHOPT(addr)        _mm_clflushopt((void const*)(addr))
    #define DIARNA_MFENCE()                _mm_mfence()
    #define DIARNA_SFENCE()                _mm_sfence()
    #define DIARNA_LFENCE()                _mm_lfence()
    #define DIARNA_PAUSE()                 _mm_pause()
    #define DIARNA_XGETBV(xcr)             _xgetbv((unsigned int)(xcr))
    #define DIARNA_XSETBV(xcr, val)        _xsetbv((unsigned int)(xcr), (unsigned __int64)(val))
    #define DIARNA_BSF(idx, mask)          _BitScanForward((unsigned long*)(idx), (unsigned long)(mask))
    #define DIARNA_BSF64(idx, mask)        _BitScanForward64((unsigned long*)(idx), (unsigned __int64)(mask))
    #define DIARNA_BSR(idx, mask)          _BitScanReverse((unsigned long*)(idx), (unsigned long)(mask))
    #define DIARNA_BSR64(idx, mask)        _BitScanReverse64((unsigned long*)(idx), (unsigned __int64)(mask))
    #define DIARNA_ROTL8(v, c)             __rotl8((unsigned char)(v), (unsigned char)(c))
    #define DIARNA_ROTL16(v, c)            __rotl16((unsigned short)(v), (unsigned char)(c))
    #define DIARNA_ROTR8(v, c)             __rotr8((unsigned char)(v), (unsigned char)(c))
    #define DIARNA_ROTR16(v, c)            __rotr16((unsigned short)(v), (unsigned char)(c))
    #define DIARNA_BYTE_SWAP16(v)          _byteswap_ushort((unsigned short)(v))
    #define DIARNA_BYTE_SWAP32(v)          _byteswap_ulong((unsigned long)(v))
    #define DIARNA_BYTE_SWAP64(v)          _byteswap_uint64((unsigned __int64)(v))
    #define DIARNA_POPCNT16(v)             __popcnt16((unsigned short)(v))
    #define DIARNA_POPCNT(v)               __popcnt((unsigned int)(v))
    #define DIARNA_POPCNT64(v)             __popcnt64((unsigned __int64)(v))
#else
    #include <x86intrin.h>
    DIARNA_INLINE void __diarna_cpuid(int info[4], unsigned leaf) {
        asm volatile("cpuid":"=a"(info[0]),"=b"(info[1]),"=c"(info[2]),"=d"(info[3]):"a"(leaf));
    }
    DIARNA_INLINE void __diarna_cpuidex(int info[4], unsigned leaf, unsigned subleaf) {
        asm volatile("cpuid":"=a"(info[0]),"=b"(info[1]),"=c"(info[2]),"=d"(info[3]):"a"(leaf),"c"(subleaf));
    }
    #define DIARNA_CPUID(info, func)       __diarna_cpuid((int*)(info), (unsigned)(func))
    #define DIARNA_CPUIDEX(info, func, sub) __diarna_cpuidex((int*)(info), (unsigned)(func), (unsigned)(sub))
    #define DIARNA_RDTSC()                 __rdtsc()
    #define DIARNA_RDTSCP(aux)             __rdtscp((unsigned int*)(aux))
    #define DIARNA_READ_GSQWORD(off)       ({ unsigned long long __v; asm volatile("movq %%gs:%1, %0":"=r"(__v):"m"(*(const unsigned long long*)(off)):"memory"); __v; })
    #define DIARNA_READ_CR0()              ({ unsigned long long __v; asm volatile("movq %%cr0, %0":"=r"(__v)); __v; })
    #define DIARNA_READ_CR2()              ({ unsigned long long __v; asm volatile("movq %%cr2, %0":"=r"(__v)); __v; })
    #define DIARNA_READ_CR3()              ({ unsigned long long __v; asm volatile("movq %%cr3, %0":"=r"(__v)); __v; })
    #define DIARNA_READ_EFLGAS()           ({ unsigned long long __v; asm volatile("pushfq; popq %0":"=r"(__v)); __v; })
    #define DIARNA_CLFLUSH(addr)           asm volatile("clflush %0"::"m"(*(const char*)(addr)))
    #define DIARNA_MFENCE()                asm volatile("mfence":::"memory")
    #define DIARNA_SFENCE()                asm volatile("sfence":::"memory")
    #define DIARNA_LFENCE()                asm volatile("lfence":::"memory")
    #define DIARNA_PAUSE()                 asm volatile("pause")
    #define DIARNA_XGETBV(xcr)             ({ unsigned eax, edx; asm volatile("xgetbv":"=a"(eax),"=d"(edx):"c"(xcr)); ((unsigned long long)edx<<32)|eax; })
    #define DIARNA_BYTE_SWAP16(v)          __builtin_bswap16((unsigned short)(v))
    #define DIARNA_BYTE_SWAP32(v)          __builtin_bswap32((unsigned int)(v))
    #define DIARNA_BYTE_SWAP64(v)          __builtin_bswap64((unsigned long long)(v))
    #define DIARNA_POPCNT16(v)             __builtin_popcount((unsigned int)(v) & 0xFFFF)
    #define DIARNA_POPCNT(v)               __builtin_popcount((unsigned int)(v))
    #define DIARNA_POPCNT64(v)             __builtin_popcountll((unsigned long long)(v))
    #define DIARNA_BSF(idx, mask)          do { *(idx) = __builtin_ctz(mask); } while(0)
    #define DIARNA_BSF64(idx, mask)        do { *(idx) = __builtin_ctzll(mask); } while(0)
    #define DIARNA_BSR(idx, mask)          do { *(idx) = 31 - __builtin_clz(mask); } while(0)
    #define DIARNA_BSR64(idx, mask)        do { *(idx) = 63 - __builtin_clzll(mask); } while(0)
    #define DIARNA_ROTL8(v, c)             ((unsigned char)(((unsigned char)(v) << (c)) | ((unsigned char)(v) >> (8-(c)))))
    #define DIARNA_ROTL16(v, c)            ((unsigned short)(((unsigned short)(v) << (c)) | ((unsigned short)(v) >> (16-(c)))))
    #define DIARNA_LIDT(addr)              asm volatile("lidt %0"::"m"(*(const void**)(addr)))
    #define DIARNA_SIDT(addr)              ({ struct { uint16_t limit; uint64_t base; } __attribute__((packed)) __d = {}; asm volatile("sidt %0":"=m"(__d)); *(uint64_t*)(addr) = __d.base; })
    #define DIARNA_SGDT(addr)              ({ struct { uint16_t limit; uint64_t base; } __attribute__((packed)) __d = {}; asm volatile("sgdt %0":"=m"(__d)); *(uint64_t*)(addr) = __d.base; })
    #define DIARNA_SLDT()                  ({ unsigned short __v; asm volatile("sldt %0":"=r"(__v)); __v; })
    #define DIARNA_STR()                   ({ unsigned short __v; asm volatile("str %0":"=r"(__v)); __v; })
#endif

// --- INLINE ASSEMBLY MACROS ---
#ifdef DIARNA_MSVC
    #ifdef DIARNA_ARCH_X64
        // MSVC x64: no inline asm. Use .asm files or intrinsics.
        #define DIARNA_ASM_BEGIN
        #define DIARNA_ASM_END
        #define DIARNA_ASM_EMIT(x)
    #else
        // MSVC x86: __asm { } blocks
        #define DIARNA_ASM_BEGIN    __asm {
        #define DIARNA_ASM_END      }
        #define DIARNA_ASM_EMIT(x)  __asm _emit x
    #endif
#else
    // MinGW/GCC: GAS .intel_syntax noprefix
    #define DIARNA_ASM_BEGIN    asm volatile(".intel_syntax noprefix\n\t"
    #define DIARNA_ASM_END      ".att_syntax prefix\n\t" ::: "memory")
    #define DIARNA_ASM_EMIT(x)  ".byte " #x "\n\t"
#endif

// Unified inline ASM helper for single instructions
#ifdef DIARNA_MSVC
    #ifdef DIARNA_ARCH_X64
        #define DIARNA_ASM_INSTR(x)  // MSVC x64: no inline asm
    #else
        #define DIARNA_ASM_INSTR(x) __asm { x }
    #endif
#else
    #define DIARNA_ASM_INSTR(x) asm volatile(#x "\n\t" ::: "memory")
#endif

// --- COMPILER ATTRIBUTE MACROS ---
#ifdef DIARNA_MSVC
    #define DIARNA_PACKED
    #define DIARNA_UNUSED
#else
    #define DIARNA_PACKED __attribute__((packed))
    #define DIARNA_UNUSED __attribute__((unused))
#endif

// --- EXCEPTION / SEH ---
#ifdef DIARNA_MSVC
    #define DIARNA_TRY        __try
    #define DIARNA_EXCEPT(x)  __except(x)
    #define DIARNA_FINALLY    __finally
    #define DIARNA_LEAVE      __leave
    #define DIARNA_EXCEPTION_EXECUTE_HANDLER EXCEPTION_EXECUTE_HANDLER
    #define DIARNA_EXCEPTION_CONTINUE_SEARCH EXCEPTION_CONTINUE_SEARCH
    #define DIARNA_EXCEPTION_CONTINUE_EXECUTION EXCEPTION_CONTINUE_EXECUTION
#else
    #define DIARNA_TRY
    #define DIARNA_EXCEPT(x)  if(0)
    #define DIARNA_FINALLY
    #define DIARNA_LEAVE
    #define DIARNA_EXCEPTION_EXECUTE_HANDLER 1
    #define DIARNA_EXCEPTION_CONTINUE_SEARCH 0
    #define DIARNA_EXCEPTION_CONTINUE_EXECUTION -1
#endif

// --- THREAD LOCAL ---
#ifdef DIARNA_MSVC
    #define DIARNA_THREAD_LOCAL __declspec(thread)
#else
    #define DIARNA_THREAD_LOCAL __thread
#endif

// --- CALLING CONVENTIONS ---
#ifdef DIARNA_MSVC
    #define DIARNA_CDECL    __cdecl
    #define DIARNA_STDCALL  __stdcall
    #define DIARNA_FASTCALL __fastcall
    #define DIARNA_VECTORCALL __vectorcall
#else
    #define DIARNA_CDECL    __attribute__((cdecl))
    #define DIARNA_STDCALL  __attribute__((stdcall))
    #define DIARNA_FASTCALL __attribute__((fastcall))
    #define DIARNA_VECTORCALL
#endif

// --- OPTIMIZATION HINTS ---
#ifdef DIARNA_MSVC
    #define DIARNA_LIKELY(x)   (x)
    #define DIARNA_UNLIKELY(x) (x)
#else
    #define DIARNA_LIKELY(x)   __builtin_expect(!!(x), 1)
    #define DIARNA_UNLIKELY(x) __builtin_expect(!!(x), 0)
#endif

// --- COMPILE-TIME WARNINGS ---
#ifdef DIARNA_MSVC
    #define DIARNA_WARNING_PUSH      __pragma(warning(push))
    #define DIARNA_WARNING_POP       __pragma(warning(pop))
    #define DIARNA_WARNING_DISABLE(n) __pragma(warning(disable:n))
#else
    #define DIARNA_WARNING_PUSH      _Pragma("GCC diagnostic push")
    #define DIARNA_WARNING_POP       _Pragma("GCC diagnostic pop")
    #define DIARNA_WARNING_DISABLE_STR(x) _Pragma(#x)
    #define DIARNA_WARNING_DISABLE(n) DIARNA_WARNING_DISABLE_STR(GCC diagnostic ignored "-Wunknown-warning")
#endif

// --- MINGW-SPECIFIC FIXES ---
#ifdef DIARNA_MINGW
    // MinGW headers may lack some recent SDK definitions
    #ifndef PROCESSOR_ARCHITECTURE_ARM64
        #define PROCESSOR_ARCHITECTURE_ARM64 12
    #endif
    #ifndef IMAGE_FILE_MACHINE_ARM64
        #define IMAGE_FILE_MACHINE_ARM64 0xAA64
    #endif

    // MinGW's wincrypt.h may not have certain structs
    #ifndef CRYPT_STRING_NOCRLF
        #define CRYPT_STRING_NOCRLF 0x40000000
    #endif

    // SEH macros for GCC
    #include <excpt.h>
    #define EXCEPTION_EXECUTE_HANDLER 1
    #define EXCEPTION_CONTINUE_SEARCH 0
    #define EXCEPTION_CONTINUE_EXECUTION -1
    #define EXCEPTION_ACCESS_VIOLATION 0xC0000005
    #define EXCEPTION_GUARD_PAGE      0x80000001
    #define EXCEPTION_ILLEGAL_INSTRUCTION 0xC000001D
    #define EXCEPTION_PRIV_INSTRUCTION    0xC0000096
#endif

// Export control: when building the DLL, define DIARNA_BUILD_DLL
#ifdef DIARNA_BUILD_DLL
    #define DIARNA_API DIARNA_DLLEXPORT
#else
    #define DIARNA_API DIARNA_DLLIMPORT
#endif
#ifdef DIARNA_STATIC
    #undef  DIARNA_API
    #define DIARNA_API
#endif
