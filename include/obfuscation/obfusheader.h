#ifndef OBFUSHEADER_H
#define OBFUSHEADER_H

#ifndef CFLOW_BRANCHING
    #define CFLOW_BRANCHING 0
#endif

#ifndef CONST_ENCRYPTION
    #define CONST_ENCRYPTION 1
#endif

#ifndef INDIRECT_BRANCHING
    #define INDIRECT_BRANCHING 1
#endif

#ifndef FAKE_SIGNATURES
    #define FAKE_SIGNATURES 1
#endif

#ifndef OBF_UNSUPPORTED
    #if !defined(_MSC_VER) && !defined(__MINGW32__) && !defined(__MINGW64__) && !defined(__GNUC__) && !defined(__clang__)
        #error "obfusheader.h: unsupported compiler. Define OBF_UNSUPPORTED to bypass."
    #endif
#endif

#ifdef _MSC_VER
    #define OBF_MSVC
#elif defined(__MINGW32__) || defined(__MINGW64__)
    #define OBF_MINGW
#elif defined(__GNUC__) || defined(__clang__)
    #define OBF_GCC
#endif

#undef INLINE
#undef NOINLINE
#undef SECTION
#undef RCAST
#undef CCAST
#undef CAST
#undef OBF
#undef OBFW
#undef MAKEOBF
#undef MAKEOBFW
#undef OBFN
#undef INDIRECT_BRANCH
#undef BLOCK_TRUE
#undef BLOCK_FALSE
#undef WATERMARK
#undef HIDE_PTR
#undef CALL
#undef CALL_EXPORT
#undef int_proxy

#ifdef OBF_MSVC
    #define INLINE             __forceinline
    #define NOINLINE           __declspec(noinline)
    #define OBF_SEC_IMPL(x)    __pragma(section(x, read, write)) __declspec(allocate(x))
    #define OBF_SEC_RO_IMPL(x) __pragma(section(x, read)) __declspec(allocate(x))
    #define OBF_USED
    #define OBF_RETAIN
    #define OBF_EMPTY_ASM
    #define OBF_PACK_START      __pragma(pack(push, 1))
    #define OBF_PACK_END        __pragma(pack(pop))
#else
    #define INLINE             __attribute__((always_inline)) inline
    #define NOINLINE           __attribute__((noinline))
    #define OBF_SEC_IMPL(x)    __attribute__((section(x)))
    #define OBF_SEC_RO_IMPL(x) __attribute__((section(x)))
    #define OBF_USED            __attribute__((used))
    #define OBF_RETAIN          OBF_USED
    #define OBF_EMPTY_ASM       __asm__ volatile("" ::: "memory")
    #define OBF_PACK_START      _Pragma("pack(push,1)")
    #define OBF_PACK_END        _Pragma("pack(pop)")
#endif

#ifndef SECTION
    #ifdef OBF_MSVC
        #define SECTION(x) __declspec(allocate(x))
    #else
        #define SECTION(x) __attribute__((section(x)))
    #endif
#endif

#ifndef __COUNTER__
    #define __COUNTER__ __LINE__
#endif

#define RCAST(T, v) reinterpret_cast<T>(v)
#define CCAST(T, v) const_cast<T>(v)
#define CAST(T, v)  static_cast<T>(v)

#define _DIARNA_CAT_IMPL(a, b) a##b
#define _DIARNA_CAT(a, b)      _DIARNA_CAT_IMPL(a, b)
#define _DIARNA_UNIQ(prefix)   _DIARNA_CAT(prefix, __COUNTER__)

namespace obf {

consteval unsigned ctime_seed_impl() {
    const char* t = __TIME__;
    unsigned h = (t[0] - '0') * 10 + (t[1] - '0');
    unsigned m = (t[3] - '0') * 10 + (t[4] - '0');
    unsigned s = (t[6] - '0') * 10 + (t[7] - '0');
    return (h * 3600 + m * 60 + s) ^ 0x9E3779B9u;
}

consteval unsigned ctime_seed_ctr(unsigned ctr) {
    return (ctime_seed_impl() + ctr * 0x9E3779B1u) ^ ((ctr << 13) | (ctr >> 19));
}

consteval unsigned ctime_seed_ctr2(unsigned ctr) {
    return (ctime_seed_ctr(ctr) ^ 0xDEADBEEFu) * 0x19660Du + ctr;
}

consteval unsigned ctime_seed_line(unsigned ctr, unsigned line) {
    return ctime_seed_ctr(ctr) ^ (line * 0x811C9DC5u) + 0x9E3779B9u;
}

template<char K>
INLINE void xor_buf(char* dst, const char* src, size_t n) {
    for (size_t i = 0; i < n; i++)
        dst[i] = src[i] ^ K;
}

template<char K>
INLINE void xor_buf_w(wchar_t* dst, const wchar_t* src, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned L = (unsigned)(unsigned short)src[i];
        unsigned H = (unsigned)((unsigned)(unsigned short)src[i] >> 8);
        L ^= (unsigned char)K;
        H ^= (unsigned char)(K ^ 0x5A);
        dst[i] = (wchar_t)((unsigned short)((H << 8) | L));
    }
}

INLINE unsigned fold_seed(unsigned s, unsigned m) {
    return (s ^ (s >> 16)) * 0x85EBCA6Bu % m;
}

template<typename T>
INLINE T rotl_impl(T v, unsigned c) {
    constexpr unsigned bits = sizeof(T) * 8;
    return (v << c) | (v >> (bits - c));
}

template<class T, size_t N, char K>
class obfuscator {
public:
    T enc[N]{};
    constexpr obfuscator(const T* s) {
        for (size_t i = 0; i < N; i++)
            enc[i] = s[i] ^ K;
    }
    INLINE void xord(T* out) const {
        for (size_t i = 0; i < N; i++)
            out[i] = enc[i] ^ K;
    }
};

template<class T, size_t N, char K>
class decryptor {
public:
    T dec[N]{};
    constexpr decryptor(const T* enc_in) {
        for (size_t i = 0; i < N; i++)
            dec[i] = enc_in[i] ^ K;
    }
    INLINE const T* xord() const { return dec; }
};

template<size_t N, char K>
class obfuscator_w {
public:
    wchar_t enc[N]{};
    constexpr obfuscator_w(const wchar_t* s) {
        for (size_t i = 0; i < N; i++) {
            unsigned L = (unsigned)(unsigned short)s[i];
            unsigned H = (unsigned)((unsigned)(unsigned short)s[i] >> 8);
            L ^= (unsigned char)K;
            H ^= (unsigned char)(K ^ 0x5A);
            enc[i] = (wchar_t)((unsigned short)((H << 8) | L));
        }
    }
    INLINE void xord(wchar_t* out) const {
        for (size_t i = 0; i < N; i++) {
            unsigned L = (unsigned)(unsigned short)enc[i];
            unsigned H = (unsigned)((unsigned)(unsigned short)enc[i] >> 8);
            L ^= (unsigned char)K;
            H ^= (unsigned char)(K ^ 0x5A);
            out[i] = (wchar_t)((unsigned short)((H << 8) | L));
        }
    }
};

template<size_t N, char K>
class decryptor_w {
public:
    wchar_t dec[N]{};
    constexpr decryptor_w(const wchar_t* enc_in) {
        for (size_t i = 0; i < N; i++) {
            unsigned L = (unsigned)(unsigned short)enc_in[i];
            unsigned H = (unsigned)((unsigned)(unsigned short)enc_in[i] >> 8);
            L ^= (unsigned char)K;
            H ^= (unsigned char)(K ^ 0x5A);
            dec[i] = (wchar_t)((unsigned short)((H << 8) | L));
        }
    }
    INLINE const wchar_t* xord() const { return dec; }
};

template<typename F>
INLINE F hide_ptr_fwd(F ptr) {
    volatile F table[3] = {};
    table[0] = ptr;
    table[1] = ptr;
    table[2] = ptr;
    return table[(ctime_seed_impl() & 1) ? 1 : 0];
}

volatile long _int_proxy_storage  = 0xC0DE;
volatile long _int_proxy_storage2 = 0x0BADF00D;

INLINE int int_proxy_rot() {
    long v = _int_proxy_storage;
    _int_proxy_storage = rotl_impl((unsigned long)v, 13);
    _int_proxy_storage2 ^= v;
    return (int)(v & 1);
}

} // namespace obf

#define CTimeSeed   obf::ctime_seed_impl()
#define CTimeSeed2  obf::ctime_seed_ctr2(__COUNTER__)
#define _RND        (obf::ctime_seed_ctr(__COUNTER__) & 0xFFu)
#define _RND_LINE   (obf::ctime_seed_line(__COUNTER__, __LINE__) & 0xFFu)
#define _FOLD(s, m) obf::fold_seed((unsigned)(s), (unsigned)(m))

#define _OBF_KEY_IMPL(ctr)    ((char)(obf::ctime_seed_ctr(ctr) & 0xFF))
#define _OBF_KEY              _OBF_KEY_IMPL(__COUNTER__)
#define _OBF_KEY_LINE          ((char)(_RND_LINE))
#define _OBF_KEY_ONCE(id)     ((char)(obf::ctime_seed_ctr2(id) & 0xFF))

#pragma region OBFUSCATION

#define OBF_KEY_NORMAL(str) \
    ([]() -> const char* { \
        constexpr char _k = _OBF_KEY; \
        constexpr static obf::obfuscator<char, sizeof(str), _k> _obf(str); \
        static char _buf[sizeof(str)]; \
        static bool _init = false; \
        if (!_init) { _obf.xord(_buf); _init = true; } \
        return _buf; \
    }())

#define OBF_KEY_THREADLOCAL(str) \
    ([]() -> const char* { \
        constexpr char _k = _OBF_KEY; \
        constexpr static obf::obfuscator<char, sizeof(str), _k> _obf(str); \
        thread_local static char _buf[sizeof(str)]; \
        thread_local static bool _init = false; \
        if (!_init) { _obf.xord(_buf); _init = true; } \
        return _buf; \
    }())

#define OBFW_KEY_NORMAL(wstr) \
    ([]() -> const wchar_t* { \
        constexpr char _k = _OBF_KEY; \
        constexpr static obf::obfuscator_w<sizeof(wstr)/sizeof(wchar_t), _k> _obf(wstr); \
        static wchar_t _buf[sizeof(wstr)/sizeof(wchar_t)]; \
        static bool _init = false; \
        if (!_init) { _obf.xord(_buf); _init = true; } \
        return _buf; \
    }())

#define OBFW_KEY_THREADLOCAL(wstr) \
    ([]() -> const wchar_t* { \
        constexpr char _k = _OBF_KEY; \
        constexpr static obf::obfuscator_w<sizeof(wstr)/sizeof(wchar_t), _k> _obf(wstr); \
        thread_local static wchar_t _buf[sizeof(wstr)/sizeof(wchar_t)]; \
        thread_local static bool _init = false; \
        if (!_init) { _obf.xord(_buf); _init = true; } \
        return _buf; \
    }())

#ifdef CONST_ENCRYPT_MODE
    #if CONST_ENCRYPT_MODE == THREADLOCAL
        #define MAKEOBF(str)  OBF_KEY_THREADLOCAL(str)
        #define MAKEOBFW(str) OBFW_KEY_THREADLOCAL(str)
    #else
        #define MAKEOBF(str)  OBF_KEY_NORMAL(str)
        #define MAKEOBFW(str) OBFW_KEY_NORMAL(str)
    #endif
#else
    #define MAKEOBF(str)  OBF_KEY_NORMAL(str)
    #define MAKEOBFW(str) OBFW_KEY_NORMAL(str)
#endif

#if CONST_ENCRYPTION
    #define OBF(str)   OBF_KEY_NORMAL(str)
    #define OBFW(str)  OBFW_KEY_NORMAL(str)
    #define OBFN(str)  OBF_KEY_NORMAL(str)
    #define OBFWN(str) OBFW_KEY_NORMAL(str)
#else
    #define OBF(str)   (str)
    #define OBFW(str)  (str)
    #define OBFN(str)  (str)
    #define OBFWN(str) (str)
#endif

#define OBF_CONST_INT(v) \
    ([]() -> auto { \
        constexpr char _k = _OBF_KEY; \
        constexpr auto _enc = (v) ^ _k; \
        return _enc ^ _k; \
    }())

#if INDIRECT_BRANCHING
    #ifdef OBF_MSVC
        #if defined(_M_AMD64) || defined(_M_X64)
            #define INDIRECT_BRANCH
        #else
            #define INDIRECT_BRANCH \
                __asm { xor eax, eax } \
                __asm { jz _ib_label } \
                __asm { _emit 0x00 } \
                __asm { _ib_label: }
        #endif
    #else
        #if defined(__x86_64__) || defined(_M_X64) || defined(_M_AMD64)
            #define INDIRECT_BRANCH \
                __asm__ volatile("xorq %%rax, %%rax\n\t" \
                                 "jz 1f\n\t" \
                                 ".byte 0x00\n\t" \
                                 "1:" ::: "rax", "cc", "memory")
        #else
            #define INDIRECT_BRANCH \
                __asm__ volatile("xorl %%eax, %%eax\n\t" \
                                 "jz 1f\n\t" \
                                 ".byte 0x00\n\t" \
                                 "1:" ::: "eax", "cc", "memory")
        #endif
    #endif
#else
    #define INDIRECT_BRANCH
#endif

#define _TRUE  (obf::_int_proxy_storage >= 0)
#define _FALSE (obf::_int_proxy_storage < 0)

#define int_proxy obf::_int_proxy_storage

#define BLOCK_TRUE(x)  \
    do { if (_TRUE) { x; } else { int_proxy++; obf::_int_proxy_storage2 ^= (long)(size_t)(&int_proxy); OBF_EMPTY_ASM; } } while(0)

#define BLOCK_FALSE(x) \
    do { if (_FALSE) { x; OBF_EMPTY_ASM; } else { int_proxy++; } } while(0)

#define BLOCK_OPAQUE(x) \
    do { \
        volatile int _bp = obf::int_proxy_rot(); \
        if (_bp) { x; } else { int_proxy++; OBF_EMPTY_ASM; } \
    } while(0)

#define JUNK_CODE \
    do { \
        OBF_EMPTY_ASM; \
        volatile unsigned _jk = (unsigned)(_RND_LINE); \
        _jk ^= (unsigned)(size_t)(&_jk); \
        obf::_int_proxy_storage2 ^= (long)_jk; \
        OBF_EMPTY_ASM; \
    } while(0)

#ifdef OBF_MSVC
    #define WATERMARK(...) \
        __pragma(section(".diarna_w", read)) \
        __declspec(allocate(".diarna_w")) \
        static volatile const char _DIARNA_UNIQ(_diarna_wm_)[] = "" __VA_ARGS__
    #define WATERMARK_W(...) \
        __pragma(section(".diarna_ww", read)) \
        __declspec(allocate(".diarna_ww")) \
        static volatile const wchar_t _DIARNA_UNIQ(_diarna_wwm_)[] = L"" __VA_ARGS__
#else
    #define WATERMARK(...) \
        static volatile const char _DIARNA_UNIQ(_diarna_wm_)[] \
            __attribute__((section(".diarna_w"), used)) = "" __VA_ARGS__
    #define WATERMARK_W(...) \
        static volatile const wchar_t _DIARNA_UNIQ(_diarna_wwm_)[] \
            __attribute__((section(".diarna_ww"), used)) = L"" __VA_ARGS__
#endif

#ifdef OBF_MSVC
    #pragma section(".diarna_w", read)
    #pragma section(".diarna_ww", read)
#endif

#define HIDE_PTR(ptr) obf::hide_ptr_fwd(ptr)
#define CALL(ptr, ...) HIDE_PTR(ptr)(__VA_ARGS__)

#define CALL_EXPORT(lib, name, type, ret) \
    do { \
        reinterpret_cast<type>(HIDE_PTR(reinterpret_cast<FARPROC(*)()>( \
            reinterpret_cast<FARPROC>(GetProcAddress)( \
                GetModuleHandleA(OBF(lib)), OBF(name)))))(); \
        (void)(ret); \
    } while(0)

#ifdef OBF_MSVC
    #define FAKE_SIG_IMPL(name, sec, ...) \
        __pragma(section(sec, read)) \
        __declspec(allocate(sec)) \
        static volatile const unsigned char _DIARNA_CAT(__fs_, name)[] = { __VA_ARGS__ }
#else
    #define FAKE_SIG_IMPL(name, sec, ...) \
        static volatile const unsigned char _DIARNA_CAT(__fs_, name)[] \
            __attribute__((section(sec), used)) = { __VA_ARGS__ }
#endif

#define FAKE_SIG(name, sec, ...) FAKE_SIG_IMPL(name, sec, __VA_ARGS__)

#if FAKE_SIGNATURES
    FAKE_SIG(denuvo_0,    ".denuvo",   0x64, 0x65, 0x6E, 0x75, 0x76, 0x6F);
    FAKE_SIG(denuvo_1,    ".denuvo",   0x44, 0x45, 0x4E, 0x55, 0x56, 0x4F);
    FAKE_SIG(themida_0,   ".themida",  0x54, 0x68, 0x65, 0x6D, 0x69, 0x64, 0x61, 0x00);
    FAKE_SIG(themida_1,   ".tmd",      0x54, 0x4D, 0x44, 0x00);
    FAKE_SIG(themida_2,   ".winlice",  0x57, 0x69, 0x6E, 0x4C, 0x69, 0x63, 0x65);
    FAKE_SIG(vmp_0,       ".vmp0",     0x56, 0x4D, 0x50, 0x52, 0x4F, 0x54, 0x45, 0x43, 0x54);
    FAKE_SIG(vmp_1,       ".vmp1",     0x76, 0x6D, 0x70, 0x00);
    FAKE_SIG(vmp_2,       ".vmp2",     0x56, 0x4D, 0x50, 0x00);
    FAKE_SIG(vmp_3,       ".vmpx",     0x00, 0x00, 0x00, 0x00);
    FAKE_SIG(enigma_0,    ".enigma1",  0x45, 0x6E, 0x69, 0x67, 0x6D, 0x61);
    FAKE_SIG(enigma_1,    ".enigma2",  0x45, 0x4E, 0x49, 0x47, 0x4D, 0x41);
    FAKE_SIG(asprotect_0, ".aspack",   0x41, 0x53, 0x50, 0x61, 0x63, 0x6B);
    FAKE_SIG(asprotect_1, ".adata",    0x41, 0x53, 0x50, 0x52, 0x4F, 0x54);
    FAKE_SIG(obsidium_0,  ".obs",      0x4F, 0x42, 0x53, 0x49, 0x44, 0x49, 0x55, 0x4D);
    FAKE_SIG(obsidium_1,  ".obscur",   0x6F, 0x62, 0x73, 0x63, 0x75, 0x72);
    FAKE_SIG(safedisc_0,  ".sdata",    0x53, 0x61, 0x66, 0x65, 0x44, 0x69, 0x73, 0x63);
    FAKE_SIG(securom_0,   ".securom",  0x53, 0x65, 0x63, 0x75, 0x52, 0x4F, 0x4D);
    FAKE_SIG(exeshield_0, ".exeshld",  0x45, 0x78, 0x65, 0x53, 0x68, 0x69, 0x65, 0x6C, 0x64);
    FAKE_SIG(yoda_0,      ".yP",       0x59, 0x6F, 0x64, 0x61);
    FAKE_SIG(yoda_1,      ".y0da",     0x59, 0x4F, 0x44, 0x41);
    FAKE_SIG(armadillo_0, ".arm",      0x41, 0x72, 0x6D, 0x61, 0x64, 0x69, 0x6C, 0x6C, 0x6F);
    FAKE_SIG(mpress_0,    ".mpress",   0x4D, 0x50, 0x52, 0x45, 0x53, 0x53);
    FAKE_SIG(mpress_1,    ".mpr",      0x6D, 0x70, 0x72, 0x65, 0x73, 0x73);
    FAKE_SIG(upx_0,       ".upx0",     0x55, 0x50, 0x58, 0x30);
    FAKE_SIG(upx_1,       ".upx1",     0x55, 0x50, 0x58, 0x31);
    FAKE_SIG(pelock_0,    ".pelock",   0x50, 0x45, 0x4C, 0x6F, 0x63, 0x6B);
    FAKE_SIG(vbox_0,      ".vbox",     0x56, 0x42, 0x6F, 0x78);
    FAKE_SIG(winlicense_0,".winlice", 0x57, 0x69, 0x6E, 0x4C, 0x69, 0x63, 0x65, 0x6E, 0x73, 0x65);
    FAKE_SIG(codeguard_0, ".guard",   0x43, 0x6F, 0x64, 0x65, 0x47, 0x75, 0x61, 0x72, 0x64);
    FAKE_SIG(svkp_0,      ".svkp",     0x53, 0x56, 0x4B, 0x50);
    FAKE_SIG(execryptor_0,".ecode",    0x45, 0x78, 0x65, 0x43, 0x72, 0x79, 0x70, 0x74, 0x6F, 0x72);
    FAKE_SIG(execryptor_1,".rsrc",     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
    FAKE_SIG(ns_pack_0,   ".nsp0",     0x4E, 0x53, 0x50, 0x41, 0x43, 0x4B);
    FAKE_SIG(ns_pack_1,   ".nsp1",     0x6E, 0x73, 0x70, 0x61, 0x63, 0x6B);
    FAKE_SIG(pecompact_0, ".pec",      0x50, 0x45, 0x43, 0x6F, 0x6D, 0x70, 0x61, 0x63, 0x74);
    FAKE_SIG(pecompact_1, ".pec1",     0x70, 0x65, 0x63, 0x6F, 0x6D, 0x70, 0x61, 0x63, 0x74);
    FAKE_SIG(pecompact_2, ".pec2",     0x50, 0x45, 0x43, 0x4F, 0x4D, 0x50, 0x41, 0x43, 0x54);
    FAKE_SIG(wl_0,        ".wl",       0x57, 0x6C, 0x53, 0x65, 0x63, 0x75, 0x72, 0x65);
    FAKE_SIG(slm_0,       ".slm",      0x53, 0x4C, 0x4D, 0x50, 0x72, 0x6F, 0x74, 0x65, 0x63, 0x74);
    FAKE_SIG(acprotect_0, ".acp",      0x41, 0x43, 0x50, 0x72, 0x6F, 0x74, 0x65, 0x63, 0x74);
    FAKE_SIG(acprotect_1, ".acp0",     0x61, 0x63, 0x70, 0x72, 0x6F, 0x74, 0x65, 0x63, 0x74);
    FAKE_SIG(ttprotect_0, ".tt",       0x54, 0x54, 0x50, 0x72, 0x6F, 0x74, 0x65, 0x63, 0x74);
    FAKE_SIG(molebox_0,   ".molebox",  0x4D, 0x6F, 0x6C, 0x65, 0x42, 0x6F, 0x78);
    FAKE_SIG(ns_vmp_0,    ".nvmp",     0x4E, 0x6F, 0x56, 0x4D, 0x50, 0x72, 0x6F, 0x74);
    FAKE_SIG(orient_0,    ".oriented", 0x4F, 0x72, 0x69, 0x65, 0x6E, 0x74, 0x65, 0x64);
    FAKE_SIG(zprotect_0,  ".zprotect", 0x5A, 0x50, 0x72, 0x6F, 0x74, 0x65, 0x63, 0x74);
    FAKE_SIG(spices_0,    ".spices",   0x53, 0x70, 0x69, 0x63, 0x65, 0x73);
    FAKE_SIG(hex_0,       ".hexe",     0x48, 0x65, 0x78, 0x45, 0x6E, 0x63, 0x72, 0x79, 0x70, 0x74);
#endif

#define HIDE_PTR_MEMBER(obj, method) \
    ([](auto&& _o) -> decltype(&decltype(_o)::method) { \
        volatile decltype(&decltype(_o)::method) _tmp = &decltype(_o)::method; \
        return _tmp; \
    }(obj))

#if CFLOW_BRANCHING
    #if defined(OBF_MINGW) || defined(OBF_GCC)
        #define OBF_CFLOW_IF       if (_TRUE)
        #define OBF_CFLOW_ELIF     else if (_TRUE)
        #define OBF_CFLOW_FOR      for (volatile int __cf_i = 0; \
                                        _TRUE && __cf_i < 1; \
                                        __cf_i++)
        #define OBF_CFLOW_WHILE    while (_TRUE)
        #define OBF_CFLOW_DO       do {
        #define OBF_CFLOW_DO_WHILE } while (_FALSE)
        #define OBF_CFLOW_SWITCH   switch (obf::int_proxy_rot())
        #define OBF_CFLOW_CASE     case 0: if (_TRUE)
        #define OBF_CFLOW_DEFAULT  default: if (_FALSE)
    #else
        #define OBF_CFLOW_IF       if (_TRUE)
        #define OBF_CFLOW_ELIF     else if (_TRUE)
        #define OBF_CFLOW_FOR      for (volatile int __cf_i = 0; \
                                        _TRUE && __cf_i < 1; \
                                        __cf_i++)
        #define OBF_CFLOW_WHILE    while (_TRUE)
        #define OBF_CFLOW_DO       do {
        #define OBF_CFLOW_DO_WHILE } while (_FALSE)
        #define OBF_CFLOW_SWITCH   switch (obf::int_proxy_rot())
        #define OBF_CFLOW_CASE     case 0: if (_TRUE)
        #define OBF_CFLOW_DEFAULT  default: if (_FALSE)
    #endif
#endif

#pragma endregion

#endif // OBFUSHEADER_H
