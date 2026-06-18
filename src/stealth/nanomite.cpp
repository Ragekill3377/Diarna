#include <diarna/stealth/syscalls.hpp>
#include <diarna/compiler_port.hpp>
#include <diarna/stealth/syscalls.hpp>
#include <diarna/stealth/nanomite.hpp>
#include <diarna/stealth/syscalls.hpp>
#include <xmmintrin.h>
#include <diarna/stealth/syscalls.hpp>
#include <algorithm>
#include <diarna/stealth/syscalls.hpp>
#include <cstring>

#ifdef DIARNA_MINGW
static void mingw_cpuid(int* cpu, unsigned leaf) {
    asm volatile("cpuid":"=a"(cpu[0]),"=b"(cpu[1]),"=c"(cpu[2]),"=d"(cpu[3]):"a"(leaf));
}
static void mingw_cpuidex(int* cpu, unsigned leaf, unsigned sub) {
    asm volatile("cpuid":"=a"(cpu[0]),"=b"(cpu[1]),"=c"(cpu[2]),"=d"(cpu[3]):"a"(leaf),"c"(sub));
}
#define DIARNA_CPUID(info,func) mingw_cpuid((int*)(info),(unsigned)(func))
#define DIARNA_CPUIDEX(info,func,sub) mingw_cpuidex((int*)(info),(unsigned)(func),(unsigned)(sub))
#endif

namespace diarna::stealth {

static uint64_t read_tsc() { return DIARNA_RDTSC(); }
static uint64_t read_tscp_core(uint32_t* aux) { return DIARNA_RDTSCP(aux); }

NanomiteEngine& NanomiteEngine::instance() { static NanomiteEngine e; return e; }
NanomiteEngine::NanomiteEngine() { veh_handle_ = nullptr; }
NanomiteEngine::~NanomiteEngine() { remove_traps(); }

bool NanomiteEngine::is_emulated() { return identify_emulator() != EmulatorType::None; }

void NanomiteEngine::install_traps() {
    if (traps_installed_) return;
    traps_installed_ = true;
}

void NanomiteEngine::remove_traps() { traps_installed_ = false; }

LONG WINAPI NanomiteEngine::emulation_veh(EXCEPTION_POINTERS* ex) { (void)ex; return EXCEPTION_CONTINUE_SEARCH; }

bool NanomiteEngine::install_rdtsc_nanomite() {
    uint32_t a1=0,a2=0,a3=0;
    uint64_t t1=read_tscp_core(&a1); DIARNA_PAUSE();
    uint64_t t2=read_tscp_core(&a2); DIARNA_PAUSE();
    uint64_t t3=read_tscp_core(&a3);
    if(t2<=t1||t3<=t2)return true;
    if(t2-t1>100000)return true;
    if(a1==a2&&a2==a3)return true;
    uint64_t s=DIARNA_RDTSC();DWORD aff=SetThreadAffinityMask(GetCurrentProcess(),1);
    uint64_t c0=DIARNA_RDTSC();SetThreadAffinityMask(GetCurrentProcess(),aff);
    uint64_t e=DIARNA_RDTSC();if(e-s>500000)return true;
    return false;
}

bool NanomiteEngine::install_cpuid_nanomite() {
    int cpu[4];
    DIARNA_CPUID(cpu,0x40000000);
    if(cpu[0]>0){char s[13]={};memcpy(s,&cpu[1],4);memcpy(s+4,&cpu[2],4);memcpy(s+8,&cpu[3],4);return true;}
    DIARNA_CPUID(cpu,1);if(cpu[2]&(1u<<31))return true;
    DIARNA_CPUID(cpu,0);int mb=cpu[0];
    DIARNA_CPUID(cpu,0x80000000);int me=cpu[0];
    if(mb<0x0D||me<0x80000008)return true;
    uint64_t t1=DIARNA_RDTSC();
    for(volatile int i=0;i<10;++i)DIARNA_CPUID(cpu,0);
    uint64_t t2=DIARNA_RDTSC();uint64_t avg=(t2-t1)/10;
    if(avg>20000||avg<30)return true;
    DIARNA_CPUIDEX(cpu,0x0D,0);if(cpu[0]==0||cpu[1]==0)return true;
    DIARNA_CPUID(cpu,0x80000002);uint32_t n1=cpu[0]^cpu[1]^cpu[2]^cpu[3];
    DIARNA_CPUID(cpu,0x80000003);uint32_t n2=cpu[0]^cpu[1]^cpu[2]^cpu[3];
    if(n1==0||n2==0)return true;
    return false;
}

bool NanomiteEngine::install_cache_nanomite() {
    volatile uint8_t* buf=(volatile uint8_t*)VirtualAlloc(nullptr,4096,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if(!buf)return false;buf[0]=0x41;DIARNA_CLFLUSH((void*)&buf[0]);DIARNA_MFENCE();
    int cpu[4];DIARNA_CPUID(cpu,0x80000006);uint32_t cl=cpu[2]&0xFF;VirtualFree((LPVOID)buf,0,MEM_RELEASE);
    return(cl!=64&&cl!=32&&cl!=128);
}

bool NanomiteEngine::install_fpu_nanomite() {
    uint16_t cw_orig=0,cw_new=0;
    asm volatile("fstcw %0":"=m"(cw_orig));cw_new=cw_orig|0x003F;
    asm volatile("fldcw %0"::"m"(cw_new));
    uint16_t cw_after=0;asm volatile("fstcw %0":"=m"(cw_after));
    asm volatile("fldcw %0"::"m"(cw_orig));
    if((cw_after&0x003F)!=0x003F)return true;
    uint8_t fe1[28]={},fe2[28]={};asm volatile("fstenv %0":"=m"(fe1));
    memcpy(fe2,fe1,28);asm volatile("fldenv %0"::"m"(fe2));
    if(memcmp(fe1,fe2,28)!=0)return true;
    return false;
}

bool NanomiteEngine::install_branch_prediction_trap() {
    volatile int c=0;for(volatile int i=0;i<10000;++i){if(i&1)c++;else c--;}
    if(c!=0)return true;
    void* tg[4]={&&l0,&&l1,&&l2,&&l3};uint64_t ts=DIARNA_RDTSC();
    for(int i=0;i<1000;++i){goto*tg[i&3];l0:c+=1;continue;l1:c+=2;continue;l2:c+=3;continue;l3:c+=4;continue;}
    uint64_t te=DIARNA_RDTSC();volatile uint64_t el=te-ts;
    return(el<1000||el>5000000);
}

bool NanomiteEngine::install_sidt_sgdt_trap() {
    uint64_t idtr_base=0, gdtr_base=0;
    DIARNA_SIDT(&idtr_base);DIARNA_SGDT(&gdtr_base);
    if(idtr_base<0xFFFF800000000000ULL)return true;
    uint16_t lt=DIARNA_SLDT(),tr=DIARNA_STR();
    if(lt==0&&tr==0)return true;
    return false;
}

bool NanomiteEngine::install_cache_coherency_trap() {
    HANDLE m=CreateFileMappingW(INVALID_HANDLE_VALUE,nullptr,PAGE_READWRITE,0,4096,nullptr);
    if(!m)return false;uint8_t*v1=(uint8_t*)MapViewOfFile(m,FILE_MAP_WRITE,0,0,4096);
    uint8_t*v2=(uint8_t*)MapViewOfFile(m,FILE_MAP_WRITE,0,0,4096);
    if(!v1||!v2){if(v1)UnmapViewOfFile(v1);CloseHandle(m);return false;}
    v1[0]=0xDE;v1[1]=0xAD;bool ok=(v2[0]==0xDE&&v2[1]==0xAD);
    UnmapViewOfFile(v1);UnmapViewOfFile(v2);CloseHandle(m);return !ok;
}

bool NanomiteEngine::install_memory_timing_trap() {
    const size_t N=256;uint8_t**p=(uint8_t**)calloc(N,sizeof(uint8_t*));
    if(!p)return false;for(size_t i=0;i<N;++i){p[i]=(uint8_t*)VirtualAlloc(nullptr,4096,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);if(!p[i]){for(size_t j=0;j<i&&p[j];++j)VirtualFree(p[j],0,MEM_RELEASE);free(p);return true;}}
    for(size_t i=0;i<N;++i)DIARNA_CLFLUSH(p[i]);DIARNA_MFENCE();
    uint64_t t1=DIARNA_RDTSC();volatile uint8_t s=0;for(size_t i=0;i<N;++i)s+=p[i][0];
    uint64_t t2=DIARNA_RDTSC();uint64_t pa=(t2-t1)/N;
    for(size_t i=0;i<N;++i)VirtualFree(p[i],0,MEM_RELEASE);free(p);
    return(pa<15||pa>2000);
}

static bool check_tsx_support() {
#ifdef DIARNA_MSVC
    int cpu[4];
    DIARNA_CPUID(cpu, 7);
    if (!(cpu[1] & (1u << 11))) return false;
    unsigned status = _xbegin();
    if (status == 0xFFFFFFFF) return false;
    if (status == 0) return true;
    _xend();
    uint64_t t1 = DIARNA_RDTSC();
    status = _xbegin();
    _xend();
    uint64_t t2 = DIARNA_RDTSC();
    return (t2 - t1 < 50);
#else
    return false;
#endif
}

NanomiteEngine::EmulatorType NanomiteEngine::identify_emulator() {
    auto r = full_emulator_scan();
    for (auto& x : r) if (x.confidence > 0.7) return x.detected;
    return EmulatorType::None;
}

std::vector<NanomiteEngine::EmulatorCheck> NanomiteEngine::full_emulator_scan() {
    std::lock_guard lock(check_mutex_);
    auto now = std::chrono::steady_clock::now();
    if (now - last_full_scan_ < std::chrono::seconds(30) && !cached_results_.empty()) return cached_results_;
    std::vector<EmulatorCheck> res;
    if (install_rdtsc_nanomite()) res.push_back({"RDTSCskew", EmulatorType::QEMU_Userspace, 0.7, ""});
    if (install_cpuid_nanomite()) res.push_back({"CPUIDvm", EmulatorType::UnknownEmulator, 0.85, ""});
    if (install_fpu_nanomite()) res.push_back({"FPUctrl", EmulatorType::QEMU_System, 0.6, ""});
    if (install_sidt_sgdt_trap()) res.push_back({"SIDTbad", EmulatorType::UnknownEmulator, 0.75, ""});
    if (install_cache_coherency_trap()) res.push_back({"CacheCoh", EmulatorType::QEMU_Userspace, 0.9, ""});
    if (install_memory_timing_trap()) res.push_back({"MemTiming", EmulatorType::Pin, 0.8, ""});
    if (check_tsx_support() && install_cache_nanomite()) res.push_back({"TSXemu", EmulatorType::DynamoRIO, 0.75, ""});
    cached_results_ = res; last_full_scan_ = now; return res;
}

bool NanomiteEngine::check_ldmxcsr_exceptions() {
    uint32_t mxcsr=_mm_getcsr();_mm_setcsr(mxcsr|0x8000);
    uint32_t m2=_mm_getcsr();_mm_setcsr(mxcsr);return(m2&0x8000)==0;
}

bool NanomiteEngine::install_sse_nanomite(){return false;}
bool NanomiteEngine::install_cr8_access_trap(){return false;}
bool NanomiteEngine::install_stack_pivot_trap(){return false;}

} // namespace diarna::stealth
