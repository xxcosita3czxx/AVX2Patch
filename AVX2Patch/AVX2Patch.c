#include <libkern/libkern.h>
#include <i386/trap.h>
#include <mach/mach_types.h>
#include <os/log.h>
#include <stdint.h>

#define UD_VECTOR 6

typedef struct {
    struct {
        uint64_t rdi;
        uint64_t rsi;
        uint64_t rbp;
        uint64_t rsp;
        uint64_t rbx;
        uint64_t rdx;
        uint64_t rcx;
        uint64_t rax;
        uint64_t r8;
        uint64_t r9;
        uint64_t r10;
        uint64_t r11;
        uint64_t r12;
        uint64_t r13;
        uint64_t r14;
        uint64_t r15;
        uint64_t rip;
        uint64_t rflags;
        uint16_t cs;
        uint16_t fs;
        uint16_t gs;
    } isf;
} x86_saved_state_t;

typedef void (*trap_handler_t)(x86_saved_state_t *);

#ifdef DEBUG
#include <IOKit/IOLib.h>
#define DBG_LOG(fmt, ...) IOLog(fmt, ##__VA_ARGS__)
#else
#define DBG_LOG(fmt, ...) do {} while(0)
#endif

static bool has_sse = false;
static bool has_sse2 = false;
static bool has_sse3 = false;
static bool has_ssse3 = false;
static bool has_sse41 = false;
static bool has_sse42 = false;
static bool has_avx = false;
static bool has_fma = false;
static bool has_avx2 = false;

static trap_handler_t *idt_table = NULL;
static trap_handler_t original_ud = NULL;

extern long SymbolLookup(const char *symbol_name);


static void check_instruction_sets(void)
{
    DBG_LOG("[AVX2Patch] Entering check_instruction_sets()\n");
    unsigned int eax, ebx, ecx, edx;

    // CPUID leaf 1: basic features
    eax = 1;
    __asm__ volatile (
        "cpuid"
        : "+a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx)
        :
        :
    );
    has_sse   = (edx & (1 << 25)) != 0;
    has_sse2  = (edx & (1 << 26)) != 0;
    has_sse3  = (ecx & (1 << 0))  != 0;
    has_ssse3 = (ecx & (1 << 9))  != 0;
    has_sse41 = (ecx & (1 << 19)) != 0;
    has_sse42 = (ecx & (1 << 20)) != 0;
    has_avx   = (ecx & (1 << 28)) != 0;
    has_fma   = (ecx & (1 << 12)) != 0;

    DBG_LOG("[AVX2Patch] After CPUID leaf 1\n");

    // CPUID leaf 7, subleaf 0: extended features (AVX2)
    eax = 7; ecx = 0;
    __asm__ volatile (
        "cpuid"
        : "+a" (eax), "=b" (ebx), "+c" (ecx), "=d" (edx)
        :
        :
    );
    has_avx2 = (ebx & (1 << 5)) != 0;

    DBG_LOG("[AVX2Patch] After CPUID leaf 7\n");

    DBG_LOG("[AVX2Patch] SSE: %s\n", has_sse ? "Supported" : "Not Supported");
    DBG_LOG("[AVX2Patch] SSE2: %s\n", has_sse2 ? "Supported" : "Not Supported");
    DBG_LOG("[AVX2Patch] SSE3: %s\n", has_sse3 ? "Supported" : "Not Supported");
    DBG_LOG("[AVX2Patch] SSSE3: %s\n", has_ssse3 ? "Supported" : "Not Supported");
    DBG_LOG("[AVX2Patch] SSE4.1: %s\n", has_sse41 ? "Supported" : "Not Supported");
    DBG_LOG("[AVX2Patch] SSE4.2: %s\n", has_sse42 ? "Supported" : "Not Supported");
    DBG_LOG("[AVX2Patch] AVX: %s\n", has_avx ? "Supported" : "Not Supported");
    DBG_LOG("[AVX2Patch] FMA: %s\n", has_fma ? "Supported" : "Not Supported");
    DBG_LOG("[AVX2Patch] AVX2: %s\n", has_avx2 ? "Supported" : "Not Supported");
}


static void my_ud_handler(x86_saved_state_t *state)
{
    bool kernel_mode = ((state->isf.cs & 3) == 0);

    DBG_LOG("[AVX2Patch] #UD caught. Kernel mode: %d\n", kernel_mode);

    uint64_t rip = state->isf.rip;

    // TODO: decode instruction at RIP
    // TODO: emulate if needed
    // If emulated:
    //    state->isf.rip += instruction_length;
    //    return;

    // Fallback to original
    if (original_ud)
        original_ud(state);
}

kern_return_t AVX2Patch_start(kmod_info_t *ki, void *d)
{
    check_instruction_sets();

    idt_table = (trap_handler_t *)SymbolLookup("_idt64_hndl_table0");
    if (!idt_table) {
        DBG_LOG("[AVX2Patch] Failed to resolve _idt64_hndl_table0\n");
        return KERN_FAILURE;
    }

//    original_ud = idt_table[UD_VECTOR];
//
//    idt_table[UD_VECTOR] = my_ud_handler;

    DBG_LOG("[AVX2Patch] #UD vector hooked\n");

    return KERN_SUCCESS;
}

kern_return_t AVX2Patch_stop(kmod_info_t *ki, void *d)
{
//    if (idt_table && original_ud) {
//        idt_table[UD_VECTOR] = original_ud;
    DBG_LOG("[AVX2Patch] #UD vector restored\n");
//    }

    return KERN_SUCCESS;
}