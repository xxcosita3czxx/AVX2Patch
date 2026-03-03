//
//  AVX2Patch.c
//  AVX2Patch
//
//  Created by cosita3cz on 06.08.2025.
//

#include <mach/mach_types.h>
#include <i386/trap.h>
#include <os/log.h>
#include <libkern/libkern.h>
#include <stdint.h>
#include <string.h>

#define UD_VECTOR 6

#ifdef !DEBUG
#define DBG_LOG(fmt, ...) kprintf(fmt, ##__VA_ARGS__)
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

static void check_instruction_sets(void)
{
    os_log(OS_LOG_DEFAULT,"[AVX2Patch] Entering check_instruction_sets()\n");
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

kern_return_t AVX2Patch_start(kmod_info_t *ki, void *d)
{
    check_instruction_sets();
    os_log(OS_LOG_DEFAULT,"[AVX2Patch] Starting AVX2Patch module.\n");
    return KERN_SUCCESS;
}

kern_return_t AVX2Patch_stop(kmod_info_t *ki, void *d)
{
    os_log(OS_LOG_DEFAULT,"[AVX2Patch] Stopping AVX2Patch module.\n");
    return KERN_SUCCESS;
}
