//
//  AVX2Patch.c
//  AVX2Patch
//
//  Created by cosita3cz on 06.08.2025.
//

#include <mach/mach_types.h>
#include <os/log.h>
#include <libkern/libkern.h>
#include <stdint.h>
#include <string.h>

#define UD_VECTOR 6

// IDT Entry
typedef struct {
    uint16_t offset_low;
    uint16_t selector;
    uint8_t ist;
    uint8_t type_attr;
    uint16_t offset_mid;
    uint32_t offset_high;
    uint32_t zero;
} __attribute__((packed)) idt_entry_t;

typedef struct {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed)) idtr_t;

static idt_entry_t original_ud_entry;
static int ud_hooked = 0;
static uint64_t original_ud_handler_addr = 0;

// === Global Variable to Store RIP ===
static volatile uint64_t saved_rip = 0;

// === Called from ASM handler ===
void restore_ud_handler(void) {
    if (!ud_hooked) return;

    idtr_t idtr;
    __asm__ volatile("sidt %0" : "=m"(idtr));
    idt_entry_t* idt = (idt_entry_t*)idtr.base;
    idt[UD_VECTOR] = original_ud_entry;

    ud_hooked = 0;
    printf("[AVX2Patch] Restored original #UD handler\n");
}

// === Called from ASM handler ===
void log_instruction(uint8_t* rip) {
    printf("[AVX2Patch] Caught #UD at RIP = %p\n", rip);
    printf("[AVX2Patch] Bytes: %02x %02x %02x %02x %02x\n",
           rip[0], rip[1], rip[2], rip[3], rip[4]);
}

void _printlog(const char* msg) {
    os_log(OS_LOG_DEFAULT,"%s", msg);
}

__attribute__((naked)) void my_ud_handler(void) {
    __asm__ volatile(
        // Save RIP to a C variable
        "movq 0(%rsp), %rax\n\t" // Load RIP from the interrupt frame
        "movq %rax, saved_rip(%rip)\n\t" // Save RIP to the global variable

        // Log instruction and emulate if possible
        "movq saved_rip(%rip), %rdi\n\t" // Pass RIP to log_instruction
        "callq _log_instruction\n\t"

        // Jump to original handler
        "movq original_ud_handler_addr(%rip), %rax\n\t"
        "jmp *%rax\n\t"

        "iretq\n\t"
    );
}

// === Hook handler ===
void hook_ud_handler(void) {
    idtr_t idtr;
    __asm__ volatile("sidt %0" : "=m"(idtr));
    idt_entry_t* idt = (idt_entry_t*)idtr.base;

    original_ud_entry = idt[UD_VECTOR];

    // Save the original handler address
    original_ud_handler_addr =
        ((uint64_t)original_ud_entry.offset_high << 32) |
        ((uint64_t)original_ud_entry.offset_mid << 16) |
        (uint64_t)original_ud_entry.offset_low;

    uint64_t handler_addr = (uint64_t)&my_ud_handler;

    idt_entry_t new_entry = {
        .offset_low  = handler_addr & 0xFFFF,
        .selector    = 0x08,
        .ist         = 0,
        .type_attr   = 0x8E,
        .offset_mid  = (handler_addr >> 16) & 0xFFFF,
        .offset_high = (handler_addr >> 32) & 0xFFFFFFFF,
        .zero        = 0
    };

    idt[UD_VECTOR] = new_entry;
    ud_hooked = 1;

    os_log(OS_LOG_DEFAULT,"[AVX2Patch] Hooked #UD handler\n");
}

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

    os_log(OS_LOG_DEFAULT,"[AVX2Patch] After CPUID leaf 1\n");

    // CPUID leaf 7, subleaf 0: extended features (AVX2)
    eax = 7; ecx = 0;
    __asm__ volatile (
        "cpuid"
        : "+a" (eax), "=b" (ebx), "+c" (ecx), "=d" (edx)
        :
        :
    );
    has_avx2 = (ebx & (1 << 5)) != 0;

    os_log(OS_LOG_DEFAULT,"[AVX2Patch] After CPUID leaf 7\n");

    os_log(OS_LOG_DEFAULT,"[AVX2Patch] SSE: %s\n", has_sse ? "Supported" : "Not Supported");
    os_log(OS_LOG_DEFAULT,"[AVX2Patch] SSE2: %s\n", has_sse2 ? "Supported" : "Not Supported");
    os_log(OS_LOG_DEFAULT,"[AVX2Patch] SSE3: %s\n", has_sse3 ? "Supported" : "Not Supported");
    os_log(OS_LOG_DEFAULT,"[AVX2Patch] SSSE3: %s\n", has_ssse3 ? "Supported" : "Not Supported");
    os_log(OS_LOG_DEFAULT,"[AVX2Patch] SSE4.1: %s\n", has_sse41 ? "Supported" : "Not Supported");
    os_log(OS_LOG_DEFAULT,"[AVX2Patch] SSE4.2: %s\n", has_sse42 ? "Supported" : "Not Supported");
    os_log(OS_LOG_DEFAULT,"[AVX2Patch] AVX: %s\n", has_avx ? "Supported" : "Not Supported");
    os_log(OS_LOG_DEFAULT,"[AVX2Patch] FMA: %s\n", has_fma ? "Supported" : "Not Supported");
    os_log(OS_LOG_DEFAULT,"[AVX2Patch] AVX2: %s\n", has_avx2 ? "Supported" : "Not Supported");
}

kern_return_t AVX2Patch_start(kmod_info_t *ki, void *d)
{
    check_instruction_sets();
    hook_ud_handler();
    return KERN_SUCCESS;
}

kern_return_t AVX2Patch_stop(kmod_info_t *ki, void *d)
{
    os_log(OS_LOG_DEFAULT,"[AVX2Patch] Stopping AVX2Patch module.\n");
    // Restore the original #UD handler
    if (ud_hooked) {
        restore_ud_handler();
    }
    return KERN_SUCCESS;
}
