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

#define RAX int
#define RDI int
#define RSI int
#define RCX int
#define RDX int
#define RBX int
#define RBP int
#define R8 int
#define R9 int
#define R10 int
#define R11 int
#define R12 int
#define R13 int
#define R14 int
#define R15 int


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

// === Custom handler in inline assembly ===
static volatile int in_handler = 0;
static volatile uint64_t saved_rax, saved_rcx, saved_rdx, saved_rsi, saved_rdi;
static volatile uint64_t saved_rbx, saved_rbp, saved_r8, saved_r9, saved_r10;
static volatile uint64_t saved_r11, saved_r12, saved_r13, saved_r14, saved_r15;

__attribute__((naked)) void my_ud_handler(void) {
    __asm__ volatile(
        // Check guard to prevent reentry
        "movl in_handler(%rip), %eax\n\t"
        "testl %eax, %eax\n\t"
        "jnz 1f\n\t"
        "movl $1, in_handler(%rip)\n\t"
        

        // Save all general-purpose registers to variables
        "movq %%rax, saved_rax(%rip)\n\t"
        "movq %%rcx, saved_rcx(%rip)\n\t"
        "movq %%rdx, saved_rdx(%rip)\n\t"
        "movq %%rsi, saved_rsi(%rip)\n\t"
        "movq %%rdi, saved_rdi(%rip)\n\t"
        "movq %%rbx, saved_rbx(%rip)\n\t"
        "movq %%rbp, saved_rbp(%rip)\n\t"
        "movq %%r8, saved_r8(%rip)\n\t"
        "movq %%r9, saved_r9(%rip)\n\t"
        "movq %%r10, saved_r10(%rip)\n\t"
        "movq %%r11, saved_r11(%rip)\n\t"
        "movq %%r12, saved_r12(%rip)\n\t"
        "movq %%r13, saved_r13(%rip)\n\t"
        "movq %%r14, saved_r14(%rip)\n\t"
        "movq %%r15, saved_r15(%rip)\n\t"

        // Get RIP from interrupt frame (no registers pushed, so it's at offset 0)
        "movq 0(%rsp), %rdi\n\t"         // rdi = RIP
        "callq _log_instruction\n\t"
        
        // Skip 3 bytes (naive)
        "addq $3, 0(%rsp)\n\t"

        // Restore registers from variables
        "movq saved_r15(%rip), %%r15\n\t"
        "movq saved_r14(%rip), %%r14\n\t"
        "movq saved_r13(%rip), %%r13\n\t"
        "movq saved_r12(%rip), %%r12\n\t"
        "movq saved_r11(%rip), %%r11\n\t"
        "movq saved_r10(%rip), %%r10\n\t"
        "movq saved_r9(%rip), %%r9\n\t"
        "movq saved_r8(%rip), %%r8\n\t"
        "movq saved_rbp(%rip), %%rbp\n\t"
        "movq saved_rbx(%rip), %%rbx\n\t"
        "movq saved_rdi(%rip), %%rdi\n\t"
        "movq saved_rsi(%rip), %%rsi\n\t"
        "movq saved_rdx(%rip), %%rdx\n\t"
        "movq saved_rcx(%rip), %%rcx\n\t"
        "movq saved_rax(%rip), %%rax\n\t"

        // Instead of restoring, jump to original handler
        "movq original_ud_handler_addr(%rip), %rax\n\t"
        "jmp *%rax\n\t"

        // Clear guard (never reached, but for completeness)
        "movl $0, in_handler(%rip)\n\t"

        "iretq\n\t"
        "1: hlt\n\t" // If reentered, halt to avoid recursion
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
