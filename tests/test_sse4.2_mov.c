#include <stdio.h>
#include <stdint.h>
#include <string.h>

int main() {
    uint64_t src[2] = {0x1122334455667788ULL, 0x99aabbccddeeff00ULL};
    uint64_t dst[2];

    // movdqa: move aligned 128-bit data
    memset(dst, 0, sizeof(dst));
    __asm__ volatile (
        "movdqa %1, %%xmm0\n\t"
        "movdqa %%xmm0, %0\n\t"
        : "=m" (dst)
        : "m" (src)
        : "xmm0"
    );
    int pass = (dst[0] == src[0] && dst[1] == src[1]);
    printf("movdqa: %s\n", pass ? "PASS" : "FAIL");

    // movdqu: move unaligned 128-bit data
    memset(dst, 0, sizeof(dst));
    __asm__ volatile (
        "movdqu %1, %%xmm0\n\t"
        "movdqu %%xmm0, %0\n\t"
        : "=m" (dst)
        : "m" (src)
        : "xmm0"
    );
    pass = (dst[0] == src[0] && dst[1] == src[1]);
    printf("movdqu: %s\n", pass ? "PASS" : "FAIL");

    // movntdq: non-temporal store from XMM
    memset(dst, 0, sizeof(dst));
    __asm__ volatile (
        "movdqa %1, %%xmm0\n\t"
        "movntdq %%xmm0, %0\n\t"
        : "=m" (dst)
        : "m" (src)
        : "xmm0"
    );
    pass = (dst[0] == src[0] && dst[1] == src[1]);
    printf("movntdq: %s\n", pass ? "PASS" : "FAIL");

    return 0;
}