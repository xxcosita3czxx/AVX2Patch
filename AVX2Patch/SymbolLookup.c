#include <libkern/libkern.h>
#include <mach/mach_types.h>

extern void _vm_kernel_unslide_or_perm_external(void *ptr, long *out_base);
extern void DBG_LOG(const char *fmt, ...);

int* FindSegment64(long machHeader, const char *segment_name) {
    int *lcPtr;
    unsigned long loadCmdSize;

    lcPtr = (int *)(machHeader + 0x20);         
    loadCmdSize = *(uint *)(machHeader + 0x14);

    while ((long)lcPtr < machHeader + loadCmdSize) {
        if (*lcPtr == 0x19) { // LC_SEGMENT_64
            if (strcmp((char *)(lcPtr + 2), segment_name) == 0) {
                return lcPtr;
            }
        }
        lcPtr = (int *)((char*)lcPtr + *(uint *)(lcPtr + 1));
    }

    return NULL;
}

long SymbolLookup(const char *symbol_name) {
    void *printf_ptr = &printf; // just to pass a kernel pointer
    long kernel_base = 0;
    _vm_kernel_unslide_or_perm_external(printf_ptr, &kernel_base);

    int *mh = (int *)(printf_ptr + (-0x7fffe00000 - kernel_base)); // original base calc
    if (*mh != -0x1120531) {
        return 0;
    }

    if (*(int *)0x00003028 > 0x13) { // macOS version check
        int *prelink = FindSegment64((long)mh, "__PRELINK_TEXT");
        if (prelink) {
            mh = *(int **)(prelink + 0x18);
        }
    }

    int *linkedit = FindSegment64((long)mh, "__LINKEDIT");
    if (!linkedit) {
        DBG_LOG("SymbolLookup: __LINKEDIT not found\n");
        return 0;
    }

    int *lc = mh + 8;
    long kernel_end = (long)mh + (uint)mh[5];

    for (; (long)lc < kernel_end; lc = (int *)((char*)lc + (uint)lc[1])) {
        if (*lc == 2 && lc[3] != 0) { // LC_SYMTAB
            long slide = *(long *)(linkedit + 0x18) - *(long *)(linkedit + 0x28);
            uint strOffset = lc[4];
            uint *symtab = (uint *)((unsigned long)lc[2] + slide);
            for (uint i = 0; i < (uint)lc[3]; i++) {
                char *name = (char *)((unsigned long)symtab[0] + strOffset + slide);
                if (strcmp(name, symbol_name) == 0) {
                    return *(long *)(symtab + 2);
                }
                symtab += 4;
            }
            DBG_LOG("SymbolLookup: Symbol '%s' not found\n", symbol_name);
            return 0;
        }
    }

    DBG_LOG("SymbolLookup: LC_SYMTAB not found\n");
    return 0;
}