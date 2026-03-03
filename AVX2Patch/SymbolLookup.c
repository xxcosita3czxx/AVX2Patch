#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <libkern/libkern.h>
#include <string.h>
#include <stdint.h>

extern void _IOLog(const char *fmt, ...);

// Finds a segment by name in the mach header
static struct segment_command_64* FindSegment(struct mach_header_64 *hdr, const char *name) {
    struct load_command *cmd = (struct load_command *)(hdr + 1);

    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        if (cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)cmd;
            if (strncmp(seg->segname, name, 16) == 0)
                return seg;
        }
        cmd = (struct load_command *)((uint8_t *)cmd + cmd->cmdsize);
    }
    return NULL;
}

// Symbol lookup like MouSSE
long _SymbolLookup(const char *symbol_name, struct mach_header_64 *kernel_hdr) {
    if (!kernel_hdr || !symbol_name)
        return 0;

    // Find __LINKEDIT segment
    struct segment_command_64 *linkedit = FindSegment(kernel_hdr, "__LINKEDIT");
    if (!linkedit) {
        _IOLog("MouSSE: __LINKEDIT not found\n");
        return 0;
    }

    // Find __TEXT segment for base slide
    struct segment_command_64 *text_seg = FindSegment(kernel_hdr, "__TEXT");
    if (!text_seg) {
        _IOLog("MouSSE: __TEXT not found\n");
        return 0;
    }

    // LC_SYMTAB command
    struct load_command *cmd = (struct load_command *)(kernel_hdr + 1);
    struct symtab_command *symtab = NULL;
    for (uint32_t i = 0; i < kernel_hdr->ncmds; i++) {
        if (cmd->cmd == LC_SYMTAB) {
            symtab = (struct symtab_command *)cmd;
            break;
        }
        cmd = (struct load_command *)((uint8_t *)cmd + cmd->cmdsize);
    }
    if (!symtab) {
        _IOLog("MouSSE: LC_SYMTAB not found\n");
        return 0;
    }

    // Compute symbol and string tables
    uint8_t *linkedit_base = (uint8_t *)linkedit->vmaddr; // virtual address of __LINKEDIT
    struct nlist_64 *symtab_ptr = (struct nlist_64 *)(linkedit_base + (symtab->symoff - linkedit->fileoff));
    char *strtab_ptr = (char *)(linkedit_base + (symtab->stroff - linkedit->fileoff));

    // Walk the symbol table
    for (uint32_t i = 0; i < symtab->nsyms; i++) {
        const char *name = strtab_ptr + symtab_ptr[i].n_un.n_strx;
        if (strcmp(name, symbol_name) == 0)
            return (long)symtab_ptr[i].n_value; // return symbol address
    }

    _IOLog("MouSSE: Symbol '%s' not found\n", symbol_name);
    return 0;
}