#include <libkern/libkern.h>
#include <mach/mach_types.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

extern void _vm_kernel_unslide_or_perm_external(void *ptr, long *out_base);
extern void DBG_LOG(const char *fmt, ...);

static struct segment_command_64 *
FindSegment64(struct mach_header_64 *mh, const char *name)
{
    struct load_command *lc =
        (struct load_command *)((char *)mh + sizeof(struct mach_header_64));

    for (uint32_t i = 0; i < mh->ncmds; i++) {

        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg =
                (struct segment_command_64 *)lc;

            if (strcmp(seg->segname, name) == 0)
                return seg;
        }

        lc = (struct load_command *)((char *)lc + lc->cmdsize);
    }

    return NULL;
}

long SymbolLookup(const char *symbol_name)
{
    void *printf_ptr = &printf;
    long unslid_base = 0;

    _vm_kernel_unslide_or_perm_external(printf_ptr, &unslid_base);

    /* reconstruct runtime mach header */
    struct mach_header_64 *mh =
        (struct mach_header_64 *)((char *)printf_ptr -
        ((char *)printf_ptr - (char *)unslid_base));

    if (mh->magic != MH_MAGIC_64)
        return 0;

    struct segment_command_64 *linkedit =
        FindSegment64(mh, "__LINKEDIT");

    if (!linkedit) {
        DBG_LOG("SymbolLookup: __LINKEDIT not found\n");
        return 0;
    }

    struct load_command *lc =
        (struct load_command *)((char *)mh +
        sizeof(struct mach_header_64));

    struct symtab_command *symtab = NULL;

    for (uint32_t i = 0; i < mh->ncmds; i++) {

        if (lc->cmd == LC_SYMTAB) {
            symtab = (struct symtab_command *)lc;
            break;
        }

        lc = (struct load_command *)((char *)lc + lc->cmdsize);
    }

    if (!symtab) {
        DBG_LOG("SymbolLookup: LC_SYMTAB not found\n");
        return 0;
    }

    long slide = (long)mh - unslid_base;

    struct nlist_64 *symbols =
        (struct nlist_64 *)(symtab->symoff + slide);

    char *strtab =
        (char *)(symtab->stroff + slide);

    for (uint32_t i = 0; i < symtab->nsyms; i++) {

        char *name = strtab + symbols[i].n_un.n_strx;

        if (strcmp(name, symbol_name) == 0)
            return symbols[i].n_value + slide;
    }

    DBG_LOG("SymbolLookup: Symbol '%s' not found\n", symbol_name);
    return 0;
}