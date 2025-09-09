#include <mach/mach_types.h>
 
extern kern_return_t _start(kmod_info_t *ki, void *data);
extern kern_return_t _stop(kmod_info_t *ki, void *data);
__private_extern__ kern_return_t AVX2Patch_start(kmod_info_t *ki, void *data);
__private_extern__ kern_return_t AVX2Patch_stop(kmod_info_t *ki, void *data);
 
__attribute__((visibility("default"))) KMOD_EXPLICIT_DECL(com.cosita3cz.AVX2Patch, "1.0.0d1", _start, _stop)
__private_extern__ kmod_start_func_t *_realmain = AVX2Patch_start;
__private_extern__ kmod_stop_func_t *_antimain = AVX2Patch_stop;
__private_extern__ int _kext_apple_cc = __APPLE_CC__ ;
