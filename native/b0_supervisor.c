/* Retained S's atomic access and readonly observer mapping primitives.
 * No HDF, callbacks, executable discovery, fd ownership, allocator or policy. */
#include <stdatomic.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/mman.h>
void *qcl_b0_s_map_ro(int fd,size_t length) {
    void *p=mmap(NULL,length,PROT_READ,MAP_SHARED,fd,0);
    return p==MAP_FAILED ? NULL : p;
}
int qcl_b0_s_unmap(void *p,size_t length) { return munmap(p,length); }
int qcl_b0_s_atomic_qualified(void *p) {
    return p && ((uintptr_t)p % 8u == 0u) &&
        atomic_is_lock_free((_Atomic uint32_t *)p) &&
        atomic_is_lock_free((_Atomic uint64_t *)p);
}
uint32_t qcl_b0_s_load32(const void *p) {
    return atomic_load_explicit((const _Atomic uint32_t *)p,memory_order_acquire);
}
uint64_t qcl_b0_s_load64(const void *p) {
    return atomic_load_explicit((const _Atomic uint64_t *)p,memory_order_acquire);
}
void qcl_b0_s_store32(void *p,uint32_t value) {
    atomic_store_explicit((_Atomic uint32_t *)p,value,memory_order_release);
}
void qcl_b0_s_store64(void *p,uint64_t value) {
    atomic_store_explicit((_Atomic uint64_t *)p,value,memory_order_release);
}
void qcl_b0_s_acquire_fence(void) { atomic_thread_fence(memory_order_acquire); }
