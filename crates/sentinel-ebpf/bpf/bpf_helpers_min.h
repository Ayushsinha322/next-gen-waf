/* Minimal, self-contained BPF helper/map macros for clang -target bpf.
 *
 * Vendored so the XDP program compiles without libbpf-dev installed. Contains
 * only what sentinel_xdp.bpf.c needs: the SEC() section attribute, the BTF map
 * definition macros (__uint / __type), a couple of helper-function
 * declarations (called by their stable uapi helper IDs), and bpf_htons().
 */
#ifndef SENTINEL_BPF_HELPERS_MIN_H
#define SENTINEL_BPF_HELPERS_MIN_H

#include <linux/bpf.h>

/* Place a symbol in an ELF section (program / maps / license). */
#define SEC(NAME) __attribute__((section(NAME), used))

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

/* BTF map-definition field macros (the libbpf convention: the field is an
 * anonymous pointer/array whose type encodes the attribute; BTF records it). */
#define __uint(name, val) int(*name)[val]
#define __type(name, val) typeof(val) *name

/* BPF helper functions, called via their stable uapi helper IDs. */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value,
                                   __u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;

/* Host<->network byte order. The BPF target is little-endian, so htons is a
 * 16-bit byte swap. */
#define bpf_htons(x) __builtin_bswap16(x)

#endif /* SENTINEL_BPF_HELPERS_MIN_H */
