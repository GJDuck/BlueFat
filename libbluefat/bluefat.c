/*
 *  ____  _            _____     _   
 * | __ )| |_   _  ___|  ___|_ _| |_ 
 * |  _ \| | | | |/ _ \ |_ / _` | __|
 * | |_) | | |_| |  __/  _| (_| | |_ 
 * |____/|_|\__,_|\___|_|  \__,_|\__|
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#ifndef SYS_getrandom
#define SYS_getrandom           318
#endif

#define BLUEFAT_PAGE_SIZE       4096

#define BLUEFAT_SIZE_BITS       24
#define BLUEFAT_ID_BITS         40

#define BLUEFAT_SIZE_MAX        ((1ull << 20) - 1)
#define BLUEFAT_SIZE_MASK       ((0x1ull << BLUEFAT_SIZE_BITS) - 1)

#define BLUEFAT_ID_MAX          ((1ull << BLUEFAT_ID_BITS) - 1)

#define BLUEFAT_PROTECT_MIN     0x6FFFF000
#define BLUEFAT_PROTECT_MAX     0x20000000000

#define BLUEFAT_CACHE_ADDR      (BLUEFAT_PROTECT_MIN + 2 * BLUEFAT_PAGE_SIZE)
#define BLUEFAT_CACHE           ((struct bluefat_entry_s *)BLUEFAT_CACHE_ADDR)
#define BLUEFAT_CACHE_SET_SIZE  1

#ifndef BLUEFAT_CACHE_SIZE
#define BLUEFAT_CACHE_SIZE      2097152
#endif

#define BLUEFAT_CSPRNG          ((struct bluefat_csprng_s *)BLUEFAT_PROTECT_MIN)

#define BLUEFAT_STRING(s)   BLUEFAT_STRING_2(s)
#define BLUEFAT_STRING_2(s) #s

#define BLUEFAT_ERROR_READ_UNDERFLOW            0
#define BLUEFAT_ERROR_READ_OVERFLOW             1
#define BLUEFAT_ERROR_READ_UAF                  2
#define BLUEFAT_ERROR_WRITE_UNDERFLOW           3
#define BLUEFAT_ERROR_WRITE_OVERFLOW            4
#define BLUEFAT_ERROR_WRITE_UAF                 5

/*
 * Define BLUEFAT_NO_CACHE to disable the cache.
 */
#ifdef BLUEFAT_NO_CACHE
#undef BLUEFAT_CACHE_SIZE
#undef BLUEFAT_CACHE_SET_SIZE
#define BLUEFAT_CACHE_SET_SIZE      0
#define BLUEFAT_CACHE_SIZE          \
    (BLUEFAT_PAGE_SIZE / sizeof(struct bluefat_entry_s))
#endif

static bool bluefat_inited = false;

/*
 * CSRNG state.
 */
struct bluefat_csprng_s
{
    uint64_t state[4];                          // Current state
    uint64_t key[4];                            // Calculated keys
    uint64_t counter:BLUEFAT_ID_BITS;           // Object ID counter
    uint8_t k[30];                              // Object ID key
    size_t map_size;                            // Map size
};

/*
 * Cache/mapping entry.
 */
struct bluefat_entry_s
{
    union
    {
        struct
        {
            uint64_t zero:BLUEFAT_SIZE_BITS;    // Object zero (obfuscated)
            uint64_t id:BLUEFAT_ID_BITS;        // Object ID (obfuscated)
        };
        uintptr_t lb;                           // Object lower bound
												// (obfuscated)
    };
    uint64_t base:44;                           // Object base pointer
    uint64_t size:20;                           // Object size
};

static inline uintptr_t bluefat_get_base(const struct bluefat_entry_s *entry)
{
    return (entry->base << 4);
}
static inline void bluefat_set_base(struct bluefat_entry_s *entry,
    uintptr_t base)
{
    entry->base = (base >> 4);
}

static size_t bluefat_cache_hit       = 0;
static size_t bluefat_cache_miss      = 0;
static size_t bluefat_write_uaf       = 0;
static size_t bluefat_read_uaf        = 0;
static size_t bluefat_write_underflow = 0;
static size_t bluefat_read_underflow  = 0;
static size_t bluefat_write_overflow  = 0;
static size_t bluefat_read_overflow   = 0;
static size_t bluefat_num_objects     = 0;
static size_t bluefat_max_objects     = 0;
static size_t bluefat_num_bytes       = 0;
static size_t bluefat_max_bytes       = 0;

#define BLUE                "\33[36m"
#define OFF                 "\33[0m"
#define bluefat_error(msg, ...)                                             \
    do {                                                                    \
        fprintf(stderr, BLUE "error" OFF ": " msg "\n", ##__VA_ARGS__);     \
        exit(EXIT_FAILURE);                                                 \
    } while (false)
#if 0
#define BLUEFAT_DEBUG(msg, ...)                                          \
    fprintf(stderr, BLUE "DEBUG" OFF ": " msg "\n", ##__VA_ARGS__);
#else
#define BLUEFAT_DEBUG(msg, ...)     /* NOP */
#endif

/*************************************************************************/
#ifdef BLUEFAT_MAP_STDCXX

/*
 * If BLUEFAT_MAP_STDCXX is defined, use std::map to implement the mapping.
 * This is slower & uses more memory, but the implementation is simpler.
 * We could also use std::unordered_map, but PIN does not support C++11.
 * This implementation does NOT protect the map data, so is less secure.
 */

#include <map>

typedef std::map<uint64_t, bluefat_entry_s> BlueFatMap;
static BlueFatMap BLUEFAT_MAP;

/*
 * Initilize the mapping.
 */
static void bluefat_map_init(void)
{
    return;
}

/*
 * Resize of the mapping.
 */
static void bluefat_map_resize(void)
{
    return;
}

/*
 * Look up an entry from the mapping.
 */
static ssize_t bluefat_map_lookup(uint64_t id)
{
	BlueFatMap::iterator i = BLUEFAT_MAP.find(id);
    return (i != BLUEFAT_MAP.end()? (ssize_t)id: -1);
}

/*
 * Find free entry suitable for id.
 */
static ssize_t bluefat_map_alloc(uint64_t id)
{
    bluefat_entry_s empty = {0};
    BLUEFAT_MAP.insert(std::make_pair(id, empty));
    return (ssize_t)id;
}

/*************************************************************************/
#else

/*
 * The default hash table implementation of the mapping.
 */

#define BLUEFAT_MAX_PROBE   32

#define BLUEFAT_MAP_ADDR                                                \
    (BLUEFAT_CACHE_ADDR +                                               \
        BLUEFAT_CACHE_SIZE * sizeof(struct bluefat_entry_s) +           \
        BLUEFAT_PAGE_SIZE)
#define BLUEFAT_MAP         ((struct bluefat_entry_s *)BLUEFAT_MAP_ADDR)
#define BLUEFAT_MAP_SIZE    (BLUEFAT_CSPRNG->map_size)

/*
 * Initilize the mapping.
 */
static void bluefat_map_init(void)
{
    BLUEFAT_MAP_SIZE = 4096;
    size_t size = BLUEFAT_MAP_SIZE * sizeof(struct bluefat_entry_s);
    void *ptr = mmap(BLUEFAT_MAP, size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr != (void *)BLUEFAT_MAP)
       bluefat_error("failed to map %zu bytes for mapping: %s", size,
            strerror(errno));
}

/*
 * Doubles the size of the mapping.
 */
static void bluefat_map_resize(void)
{
    size_t old_size = BLUEFAT_MAP_SIZE * sizeof(struct bluefat_entry_s);
    // Cannot use mremap() b/c of some PIN issue...
    void *ptr = (void *)(BLUEFAT_MAP_ADDR + old_size);
    void *res = mmap(ptr, old_size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (res != ptr)
        bluefat_error("failed to map %zu bytes: %s", old_size, strerror(errno));
    size_t mask = 2 * BLUEFAT_MAP_SIZE - 1;
    for (size_t i = 0; i < BLUEFAT_MAP_SIZE; i++)
    {
        if (BLUEFAT_MAP[i].id == 0x0)
            continue;
        struct bluefat_entry_s entry = BLUEFAT_MAP[i];
        BLUEFAT_MAP[i].id = 0x0;
        for (size_t j = 0; ; j++)
        {
            size_t k = (entry.id + j) & mask;
            if (BLUEFAT_MAP[k].id == 0x0)
            {
                BLUEFAT_MAP[k] = entry;
                break;
            }
        }
    }
    BLUEFAT_MAP_SIZE *= 2;
}

/*
 * Look up an entry from the mapping.
 */
static ssize_t bluefat_map_lookup(uint64_t id)
{
    uint64_t mask = BLUEFAT_MAP_SIZE - 1;
    for (size_t i = 0; i < BLUEFAT_MAX_PROBE; i++)
    {
        uint64_t idx = (id + i) & mask;
        if (BLUEFAT_MAP[idx].id == id)
            return (ssize_t)idx;
    }
    return -1;
}

/*
 * Find free entry suitable for id.
 */
static ssize_t bluefat_map_alloc(uint64_t id)
{
    uint64_t mask = BLUEFAT_MAP_SIZE - 1;
    for (size_t i = 0; i < BLUEFAT_MAX_PROBE; i++)
    {
        uint64_t idx = (id + i) & mask;
        if (BLUEFAT_MAP[idx].id == 0x0)
            return (ssize_t)idx;
    }
    return -1;
}

/*************************************************************************/
#endif

/*
 * Functions provided by the PIN tool.
 */
static void *bluefat_memory_error(const void *loc, const void *ptr,
    size_t size, const struct bluefat_entry_s *entry, int code);
static void bluefat_lock(void);
static void bluefat_unlock(void);

/*************************************************************************/
#if (BLUEFAT_CACHE_SET_SIZE == 0)

/*
 * If BLUEFAT_CACHE_SET_SIZE==0, then the cache is effectively disabled.
 */

#define BLUEFAT_SET_ALIGN   /* None */

static inline int bluefat_cache_lookup(uint64_t id,
    struct bluefat_entry_s entry[BLUEFAT_CACHE_SET_SIZE])
{
    return -1;
}

static inline void bluefat_cache_insert(uint64_t id,
    const bluefat_entry_s entry[BLUEFAT_CACHE_SET_SIZE])
{
    return;
}

/*************************************************************************/
#elif (BLUEFAT_CACHE_SET_SIZE == 1)

#define BLUEFAT_SET_ALIGN   __attribute__((__aligned__(16)))

static inline int bluefat_cache_lookup(uint64_t id,
    struct bluefat_entry_s entry[BLUEFAT_CACHE_SET_SIZE])
{
    uintptr_t idx = id % (BLUEFAT_CACHE_SIZE / BLUEFAT_CACHE_SET_SIZE);
    idx *= sizeof(struct bluefat_entry_s);

    asm volatile (
        "movdqa " BLUEFAT_STRING(BLUEFAT_CACHE_ADDR) "(%0),%%xmm0\n"
        "movdqa %%xmm0,(%1)\n"
        : : "r"(idx), "r"(entry) : "memory", "xmm0");

    return (entry[0].id == id? 0: -1);
}

static inline void bluefat_cache_insert(uint64_t id,
    const bluefat_entry_s entry[BLUEFAT_CACHE_SET_SIZE])
{
    uintptr_t idx = id % (BLUEFAT_CACHE_SIZE / BLUEFAT_CACHE_SET_SIZE);
    idx *= sizeof(struct bluefat_entry_s);

    asm volatile (
        "movdqa (%1),%%xmm0\n"
        "movdqa %%xmm0," BLUEFAT_STRING(BLUEFAT_CACHE_ADDR) "(%0)"
        : : "r"(idx), "r"(entry) : "memory", "xmm0");
}

/*************************************************************************/
#elif (BLUEFAT_CACHE_SET_SIZE == 2)

#define BLUEFAT_SET_ALIGN   __attribute__((__aligned__(32)))

static inline int bluefat_cache_lookup(uint64_t id,
    struct bluefat_entry_s entry[BLUEFAT_CACHE_SET_SIZE])
{
    uintptr_t idx = id % (BLUEFAT_CACHE_SIZE / BLUEFAT_CACHE_SET_SIZE);
    idx *= sizeof(struct bluefat_entry_s) * BLUEFAT_CACHE_SET_SIZE;

    asm volatile (
        "vmovdqa " BLUEFAT_STRING(BLUEFAT_CACHE_ADDR) "(%0),%%ymm0\n"
        "vmovdqa %%ymm0,(%1)"
        : : "r"(idx), "r"(entry) : "memory", "ymm0");

    int i = -1;
    i = (entry[0].id == id? 0: i);
    i = (entry[1].id == id? 1: i);
    return i;
}

static inline void bluefat_cache_insert(uint64_t id,
    const struct bluefat_entry_s entry[BLUEFAT_CACHE_SET_SIZE])
{
    uintptr_t idx = id % (BLUEFAT_CACHE_SIZE / BLUEFAT_CACHE_SET_SIZE);
    idx *= sizeof(struct bluefat_entry_s) * BLUEFAT_CACHE_SET_SIZE;

    asm volatile (
        "vmovdqa (%1),%%ymm0\n"
        "vmovdqa %%ymm0," BLUEFAT_STRING(BLUEFAT_CACHE_ADDR) "(%0)"
        : : "r"(idx), "r"(entry) : "memory", "ymm0");
}

#else
#error "invalid value for BLUEFAT_CACHE_SET_SIZE"
#endif

static void bluefat_init(void)
{
    if (bluefat_inited)
        return;
    bluefat_inited = true;

    BLUEFAT_DEBUG("init()");

    size_t size = BLUEFAT_CACHE_SIZE * sizeof(struct bluefat_entry_s);
    void *ptr = mmap(BLUEFAT_CACHE, size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr != (void *)BLUEFAT_CACHE)
        bluefat_error("failed to map %zu bytes for cache: %s", size,
            strerror(errno));

    size = BLUEFAT_PAGE_SIZE;
    ptr = mmap(BLUEFAT_CSPRNG, size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr != (void *)BLUEFAT_CSPRNG)
        bluefat_error("failed to map %zu bytes for CSPRNG: %s", size,
            strerror(errno));

    const char *seed = getenv("BLUEFAT_SEED");
    if (seed != NULL)
    {
        size = strlen(seed);
        size = (size > sizeof(BLUEFAT_CSPRNG->state)?
            sizeof(BLUEFAT_CSPRNG->state): size);
        memcpy(BLUEFAT_CSPRNG->state, seed, size);
        size = strlen(seed);
        size = (size > sizeof(BLUEFAT_CSPRNG->k)?
            sizeof(BLUEFAT_CSPRNG->k): size);
        memcpy(BLUEFAT_CSPRNG->k, seed, size);
    }
    else
    {
        size = sizeof(*BLUEFAT_CSPRNG);
        if (syscall(SYS_getrandom, BLUEFAT_CSPRNG, size, 0) != (int)size)
            bluefat_error("failed to get %zu random bytes: %s", size,
                strerror(errno));
        BLUEFAT_CSPRNG->map_size = 0;
        BLUEFAT_CSPRNG->counter  = 0;
    }
    
    bluefat_map_init();
}

/*
 * Check if a pointer is encoded or not.
 */
static bool bluefat_is_encoded(const void *ptr)
{
    uintptr_t iptr = (uintptr_t)ptr;
    return ((iptr & 0xFFFF000000000000ull) != 0x0);
}

/*
 * Create a new "key" of random bits.  This will be the basis for the
 * obfuscated pointer.
 */
#include "sha256.c"
#include "skip40.c"
static uint64_t bluefat_create_key(void)
{
    // Sequential ID allocation:
    uint64_t id = 0x0;
    while (BLUEFAT_CSPRNG->counter < BLUEFAT_ID_MAX)
    {
        id = skip40(BLUEFAT_CSPRNG->k, BLUEFAT_CSPRNG->counter, true);
        BLUEFAT_CSPRNG->counter++;
        id <<= BLUEFAT_SIZE_BITS;
        if (bluefat_is_encoded((void *)id))
            break;
        id = 0x0;
    }

    // Random bits allocation:
    while (true)
    {
        for (int i = 0; i < 4; i++)
        {
            uint64_t key = BLUEFAT_CSPRNG->key[i];
            if (key == 0x0)
                continue;
            BLUEFAT_CSPRNG->key[i] = 0x0;
            if (id != 0x0)
            {
                key &= BLUEFAT_SIZE_MASK;
                key |= id;
            }
            if (bluefat_is_encoded((void *)key))
                return key;
        }
        for (int i = 0; i < 4; i++)
        {
            BLUEFAT_CSPRNG->state[i]++;
            if (BLUEFAT_CSPRNG->state[i] != 0)
                break;
        }

        SHA256_CTX *ctx = (SHA256_CTX *)(BLUEFAT_CSPRNG + 1);
        sha256_init(ctx);
        sha256_update(ctx, (const uint8_t *)BLUEFAT_CSPRNG->state,
            sizeof(BLUEFAT_CSPRNG->state));
        sha256_final(ctx, (uint8_t *)BLUEFAT_CSPRNG->key);
    }
}

static uint32_t bluefat_hash32(uint64_t x)
{
    x ^= x >> 30;
    x *= 0xbf58476d1ce4e5b9ull;
    x ^= x >> 27;
    x *= 0x94d049bb133111ebull;
    x ^= x >> 31;
    return (uint32_t)x;
}
static int bluefat_cache_evict(
    struct bluefat_entry_s entry[BLUEFAT_CACHE_SET_SIZE])
{
    if (BLUEFAT_CACHE_SET_SIZE <= 1)
        return 0;
    int i = 0;
    for (; i < BLUEFAT_CACHE_SET_SIZE; i++)
    {
        if (entry[i].id == 0x0)
            return i;
    }
    uint32_t sum = 0;
    for (; i < BLUEFAT_CACHE_SET_SIZE; i++)
        sum += bluefat_hash32(entry[i].id);
    return
        (int)(sum % (BLUEFAT_CACHE_SET_SIZE == 0? 1: BLUEFAT_CACHE_SET_SIZE));
}

/*
 * Given a pointer, return the corresponding bluefat_entry_s data.
 * The returned data is a copy stored in the entry[] parameter.
 * Return NULL if the pointer is invalid.
 */
static const struct bluefat_entry_s *bluefat_entry_lookup(const void *ptr,
    struct bluefat_entry_s entry[BLUEFAT_CACHE_SET_SIZE])
{
    if (!bluefat_is_encoded(ptr))
        return NULL;
    uintptr_t iptr = (uintptr_t)ptr;
    uint64_t id = iptr >> BLUEFAT_SIZE_BITS;

    // Step (1): Cache lookup:
    int i = bluefat_cache_lookup(id, entry);
    if (__builtin_expect(i >= 0, true))
    {
        bluefat_cache_hit++;    // Fast path (cache hit)
        return entry + i;
    }
    bluefat_cache_miss++;       // Slow path (cache miss)

    // Step (2): Mapping lookup (serialized):
    bluefat_lock();
    i = bluefat_cache_lookup(id, entry);
    if (i >= 0)
    {
        bluefat_unlock();
        return entry + i;       // Insert by another thread
    }
    ssize_t idx = bluefat_map_lookup(id);
    if (idx < 0)
    {
        bluefat_unlock();
        return NULL;            // Invalid
    }
    i = bluefat_cache_evict(entry);
    entry[i] = BLUEFAT_MAP[idx];
    bluefat_cache_insert(id, entry);
    bluefat_unlock();
    
    return entry + i;
}

/*
 * Given an unencoded pointer, create a new encoding, and add it to both the
 * mapping and cache.  Used for allocations.
 */
static void *bluefat_entry_create(const void *ptr, size_t size,
	size_t align)
{
	if (ptr == NULL ||
	        size > BLUEFAT_SIZE_MAX ||
	        align > BLUEFAT_SIZE_MAX ||
	        ((align - 1) & align) != 0 ||
	        ((uintptr_t)ptr & 0xF) != 0x0)
	    return (void *)ptr;
	uint64_t mask = BLUEFAT_PAGE_SIZE - 1;
	if (align > mask + 1)
	    mask = align - 1;
	
	uint64_t lsb = (uintptr_t)ptr & mask;
	
	bluefat_lock();
	
	bluefat_num_objects++;
	bluefat_max_objects = (bluefat_num_objects > bluefat_max_objects?
	    bluefat_num_objects: bluefat_max_objects);
	bluefat_num_bytes += size;
	bluefat_max_bytes = (bluefat_num_bytes > bluefat_max_bytes?
	    bluefat_num_bytes: bluefat_max_bytes);
	
	// Step (1): Create obfuscated pointer; insert into mapping
	uint64_t id = 0x0, offset = 0x0;
	ssize_t idx;
	while (true)
	{
	    uint64_t key = bluefat_create_key();
	    id = key >> BLUEFAT_SIZE_BITS;
	    idx = bluefat_map_lookup(id);
	    if (idx >= 0)
	        continue;       // The ID is in use; try another
	    while (true)
	    {
	        idx = bluefat_map_alloc(id);
	        if (idx >= 0)
	            break;
	        bluefat_map_resize();
	    }
	    offset = (key & BLUEFAT_SIZE_MASK & ~mask);
	    break;
	}
	
	uint64_t zero = offset | lsb;
	uint64_t overflow = zero + size;
	if ((overflow & ~BLUEFAT_SIZE_MASK) != 0x0)
	{
	    zero &= ~mask;
	    zero -= size;
	    zero &= ~mask;
	    zero |= lsb;
	}
	BLUEFAT_MAP[idx].id   = id;
	BLUEFAT_MAP[idx].zero = zero;
	BLUEFAT_MAP[idx].size = size;
	bluefat_set_base(&BLUEFAT_MAP[idx], (uintptr_t)ptr);
	
	// Step (2): Add to cache (avoid cold miss):
	struct bluefat_entry_s entry[BLUEFAT_CACHE_SET_SIZE] BLUEFAT_SET_ALIGN;
	int i = bluefat_cache_lookup(id, entry);
	if (i >= 0)
	{
	    // Should never happen:
	    bluefat_error("failed to insert entry into cache; entry for 0x%lx "
	        "already exists (THIS SHOULD NOT HAPPEN)", id);
	}
	i = bluefat_cache_evict(entry);
	entry[i] = BLUEFAT_MAP[idx];
	bluefat_cache_insert(id, entry);
	bluefat_unlock();
	
	// Step (3): Construct the encoded pointer:
	uintptr_t iptr = (id << BLUEFAT_SIZE_BITS) | zero;
	return (void *)iptr;
}

/*
 * Given a pointer, revoke it.  This means clear the corresponding entries
 * from both the mapping and cache.  Used for deallocations.
 */
static const struct bluefat_entry_s *bluefat_entry_revoke(const void *ptr,
    struct bluefat_entry_s entry[BLUEFAT_CACHE_SET_SIZE])
{
    if (!bluefat_is_encoded(ptr))
        return NULL;
    uintptr_t iptr = (uintptr_t)ptr;
    uint64_t id = iptr >> BLUEFAT_SIZE_BITS;

    // Revoke mapping & cache:
    bluefat_lock();
    int i = bluefat_cache_lookup(id, entry);
    if (i >= 0)
    {
        entry[i].id = 0x0;
        bluefat_cache_insert(id, entry);
    }
    ssize_t idx = bluefat_map_lookup(id);
    if (idx < 0)
    {
        bluefat_unlock();
        return NULL;
    }
    entry[0] = BLUEFAT_MAP[idx];
    BLUEFAT_MAP[idx].id = 0x0;
    bluefat_num_objects--;
    bluefat_num_bytes -= entry->size;
    bluefat_unlock();
    return entry;
}

/*
 * Translate an encoded pointer with error checking.
 */
static inline void *bluefat_make_valid(const struct bluefat_entry_s *entry,
    const void *ptr, size_t size, bool w, void *loc)
{
    uintptr_t iptr = (uintptr_t)ptr;
    if (__builtin_expect(entry == NULL, false))
    {
        if (w)
            return bluefat_memory_error(loc, ptr, size, entry,
                BLUEFAT_ERROR_WRITE_UAF);
        else
            return bluefat_memory_error(loc, ptr, size, entry,
                BLUEFAT_ERROR_READ_UAF);
    }
    if (__builtin_expect((iptr < entry->lb), false))
    {
        if (w)
            return bluefat_memory_error(loc, ptr, size, entry,
                BLUEFAT_ERROR_WRITE_UNDERFLOW);
        else
            return bluefat_memory_error(loc, ptr, size, entry,
                BLUEFAT_ERROR_READ_UNDERFLOW);
    }
    uintptr_t ub = entry->lb + entry->size;
    if (__builtin_expect((iptr + size > ub), false))
    {
        if (w)
            return bluefat_memory_error(loc, ptr, size, entry,
                BLUEFAT_ERROR_WRITE_OVERFLOW);
        else
            return bluefat_memory_error(loc, ptr, size, entry,
                BLUEFAT_ERROR_READ_OVERFLOW);
    }
    ptrdiff_t offset = (intptr_t)iptr - (intptr_t)entry->lb;
    iptr = bluefat_get_base(entry) + offset;
    return (void *)iptr;
}

/*
 * Encode a pointer.
 */
static void *bluefat_encode(const void *ptr, size_t args)
{
    if (bluefat_is_encoded(ptr))
        return (void *)ptr;
    size_t size  = args & 0xFFFFFFFFull;
    size_t align = args >> 32;
    void *nptr = bluefat_entry_create(ptr, size, align);
    BLUEFAT_DEBUG("encode(%p,%zu,%zu) = %p", ptr, size, align, nptr);
    return nptr;
}

/*
 * Revoke a pointer.  Returns the decoded pointer.
 */
static void *bluefat_revoke(const void *ptr)
{
    if (!bluefat_is_encoded(ptr))
        return (void *)ptr;
    
    BLUEFAT_DEBUG("revoke(%p)", ptr);

    struct bluefat_entry_s ENTRY[BLUEFAT_CACHE_SET_SIZE] BLUEFAT_SET_ALIGN;
    const struct bluefat_entry_s *entry = bluefat_entry_revoke(ptr, ENTRY);
    if (entry == NULL)
        bluefat_error("failed to revoke invalid pointer %p (double-free?)",
            ptr);

    uint64_t offset = (uintptr_t)ptr & BLUEFAT_SIZE_MASK;
    ptrdiff_t diff = (ptrdiff_t)offset - (ptrdiff_t)entry->zero;
    if (offset != entry->zero)
        bluefat_error("failed to revoke pointer %p; non-zero offset %+zd",
            ptr, diff);

    return (void *)bluefat_get_base(entry);
}

/*
 * Marshall a pointer (translate without error checking)
 */
static void *bluefat_marshall(const void *ptr)
{
    struct bluefat_entry_s ENTRY[BLUEFAT_CACHE_SET_SIZE] BLUEFAT_SET_ALIGN;
    const struct bluefat_entry_s *entry = bluefat_entry_lookup(ptr, ENTRY);
    if (entry == NULL)
        return (void *)ptr;

    const uint8_t *ptr8 = (uint8_t *)ptr;
    const uint8_t *lb8  = (uint8_t *)entry->lb;
    ptrdiff_t offset = ptr8 - lb8;
    intptr_t iptr = bluefat_get_base(entry) + offset;
    return (void *)iptr;
}

/*
 * Deref a pointer (translated with error checking)
 */
static inline void *bluefat_deref(const void *ptr, size_t size, bool w,
    void *loc)
{
    if (!bluefat_is_encoded(ptr))
    {
        uintptr_t iptr = (uintptr_t)ptr;
        if (iptr + size >= BLUEFAT_PROTECT_MIN && iptr < BLUEFAT_PROTECT_MAX)
            bluefat_error("failed to %s BlueFat private memory at address %p",
                (w? "write-to": "read-from"), ptr);
        return (void *)ptr;
    }

    struct bluefat_entry_s ENTRY[BLUEFAT_CACHE_SET_SIZE] BLUEFAT_SET_ALIGN;
    const struct bluefat_entry_s *entry = bluefat_entry_lookup(ptr, ENTRY);
    void *nptr = bluefat_make_valid(entry, ptr, size, w, loc);
    return nptr;
}

