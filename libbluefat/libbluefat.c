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

/*
 * Wraps malloc/free with pointer encoding/decoding.
 */

#include <errno.h>
#include <malloc.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define BLUEFAT_PAGE_SIZE   4096
#define BLUEFAT_NUM_PAGES(size)                                          \
    ((((size) - 1) / BLUEFAT_PAGE_SIZE) + 1)

#define BLUE                "\33[34m"
#define OFF                 "\33[0m"
#if 0
#define BLUEFAT_DEBUG(msg, ...)                                          \
    fprintf(stderr, BLUE "DEBUG" OFF ": " msg "\n", ##__VA_ARGS__);
#else
#define BLUEFAT_DEBUG(msg, ...)     /* NOP */
#endif

/*
 * Encode instruction. (nop %r14), handled by the BlueFat Pin tool.
 */
static inline void *bluefat_encode(const void *ptr0, size_t size0,
    size_t align)
{
    size0 |= (align << 32);
    register const void *ptr1 asm ("r14") = ptr0;
    register size_t size1 asm("rsi") = size0;
    register void *ptr asm ("rax") = (void *)ptr1;
    asm volatile (
        "mov %1,%0\n"
        "nopl (%1,%2)" : "=r"(ptr) : "r"(ptr1), "r"(size1));
    return ptr;
}

/*
 * Revoke instruction. (nop %r15)
 */
static inline void *bluefat_revoke(const void *ptr0)
{
    register const void *ptr1 asm ("r15") = ptr0;
    register void *ptr asm ("rax") = (void *)ptr1;
    asm volatile (
        "mov %1,%0\n"
        "nopl (%1)" : "=r"(ptr) : "r"(ptr1));
    return ptr;
}

#define BLUEFAT_ENCODE(ptr, size, align)    \
    bluefat_encode((ptr), (size), (align))
#define BLUEFAT_REVOKE(ptr)                 bluefat_revoke((ptr))

/*
 * Glibc malloc() functions.
 */
extern void *__libc_malloc(size_t size);
extern void __libc_free(void *);
extern void *__libc_realloc(void *ptr, size_t size);
extern void *__libc_calloc(size_t nmemb, size_t size);
void *__libc_memalign(size_t align, size_t size);
extern void *_ZSt17__throw_bad_allocv() __attribute__((__weak__));

/*
 * BlueFat malloc().
 */
static void *bluefat_malloc(size_t size)
{
    void *ptr = __libc_malloc(size);
    if (ptr == NULL)
        return ptr;
    memset(ptr, 0x0, size);
    ptr = BLUEFAT_ENCODE(ptr, size, 0);
    BLUEFAT_DEBUG("malloc(%zu) = %p", size, ptr);
    return ptr;
}

/*
 * BlueFat free().
 */
static void bluefat_free(void *ptr)
{
    BLUEFAT_DEBUG("free(%p)", ptr);
    ptr = BLUEFAT_REVOKE(ptr);
    __libc_free(ptr);
}

/*
 * BlueFat realloc().
 */
static void *bluefat_realloc(void *ptr0, size_t size)
{
    void *ptr = BLUEFAT_REVOKE(ptr0);
    ptr = __libc_realloc(ptr, size);
    if (ptr == NULL)
        return ptr;
    uint8_t *ptr8 = (uint8_t *)ptr;
    memset(ptr8 + size, 0x0, malloc_usable_size(ptr) - size);
    ptr = BLUEFAT_ENCODE(ptr, size, 0);
    BLUEFAT_DEBUG("realloc(%p,%zu) = %p", ptr0, size, ptr);
    return ptr;
}

/*
 * BlueFat calloc().
 */
static void *bluefat_calloc(size_t nmemb, size_t size)
{
    void *ptr = __libc_calloc(nmemb, size);
    if (ptr == NULL)
        return ptr;
    ptr = BLUEFAT_ENCODE(ptr, nmemb * size, 0);
    BLUEFAT_DEBUG("calloc(%zu,%zu) = %p", nmemb, size, ptr);
    return ptr;
}

/*
 * BlueFat memalign().
 */
static void *bluefat_memalign(size_t align, size_t size)
{
    void *ptr = __libc_memalign(align, size);
    if (ptr == NULL)
        return ptr;
    memset(ptr, 0x0, size);
    ptr = BLUEFAT_ENCODE(ptr, size, align);
    BLUEFAT_DEBUG("malign(%zu,%zu) = %p", align, size, ptr);
    return ptr;
}

/*
 * BlueFat posix_memalign().
 */
static int bluefat_posix_memalign(void **memptr, size_t align, size_t size)
{
    if ((align & (align - 1)) != 0 || align < sizeof(void *))
        return EINVAL;
    void *ptr = bluefat_memalign(align, size);
    if (ptr == NULL)
        return ENOMEM;
    *memptr = ptr;
    return 0;
}

/*
 * Memory allocation function wrappers.
 */
#define BLUEFAT_ALIAS(f)    __attribute__((__alias__(f)))
extern void *malloc(size_t size) BLUEFAT_ALIAS("bluefat_malloc");
extern void free(void *ptr) BLUEFAT_ALIAS("bluefat_free");
extern void *realloc(void *ptr, size_t size) BLUEFAT_ALIAS("bluefat_realloc");
extern void *calloc(size_t nmemb, size_t size) BLUEFAT_ALIAS("bluefat_calloc");

static void *bluefat__Znwm(size_t size)
{
    void *ptr = bluefat_malloc(size);
    if (ptr != NULL)
        return ptr;
    _ZSt17__throw_bad_allocv();
    abort();
}
static void *bluefat__Znam(size_t size) BLUEFAT_ALIAS("bluefat__Znwm");
static void *bluefat__ZnwmRKSt9nothrow_t(size_t size)
    BLUEFAT_ALIAS("bluefat_malloc");
static void *bluefat__ZnamRKSt9nothrow_t(size_t size)
    BLUEFAT_ALIAS("bluefat_malloc");

extern void *_Znwm(size_t size) BLUEFAT_ALIAS("bluefat__Znwm");
extern void *_Znam(size_t size) BLUEFAT_ALIAS("bluefat__Znwm");
extern void *_ZnwmRKSt9nothrow_t(size_t size) BLUEFAT_ALIAS("bluefat_malloc");
extern void *_ZnamRKSt9nothrow_t(size_t size) BLUEFAT_ALIAS("bluefat_malloc");

static void bluefat__ZdlPv(void *ptr) BLUEFAT_ALIAS("bluefat_free");
static void bluefat__ZdaPv(void *ptr) BLUEFAT_ALIAS("bluefat_free");
static void bluefat__ZdaPvRKSt9nothrow_t(void *ptr)
	BLUEFAT_ALIAS("bluefat_free");
static void bluefat__ZdlPvRKSt9nothrow_t(void *ptr)
	BLUEFAT_ALIAS("bluefat_free");
static void bluefat__ZdaPvm(void *ptr, size_t size)
    BLUEFAT_ALIAS("bluefat_free");
static void bluefat__ZdlPvm(void *ptr, size_t size)
    BLUEFAT_ALIAS("bluefat__ZdaPvm");

extern void _ZdlPv(void *ptr) BLUEFAT_ALIAS("bluefat_free");
extern void _ZdaPv(void *ptr) BLUEFAT_ALIAS("bluefat_free");
extern void _ZdaPvRKSt9nothrow_t(void *ptr) BLUEFAT_ALIAS("bluefat_free");
extern void _ZdlPvRKSt9nothrow_t(void *ptr) BLUEFAT_ALIAS("bluefat_free");
extern void _ZdaPvm(void *ptr, size_t size) BLUEFAT_ALIAS("bluefat__ZdaPvm");
extern void _ZdlPvm(void *ptr, size_t size) BLUEFAT_ALIAS("bluefat__ZdaPvm");

extern int posix_memalign(void **memptr, size_t align, size_t size)
    BLUEFAT_ALIAS("bluefat_posix_memalign");
extern void *memalign(size_t align, size_t size)
    BLUEFAT_ALIAS("bluefat_memalign");
extern void *aligned_alloc(size_t align, size_t size)
    BLUEFAT_ALIAS("bluefat_memalign");

static void *bluefat_valloc(size_t size)
{
    return bluefat_memalign(BLUEFAT_PAGE_SIZE, size);
}
extern void *valloc(size_t size) BLUEFAT_ALIAS("bluefat_valloc");

static void *bluefat_pvalloc(size_t size)
{
    return bluefat_memalign(BLUEFAT_PAGE_SIZE,
        BLUEFAT_NUM_PAGES(size) * BLUEFAT_PAGE_SIZE);
}
extern void *pvalloc(size_t size) BLUEFAT_ALIAS("bluefat_pvalloc");

static void *bluefat__ZnwmSt11align_val_t(size_t size, size_t align)
{
    void *ptr = bluefat_memalign(align, size);
    if (ptr != NULL)
        return ptr;
    _ZSt17__throw_bad_allocv();
    abort();
}
static void *bluefat__ZnamSt11align_val_t(size_t size, size_t align)
    BLUEFAT_ALIAS("bluefat__ZnwmSt11align_val_t");
static void *bluefat__ZnwmSt11align_val_tRKSt9nothrow_t(size_t size,
    size_t align)
{
    return bluefat_memalign(align, size);
}
static void *bluefat__ZnamSt11align_val_tRKSt9nothrow_t(size_t size,
    size_t align) BLUEFAT_ALIAS("bluefat__ZnwmSt11align_val_tRKSt9nothrow_t");

extern void *_ZnwmSt11align_val_t(size_t size, size_t align)
    BLUEFAT_ALIAS("bluefat__ZnwmSt11align_val_t");
extern void *_ZnamSt11align_val_t(size_t size, size_t align)
    BLUEFAT_ALIAS("bluefat__ZnwmSt11align_val_t");
extern void *_ZnwmSt11align_val_tRKSt9nothrow_t(size_t size, size_t align)
    BLUEFAT_ALIAS("bluefat__ZnwmSt11align_val_tRKSt9nothrow_t");
extern void *_ZnamSt11align_val_tRKSt9nothrow_t(size_t size, size_t align)
    BLUEFAT_ALIAS("bluefat__ZnwmSt11align_val_tRKSt9nothrow_t");

static void bluefat__ZdlPvSt11align_val_t(void *ptr, size_t align)
    BLUEFAT_ALIAS("bluefat__ZdlPv");
static void bluefat__ZdlPvmSt11align_val_t(void *ptr, size_t size,
    size_t align) BLUEFAT_ALIAS("bluefat__ZdlPvm");
static void bluefat__ZdlPvSt11align_val_tRKSt9nothrow_t(void *ptr, size_t align)
    BLUEFAT_ALIAS("bluefat__ZdlPv");
static void bluefat__ZdaPvSt11align_val_t(void *ptr, size_t align)
    BLUEFAT_ALIAS("bluefat__ZdaPv");
static void bluefat__ZdaPvmSt11align_val_t(void *ptr, size_t size, size_t align)
    BLUEFAT_ALIAS("bluefat__ZdaPvm");
static void bluefat__ZdaPvSt11align_val_tRKSt9nothrow_t(void *ptr, size_t align)
    BLUEFAT_ALIAS("bluefat__ZdaPv");

extern void _ZdlPvSt11align_val_t(void *ptr, size_t align)
    BLUEFAT_ALIAS("bluefat__ZdlPv");
extern void _ZdlPvmSt11align_val_t(void *ptr, size_t size,
    size_t align) BLUEFAT_ALIAS("bluefat__ZdlPvm");
extern void _ZdlPvSt11align_val_tRKSt9nothrow_t(void *ptr, size_t align)
    BLUEFAT_ALIAS("bluefat__ZdlPv");
extern void _ZdaPvSt11align_val_t(void *ptr, size_t align)
    BLUEFAT_ALIAS("bluefat__ZdaPv");
extern void _ZdaPvmSt11align_val_t(void *ptr, size_t size, size_t align)
    BLUEFAT_ALIAS("bluefat__ZdaPvm");
extern void _ZdaPvSt11align_val_tRKSt9nothrow_t(void *ptr, size_t align)
    BLUEFAT_ALIAS("bluefat__ZdaPv");

#undef strdup
#undef __strdup
static char *bluefat_strdup(const char *str)
{
    size_t len = strlen(str);
    char *str2 = (char *)malloc(len+1);
    memmove(str2, str, len+1);
    return str2;
}
extern char *strdup(const char *str) BLUEFAT_ALIAS("bluefat_strdup");
extern char *__strdup(const char *str) BLUEFAT_ALIAS("bluefat_strdup");

#undef strndup
#undef __strndup
static char *bluefat_strndup(const char *str, size_t n)
{
    size_t len = strnlen(str, n);
    char *str2 = (char *)malloc(len+1);
    memmove(str2, str, len);
    str2[len] = '\0';
    return str2;
}
extern char *strndup(const char *str, size_t n)
    BLUEFAT_ALIAS("bluefat_strndup");
extern char *__strndup(const char *str, size_t n)
    BLUEFAT_ALIAS("bluefat_strndup");

