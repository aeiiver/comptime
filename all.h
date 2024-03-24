#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SHIFT_ARGS(argc, argv) (argc--, *argv++)

#define PANIC(s)         (fprintf(stderr, "panic: %s\n", s),                fflush(stderr), __builtin_trap())
#define PANICF(fmt, ...) (fprintf(stderr, "panic: " fmt "\n", __VA_ARGS__), fflush(stderr), __builtin_trap())

// TODO: ifdef 'UNREACHABLE()' for non-debug builds where we would just
//       use '__builtin_unreachable()'

#define UNREACHABLE() PANIC("unreachable")

#define SV_STARTS_WITH(sv, static_sz) (sv.len >= (sizeof(static_sz)-1) && memcmp(sv.ptr, static_sz, (sizeof(static_sz)-1)) == 0)
#define SV_ENDS_WITH(sv, static_sz)   (sv.len >= (sizeof(static_sz)-1) && memcmp(sv.ptr + sv.len - (sizeof(static_sz)-1), static_sz, (sizeof(static_sz)-1)) == 0)

typedef int libc_errno;

typedef struct {
    union { unsigned char *ptr; char *ptrc; };
    int cap;
    int len;
} sb;

typedef struct {
    unsigned char *ptr;
    int len;
} sv;

static void
out_of_memory(void)
{
    PANIC("out of memory");
}

static void *
malloc_or_oom(int size)
{
    void *ptr = malloc(size);
    if (ptr == 0) out_of_memory();
    return ptr;
}

static void *
realloc_or_oom(void *ptr, int size)
{
    ptr = realloc(ptr, size);
    if (ptr == 0) out_of_memory();
    return ptr;
}

static void
sb_free(sb *sb)
{
    free(sb->ptr);
    sb->ptr = 0;
}

static void
sb_ensure_fit(sb *sb, int newcap)
{
    if (newcap <= sb->cap) return;
    sb->ptr = realloc_or_oom(sb->ptr, newcap);
    sb->cap = newcap;
}

static void
sb_splice(sb *sb, int start, int end, void *replace, int replacelen)
{
    int rangelen = end - start;
    int newlen = sb->len - rangelen + replacelen;

    sb_ensure_fit(sb, newlen);

    unsigned char *splice_start   = sb->ptr + start;
    unsigned char *splice_end     = splice_start + rangelen;
    unsigned char *splice_new_end = splice_start + replacelen;

    memmove(splice_new_end, splice_end, sb->ptr + sb->len - splice_end);
    memcpy(splice_start, replace, replacelen);

    sb->len = newlen;
}

static bool
sz_eql(const char *lhs, const char *rhs)
{
    return strcmp(lhs, rhs) == 0;
}

static libc_errno
file_try_read(char *fname, sb *dest)
{
    libc_errno ret = 0;

    FILE *f = fopen(fname, "rb");
    if (f == 0) {
        ret = errno;
        goto ret;
    }

    if (fseek(f, 0, SEEK_END) < 0) {
        ret = errno;
        goto fclose;
    }

    int len = ftell(f);
    if (len < 0) {
        ret = errno;
        goto fclose;
    }

    if (fseek(f, 0, SEEK_SET) < 0) {
        ret = errno;
        goto fclose;
    }

    unsigned char *buf = malloc(len);
    if (buf == 0) {
        ret = errno;
        goto fclose;
    }

    if (fread(buf, 1, len, f) < len) {
        ret = errno;
        goto free;
    }

    dest->ptr = buf;
    dest->cap = len;
    dest->len = len;
    goto fclose;

free:
    free(buf);
fclose:
    fclose(f);
ret:
    return ret;
}
