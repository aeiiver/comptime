#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PANIC(fmt, ...) (fprintf(stderr, fmt "\n" __VA_OPT__(,) __VA_ARGS__), fflush(stderr), __builtin_trap())

#define SV(s) ((sv){s, sizeof(s) - 1})

typedef int libc_errno;

typedef struct {
    void *ptr;
    int   cap;
    int   len;
} sb;

typedef struct {
    void *ptr;
    int   len;
} sv;

static void
sb_free(sb *self)
{
    free(self->ptr);
    self->ptr = 0;
}

static void
sb_ensure_fit(sb *self, int newcap)
{
    if (newcap >= self->cap) {
        self->ptr = realloc(self->ptr, newcap);
        if (self->ptr == 0) PANIC("sb_ensure_fit: sorry");
        self->cap = newcap;
    }
}

static void
sb_splice(sb *self, int start, int end, void *replace, int replacelen)
{
    int count = end - start;

    int newlen = self->len - count + replacelen;
    sb_ensure_fit(self, newlen);

    void *splice_start   = self->ptr + start;
    void *splice_end     = splice_start + count;
    void *splice_new_end = splice_start + replacelen;
    memmove(splice_new_end, splice_end, self->ptr + self->len - splice_end);
    memcpy(splice_start, replace, replacelen);

    self->len = newlen;
}

static sv
sv_new(void *ptr, int len)
{
    return (sv){ptr, len};
}

static bool
sv_eql(sv lhs, sv rhs)
{
    return lhs.len == rhs.len && memcmp(lhs.ptr, rhs.ptr, lhs.len) == 0;
}

static bool
sv_starts_with(sv self, sv prefix)
{
    return sv_eql(sv_new(self.ptr, prefix.len), prefix);
}

static bool
sv_ends_with(sv self, sv suffix)
{
    return sv_eql(sv_new(self.ptr + self.len - suffix.len, suffix.len), suffix);
}

static bool
sz_eql(void *lhs, void *rhs)
{
    return strcmp(lhs, rhs) == 0;
}

static libc_errno
file_try_read(char *fname, sb *dest)
{
    libc_errno ret = 0;

    FILE *f = fopen(fname, "rb");
    if (f == 0) {
        ret = -errno;
        goto ret;
    }

    if (fseek(f, 0, SEEK_END) < 0) {
        ret = -errno;
        goto fclose;
    }

    int len = ftell(f);
    if (len < 0) {
        ret = -errno;
        goto fclose;
    }

    if (fseek(f, 0, SEEK_SET) < 0) {
        ret = -errno;
        goto fclose;
    }

    unsigned char *buf = malloc(len);
    if (buf == 0) {
        ret = -errno;
        goto fclose;
    }

    if (fread(buf, 1, len, f) < len) {
        ret = -errno;
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
