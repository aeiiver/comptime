#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PASTE(x)  PASTE2(x)
#define PASTE2(x) #x

#define FILELOC __FILE__ ":" PASTE(__LINE__) ": "

#define EPUTC(s)          fputc(s, stderr)
#define EPUTS(s)          EPRINTF("%s\n", s)
#define EPRINTF(fmt, ...) fprintf(stderr, fmt, __VA_ARGS__)

#define FATAL(s)         (EPUTS(s),                  exit(EXIT_FAILURE))
#define FATALF(fmt, ...) (EPRINTF(fmt, __VA_ARGS__), exit(EXIT_FAILURE))

#define PANIC(s) \
    (EPUTS(FILELOC s), fflush(stderr), __builtin_trap())

#define PANICF(fmt, ...) \
    (EPRINTF(FILELOC fmt, __VA_ARGS__), fflush(stderr), __builtin_trap())

#define ASSERT(x, fmt, ...) \
    do { if (!(x)) PANICF(fmt, __VA_ARGS__); } while (0)

#define SV_STARTS_WITH(lhs, rhslit) (memcmp(lhs, rhslit, sizeof(rhslit) - 1) == 0)

#define SB_GROW        1.5
#define SB(s)          sb_new(s, sizeof(s) - 1)
#define SBZ(s)         sb_new(s, sizeof(s))
#define SB_CATS(sb, s) sb_cats(sb, s, sizeof(s) - 1)

typedef struct {
    void *ptr; // Borrowed
    int len;
} sv;

typedef struct {
    void *buf; // Owned
    int cap;
    int len;
} sb;

static sb sb_new(void *s, int len)
{
    // CLEANUP: Not even checking if malloc fails
    sb sb = {
        .buf = malloc(len),
        .cap = len,
        .len = len,
    };
    memcpy(sb.buf, s, len);
    return sb;
}

static void sb_free(sb sb)
{
    free(sb.buf);
}

static void sb_cats(sb *sb, void *s, int len)
{
    if (sb->len + len >= sb->cap) {
        int newcap = sb->cap * SB_GROW + len;
        // CLEANUP: Check if realloc fails
        sb->buf = realloc(sb->buf, newcap);
        sb->cap = newcap;
    }
    memcpy(((unsigned char *)sb->buf) + sb->len, s, len);
    sb->len += len;
}

static void sb_catc(sb *sb, unsigned char c)
{
    sb_cats(sb, &c, 1);
}

static unsigned char *try_readfile(char *fname, int *flen)
{
    FILE *f = fopen(fname, "rb");
    if (f == 0) goto ret;

    if (fseek(f, 0, SEEK_END) < 0)
        goto fclose;

    int len = ftell(f);
    if (flen < 0) goto fclose;

    if (fseek(f, 0, SEEK_SET) < 0)
        goto fclose;

    unsigned char *fdata = malloc(sizeof(*fname) * len);
    if (fdata == 0) goto fclose;

    if (fread(fdata, sizeof(*fname), len, f) < len)
        goto free;

    if (flen) *flen = len;
    return fdata;

free:
    free(fdata);
fclose:
    fclose(f);
ret:
    return 0;
}
