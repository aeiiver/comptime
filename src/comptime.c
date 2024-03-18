#include <dlfcn.h>
#include <spawn.h>

#define librope_rope_implementation
#include "external/rope.h"
#define STB_DS_IMPLEMENTATION
#define STBDS_NO_SHORT_NAMES
#include "external/stb_ds.h"
#include "tree_sitter/api.h"

#include "all.h"

#define NAMED_CHILD(node, name) \
    ts_node_child_by_field_name(node, name, sizeof(name) - 1)

typedef struct {
    char *name; // Borrowed
    rope *data; // Borrowed
    int len;
} file;

typedef enum {
    RET_VOID = 1,
    RET_INT,
} retkind;

typedef struct {
    sb name; // Owned
    retkind retkind;
} fndef;

extern TSLanguage *tree_sitter_c(void);

static TSParser *C_PARSER = 0;
static fndef *FNDEFS = 0;

static void
debug_node(TSNode node)
{
    char *text = ts_node_string(node);
    EPUTS(text);
}

static sv
node_text(TSNode node, unsigned char *fdata)
{
    int start = ts_node_start_byte(node);
    int end = ts_node_end_byte(node);
    sv sv = {.ptr = fdata + start, .len = end - start};
    return sv;
}

static void
collect_fndefs(TSNode node, unsigned char *fdata)
{
    if (SV_STARTS_WITH(ts_node_type(node), "function_definition")) {
        TSNode identnode = node;
        while (!SV_STARTS_WITH(ts_node_type(identnode), "identifier")) {
            identnode = NAMED_CHILD(identnode, "declarator");
            if (ts_node_is_null(identnode)) PANIC("unreachable");
        }
        sv ident = node_text(identnode, fdata);
        if (!SV_STARTS_WITH(ident.ptr, "comptime_")) return;

        TSNode typenode = NAMED_CHILD(node, "type");
        if (ts_node_is_null(typenode)) PANIC("unreachable");
        sv type = node_text(typenode, fdata);

        retkind retkind = 0;
        if (SV_STARTS_WITH(type.ptr, "void"))     retkind = RET_VOID;
        else if (SV_STARTS_WITH(type.ptr, "int")) retkind = RET_INT;
        else PANIC("unreachable");

        sb sb = sb_new(ident.ptr, ident.len);
        fndef fndef = {
            .name = sb,
            .retkind = retkind,
        };
        stbds_arrput(FNDEFS, fndef);

        return;
    }
    for (int i = 0; i < ts_node_named_child_count(node); i += 1) {
        collect_fndefs(ts_node_named_child(node, i), fdata);
    }
}

// static void
// next_fncall2(TSNode node, unsigned char *fdata, sb *fncalls)
// {
//     const char *type = ts_node_type(node);
//     if (strcmp(type, "call_expression") == 0) {
//         TSNode iden = NAMED_CHILD(node, "function");
//         if (ts_node_is_null(iden)) return;
//
//         int start = ts_node_start_byte(iden);
//         int end = ts_node_end_byte(iden);
//
//         unsigned char *text = fdata + start;
//         int textlen = end - start;
//
//         if (!SV_EQL(text, "comptime_")) return;
//
//         printf("%.*s\n", textlen, text);
//         sb sb = sb_new(text, textlen);
//         stbds_arrput(FNDEFS, sb);
//
//         TSNode arglist = NAMED_CHILD(node, "arguments");
//         if (ts_node_is_null(arglist)) PANIC("funcall without `arguments` child?");
//
//         debug_node(arglist);
//
//         return;
//     }
//
//     for (int i = 0; i < ts_node_named_child_count(node); i += 1) {
//         next_fncall2(ts_node_named_child(node, i), fdata, fncalls);
//     }
// }
//
// static void next_fncall(TSNode node, unsigned char *fdata)
// {
//     // HACK: This is awful but this ensures that fncalls is never NULL
//     // and gets reset
//     static sb *fncalls = 0;
//     stbds_arrput(fncalls, (sb){0});
//     stbds_header(fncalls)->length = 0;
//
//     next_fncall2(node, fdata, fncalls);
// }

static void
comptime_ayaya(void)
{
    puts("AYAYA!");
}

static void *
comptime_ayaya2(void)
{
    puts("AYAYA! 2");
    return 0;
}

static int
comptime_add(int a, float b)
{
    return a + b;
}

int
main(int argc, char **argv, char **envp)
{
    C_PARSER = ts_parser_new();
    ts_parser_set_language(C_PARSER, tree_sitter_c());

    static file *files = 0;

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') continue;
        file f = {.name = argv[i], .data = rope_new_with_utf8(try_readfile(argv[i], &f.len))};
        if (f.data == 0) {
            FATALF("Failed to read '%s'\n", argv[i]);
            continue;
        }
        stbds_arrput(files, f);
    }

    for (int i = 0; i < stbds_arrlen(files); i++) {
        rope *fdata = files[i].data;
        int flen = files[i].len;
        TSTree *tree = ts_parser_parse_string(C_PARSER, 0, (char *)fdata, flen);
        // HACK: This is so memory-leaky
        collect_fndefs(ts_tree_root_node(tree), rope_create_cstr(fdata));
    }

    // CLEANUP: maybe make this string buffer an owned immutable one?
    // The semantics of this DS is that it may be mutated
    // Also we're tecnically playing with a path...
    char *pwd = getenv("PWD");
    sb TARGET = sb_new(pwd, strlen(pwd));
    sb_catc(&TARGET, '/');
    SB_CATS(&TARGET, "comptime.so");
    sb_catc(&TARGET, '\0');

    puts(TARGET.buf);

    char **cc_argv = 0;
    stbds_arrput(cc_argv, "cc");
    stbds_arrput(cc_argv, "-shared");
    stbds_arrput(cc_argv, "-fPIC");
    stbds_arrput(cc_argv, "-o");
    // NOTE: Be careful, this array is *borrowing* TARGET.buf
    stbds_arrput(cc_argv, TARGET.buf);
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') continue;
        stbds_arrput(cc_argv, argv[i]);
    }

    // CLEANUP: This is a simple debug print but make this cleaner next time
    EPRINTF("%s", cc_argv[0]);
    for (int i = 1; i < stbds_arrlen(cc_argv); i++) {
        EPRINTF(" %s", cc_argv[i]);
    }
    EPUTC('\n');

    int pid;
    if (posix_spawnp(&pid, cc_argv[0], 0, 0, cc_argv, envp) < 0)
        PANIC("couldn't spawn cc");

    void *dl = dlopen(TARGET.buf, RTLD_LAZY);
    if (dl == 0) PANIC("couldn't dlopen");

    for (int i = 0; i < stbds_arrlen(FNDEFS); i++) {
        EPRINTF("debug: found '%.*s'\n",
                FNDEFS[i].name.len, (char *)FNDEFS[i].name.buf);
    }
    // next_fncall(root, fdata);

    // TEMP
    int test = comptime_add(1, 2.0f);
    int test2 = comptime_add(comptime_add(1, 2.0f), 2.0f);

    return 0;
}
