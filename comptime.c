#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <spawn.h>
#include <sys/wait.h>

#include "ffi.h"
#define STB_DS_IMPLEMENTATION
#define STBDS_NO_SHORT_NAMES
#include "external/stb_ds.h"
#include "tree_sitter/api.h"

#include "all.h"

extern const TSLanguage *tree_sitter_c(void);

typedef struct {
    char     *name;
    ffi_type *stbds_arr_arg_types;
    ffi_type *return_type;
} fndef;

typedef struct {
    char  *name;
    void **stbds_arr_arg_values;
} fncall;

static sv decl_sv = SV("declarator");
static sv type_sv = SV("type");
static sv paramlist_sv = SV("parameters");
static sv arglist_sv = SV("arguments");

static fndef *stbds_arr_fndefs = 0;

static sv
node_text(TSNode node, unsigned char *data)
{
    int start = ts_node_start_byte(node);
    int end = ts_node_end_byte(node);
    return sv_new(data + start, end - start);
}

static void
print_node(TSNode node)
{
    char *sexp = ts_node_string(node);
    fprintf(stderr, "%s\n", sexp);
}

static void
print_node_text(TSNode node, unsigned char *data)
{
    sv text = node_text(node, data);
    fprintf(stderr, "%.*s\n", text.len, (char *)text.ptr);
}

static void
find_fundefs(TSNode node, unsigned char *data)
{
    if (sz_eql((void *)ts_node_type(node), "function_definition")) {
        bool return_is_ptr = false;

        TSNode fun_decl_node = ts_node_child_by_field_name(node, decl_sv.ptr, decl_sv.len);
        while (!sz_eql((void *)ts_node_type(fun_decl_node), "function_declarator")) {
            return_is_ptr = true;
            fun_decl_node = ts_node_child_by_field_name(fun_decl_node, decl_sv.ptr, decl_sv.len);
            if (ts_node_is_null(fun_decl_node)) PANIC("unreachable");
        }
        TSNode fun_ident = ts_node_child_by_field_name(fun_decl_node, decl_sv.ptr, decl_sv.len);
        if (ts_node_is_null(fun_ident)) PANIC("unreachable");

        sv sv_ident = node_text(fun_ident, data);
        if (!sv_starts_with(sv_ident, SV("comptime_"))) return;

        fndef fndef = {0};

        fndef.name = malloc(sv_ident.len + 1);
        memcpy(fndef.name, sv_ident.ptr, sv_ident.len);
        fndef.name[sv_ident.len] = 0;

        TSNode paramlist = ts_node_child_by_field_name(fun_decl_node, paramlist_sv.ptr, paramlist_sv.len);
        if (ts_node_is_null(paramlist)) PANIC("unreachable");

        for (int i = 0; i < ts_node_named_child_count(paramlist); i++) {
            ffi_type paramtype;

            TSNode param = ts_node_named_child(paramlist, i);

            TSNode param_type = ts_node_child_by_field_name(param, type_sv.ptr, type_sv.len);
            if (ts_node_is_null(param_type)) PANIC("unreachable");
            sv param_type_text = node_text(param_type, data);

            TSNode param_decl = ts_node_child_by_field_name(param, decl_sv.ptr, decl_sv.len);
            if (ts_node_is_null(param_decl)) PANIC("unreachable");

            if      (sz_eql((void *)ts_node_type(param_decl), "pointer_declarator")) paramtype = ffi_type_pointer;
            else if (sv_ends_with(param_type_text, SV("void")))           paramtype = ffi_type_void;
            else if (sv_ends_with(param_type_text, SV("unsigned long")))  paramtype = ffi_type_uint64;
            else if (sv_ends_with(param_type_text, SV("unsigned int")))   paramtype = ffi_type_uint32;
            else if (sv_ends_with(param_type_text, SV("unsigned short"))) paramtype = ffi_type_uint16;
            else if (sv_ends_with(param_type_text, SV("unsigned char")))  paramtype = ffi_type_uint8;
            else if (sv_ends_with(param_type_text, SV("long")))           paramtype = ffi_type_sint64;
            else if (sv_ends_with(param_type_text, SV("int")))            paramtype = ffi_type_sint32;
            else if (sv_ends_with(param_type_text, SV("short")))          paramtype = ffi_type_sint16;
            else if (sv_ends_with(param_type_text, SV("char")))           paramtype = ffi_type_sint8;
            else {
                fprintf(stderr, "unsupported param type: %.*s\n", param_type_text.len, (char *)param_type_text.ptr);
                return;
            }
            stbds_arrput(fndef.stbds_arr_arg_types, paramtype);
        }

        TSNode type_node = ts_node_child_by_field_name(node, type_sv.ptr, type_sv.len);
        if (ts_node_is_null(type_node)) PANIC("unreachable");

        sv type_text = node_text(type_node, data);

        if      (return_is_ptr)                                 fndef.return_type = &ffi_type_pointer;
        else if (sv_ends_with(type_text, SV("void")))           fndef.return_type = &ffi_type_void;
        else if (sv_ends_with(type_text, SV("unsigned long")))  fndef.return_type = &ffi_type_uint64;
        else if (sv_ends_with(type_text, SV("unsigned int")))   fndef.return_type = &ffi_type_uint32;
        else if (sv_ends_with(type_text, SV("unsigned short"))) fndef.return_type = &ffi_type_uint16;
        else if (sv_ends_with(type_text, SV("unsigned char")))  fndef.return_type = &ffi_type_uint8;
        else if (sv_ends_with(type_text, SV("long")))           fndef.return_type = &ffi_type_sint64;
        else if (sv_ends_with(type_text, SV("int")))            fndef.return_type = &ffi_type_sint32;
        else if (sv_ends_with(type_text, SV("short")))          fndef.return_type = &ffi_type_sint16;
        else if (sv_ends_with(type_text, SV("char")))           fndef.return_type = &ffi_type_sint8;
        else {
            fprintf(stderr, "unsupported return type: %.*s\n", type_text.len, (char *)type_text.ptr);
            return;
        }

        stbds_arrput(stbds_arr_fndefs, fndef);
        return;
    }

    for (int i = 0; i < ts_node_named_child_count(node); i++)
        find_fundefs(ts_node_named_child(node, i), data);
}

static bool
next_fncall(TSNode node, unsigned char *data, fncall *dst, TSNode *dstnode)
{
    if (sz_eql((void *)ts_node_type(node), "call_expression")) {
        static sv fun_sv = SV("function");

        TSNode fun_ident = ts_node_child_by_field_name(node, fun_sv.ptr, fun_sv.len);
        if (ts_node_is_null(fun_ident)) PANIC("unreachable");

        sv sv_ident = node_text(fun_ident, data);
        if (!sv_starts_with(sv_ident, SV("comptime_")))
            goto recurse;

        fncall fncall = {0};
        fncall.name = malloc(sv_ident.len + 1);
        memcpy(fncall.name, sv_ident.ptr, sv_ident.len);
        fncall.name[sv_ident.len] = 0;

        TSNode arglist = ts_node_child_by_field_name(node, arglist_sv.ptr, arglist_sv.len);
        if (ts_node_is_null(arglist)) PANIC("unreachable");

        // NOTE: Check if we don't have any call expression child.
        //       If we find one, current node is not a leaf.
        for (int i = 0; i < ts_node_named_child_count(arglist); i++) {
            TSNode arg = ts_node_named_child(arglist, i);
            if (sz_eql((void *)ts_node_type(arg), "call_expression"))
                if (next_fncall(arg, data, dst, dstnode))
                    return true;
        }

        for (int i = 0; i < ts_node_named_child_count(arglist); i++) {
            TSNode arg = ts_node_named_child(arglist, i);
            unsigned char *val;

            const char *arg_tstype = ts_node_type(arg);
            if (sz_eql((void *)arg_tstype, "string_literal")) {
                sv quoted_string = node_text(arg, data);
                sv unquoted = sv_new(quoted_string.ptr + 1, quoted_string.len - 2);
                val = malloc(unquoted.len + 1);
                memcpy(val, unquoted.ptr, unquoted.len);
                val[unquoted.len] = 0;
                stbds_arrput(fncall.stbds_arr_arg_values, &val);
            } else if (sz_eql((void *)arg_tstype, "number_literal")) {
                sv unquoted = node_text(arg, data);
                val = malloc(sizeof(long));
                *val = atol(unquoted.ptr);
                stbds_arrput(fncall.stbds_arr_arg_values, val);
            } else {
                fprintf(stderr, "unsupported arg type: %s\n", arg_tstype);
                return false;
            }
        }

        *dst = fncall;
        *dstnode = node;
        return true;
    }

recurse:
    for (int i = 0; i < ts_node_named_child_count(node); i++)
        if (next_fncall(ts_node_named_child(node, i), data, dst, dstnode))
            return true;
    return false;
}

int
main(int argc, char **argv, char **envp)
{
    TSParser *parser = ts_parser_new();
    ts_parser_set_language(parser, tree_sitter_c());

    sb *stbds_arr_files = 0;
    char **cc_argv = 0;

    char *pwd = getenv("PWD");
    if (pwd == 0) PANIC("PWD environment variable is not set");

    char *so_file = malloc(strlen(pwd) + 1 + sizeof("comptime.so"));
    sprintf(so_file, "%s/comptime.so", pwd);

    stbds_arrput(cc_argv, "cc");
    stbds_arrput(cc_argv, "-O2");
    stbds_arrput(cc_argv, "-shared");
    stbds_arrput(cc_argv, "-fPIC");
    stbds_arrput(cc_argv, "-o");
    stbds_arrput(cc_argv, so_file);

    for (int i = 1; i < argc; i++) {
        stbds_arrput(cc_argv, argv[i]);

        char *arg = argv[i];
        if (arg[0] == '-') continue;

        sb file;
        int err = file_try_read(arg, &file);
        if (err < 0) PANIC("%s: %s", arg, strerror(-err));

        TSTree *tree = ts_parser_parse_string(parser, 0, file.ptr, file.len);
        find_fundefs(ts_tree_root_node(tree), file.ptr);

        stbds_arrput(stbds_arr_files, file);
    }

    int files_len = stbds_arrlen(stbds_arr_files);
    int fndefs_len = stbds_arrlen(stbds_arr_fndefs);

    int cc_argc = stbds_arrlen(cc_argv);
    for (int i = 0; i < cc_argc; i++) {
        fprintf(stderr, "%s ", cc_argv[i]);
    }
    fputc('\n', stderr);

    pid_t cc_pid;
    int error = posix_spawnp(&cc_pid, "cc", 0, 0, cc_argv, envp);
    if (error < 0) PANIC("system error: %d", error);

    int status;
    if (wait(&status) < 0) PANIC("system error: %s", strerror(errno));
    if (!WIFEXITED(status)) PANIC("comptime cc exited abnormally");
    if (WEXITSTATUS(status) != 0) PANIC("comptime cc exited with non-zero status code");

    void *dl = dlopen(so_file, RTLD_LAZY);
    if (dl == 0) PANIC("%s", dlerror());

    while (1) {
        sb *file2;
        fncall fncall;
        TSNode callnode;
        bool callfound = false;

        for (int i = 0; i < files_len; i++) {
            file2 = &stbds_arr_files[i];
            TSTree *tree = ts_parser_parse_string(parser, 0, file2->ptr, file2->len);

            if (next_fncall(ts_tree_root_node(tree), file2->ptr, &fncall, &callnode)) {
                callfound = true;
                break;
            }
        }
        if (!callfound) break;

        fndef *def = 0;
        for (int i = 0; i < fndefs_len; i++) {
            fndef cur = stbds_arr_fndefs[i];
            if (sz_eql(cur.name, fncall.name)) {
                def = &stbds_arr_fndefs[i];
                break;
            }
        }
        if (def == 0) PANIC("found comptime call without its definition");

        void *fn = dlsym(dl, def->name);
        if (fn == 0) PANIC("couldn't find '%s'", def->name);

        ffi_cif cif = {0};
        ffi_status status = ffi_prep_cif(&cif, FFI_DEFAULT_ABI, stbds_arrlen(def->stbds_arr_arg_types), def->return_type, &def->stbds_arr_arg_types);
        if (status != FFI_OK) PANIC("ffi died");

        // HACK: retval is 64-bit long. Maybe that's enough for us
        unsigned char retval[8] = {0};
        ffi_call(&cif, fn, retval, fncall.stbds_arr_arg_values);

        // HACK: Static string
        static char replace[256];
        int replacelen;

        ffi_type *ffi_rettype = def->return_type;

        // TODO: ffi_type_pointer is handled so badly. It only works null-terminated strings.
        if      (ffi_rettype == &ffi_type_pointer) { replacelen = sprintf(replace, "\"%.*s\"", (int)strlen(*(char **)retval), *(char **)retval); }
        else if (ffi_rettype == &ffi_type_void)    { replacelen = 0; }
        else if (ffi_rettype == &ffi_type_uint64)  { replacelen = sprintf(replace, "%lu", *(unsigned long *) retval); }
        else if (ffi_rettype == &ffi_type_uint32)  { replacelen = sprintf(replace, "%du", *(unsigned int *)  retval); }
        else if (ffi_rettype == &ffi_type_uint16)  { replacelen = sprintf(replace, "%du", *(unsigned short *)retval); }
        else if (ffi_rettype == &ffi_type_uint8)   { replacelen = sprintf(replace, "%du", *(unsigned char *) retval); }
        else if (ffi_rettype == &ffi_type_sint64)  { replacelen = sprintf(replace, "%ld", *(long *) retval); }
        else if (ffi_rettype == &ffi_type_sint32)  { replacelen = sprintf(replace, "%d",  *(int *)  retval); }
        else if (ffi_rettype == &ffi_type_sint16)  { replacelen = sprintf(replace, "%d",  *(short *)retval); }
        else if (ffi_rettype == &ffi_type_sint8)   { replacelen = sprintf(replace, "%d",  *(char *) retval); }
        else PANIC("unsupported ffi type: %p\n", ffi_rettype);

        int start = ts_node_start_byte(callnode);
        int end = ts_node_end_byte(callnode);
        sb_splice(file2, start, end, replace, replacelen);

        // DEBUG
        fprintf(stderr, "%.*s\n", file2->len, (char *)file2->ptr);

        puts(fncall.name);
    }

    return 0;
}
