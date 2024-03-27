#include <dlfcn.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ffi.h"
#define STB_DS_IMPLEMENTATION
#define STBDS_NO_SHORT_NAMES
#include "external/stb_ds.h"
#include "tree_sitter/api.h"

#include "all.h"

#define TS_CHILD_NODE(node, fieldname) \
    ts_node_child_by_field_name(node, fieldname, sizeof(fieldname) - 1)

extern TSLanguage *tree_sitter_c(void);

typedef struct {
    char      *name;
    ffi_type **stbds_arr_arg_types;
    ffi_type  *return_type;
    bool       is_variadic;
} fndef;

typedef struct {
    char      *name;
    void     **stbds_arr_arg_values;
    ffi_type **stbds_arr_arg_types;
} fncall;

static fndef *stbds_arr_fndefs = 0;

static sv
node_text(TSNode node, unsigned char *data)
{
    int start = ts_node_start_byte(node);
    int end   = ts_node_end_byte(node);
    return (sv){data + start, end - start};
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
    fprintf(stderr, "%.*s\n", text.len, text.ptr);
}

static void
find_fundefs(TSNode node, unsigned char *data)
{
    bool is_decl = sz_eql(ts_node_type(node), "declaration");
    if (!is_decl && !sz_eql(ts_node_type(node), "function_definition")) {
        for (int i = 0; i < ts_node_named_child_count(node); i++)
            find_fundefs(ts_node_named_child(node, i), data);
        return;
    }

    bool return_ptr = false;

    TSNode fun_decl_node = TS_CHILD_NODE(node, "declarator");
    if (ts_node_is_null(fun_decl_node)) UNREACHABLE();

    while (!sz_eql(ts_node_type(fun_decl_node), "function_declarator")) {
        return_ptr = true;
        fun_decl_node = TS_CHILD_NODE(fun_decl_node, "declarator");
        if (ts_node_is_null(fun_decl_node)) return;
    }

    TSNode fun_ident_node = TS_CHILD_NODE(fun_decl_node, "declarator");
    if (ts_node_is_null(fun_ident_node)) UNREACHABLE();

    sv sv_ident = node_text(fun_ident_node, data);
    fndef def = {0};

    def.name = malloc_or_oom(sv_ident.len + 1);
    memcpy(def.name, sv_ident.ptr, sv_ident.len);
    def.name[sv_ident.len] = 0;

    TSNode paramlist = TS_CHILD_NODE(fun_decl_node, "parameters");
    if (ts_node_is_null(paramlist)) UNREACHABLE();

    for (int i = 0; i < ts_node_named_child_count(paramlist); i++) {
        TSNode param = ts_node_named_child(paramlist, i);

        if (sz_eql(ts_node_type(param), "variadic_parameter")) {
            def.is_variadic = true;
            break;
        }

        bool maybe_pointer = true;
        TSNode param_decl = TS_CHILD_NODE(param, "declarator");
        if (ts_node_is_null(param_decl)) maybe_pointer = false;

        TSNode param_type = TS_CHILD_NODE(param, "type");
        if (ts_node_is_null(param_type)) UNREACHABLE();

        sv param_type_text = node_text(param_type, data);
        ffi_type *paramtype;

        if      (maybe_pointer && sz_eql(ts_node_type(param_decl), "pointer_declarator")) paramtype = &ffi_type_pointer;
        else if (SV_ENDS_WITH(param_type_text, "void"))           paramtype = &ffi_type_void;
        else if (SV_ENDS_WITH(param_type_text, "unsigned long"))  paramtype = &ffi_type_uint64;
        else if (SV_ENDS_WITH(param_type_text, "unsigned int"))   paramtype = &ffi_type_uint32;
        else if (SV_ENDS_WITH(param_type_text, "unsigned short")) paramtype = &ffi_type_uint16;
        else if (SV_ENDS_WITH(param_type_text, "unsigned char"))  paramtype = &ffi_type_uint8;
        else if (SV_ENDS_WITH(param_type_text, "long"))           paramtype = &ffi_type_sint64;
        else if (SV_ENDS_WITH(param_type_text, "int"))            paramtype = &ffi_type_sint32;
        else if (SV_ENDS_WITH(param_type_text, "short"))          paramtype = &ffi_type_sint16;
        else if (SV_ENDS_WITH(param_type_text, "char"))           paramtype = &ffi_type_sint8;
        else {
            fprintf(
                stderr, "unsupported param type: %.*s\n",
                param_type_text.len, param_type_text.ptr
            );
            return;
        }

        // You may have a compiler warning on the following line.
        // It's safe to ignore because we do want to store addresses.
        stbds_arrput(def.stbds_arr_arg_types, paramtype);
    }

    TSNode return_type_node = TS_CHILD_NODE(node, "type");
    if (ts_node_is_null(return_type_node)) UNREACHABLE();

    sv return_type_text = node_text(return_type_node, data);

    if      (return_ptr)                                 def.return_type = &ffi_type_pointer;
    else if (SV_ENDS_WITH(return_type_text, "void"))           def.return_type = &ffi_type_void;
    else if (SV_ENDS_WITH(return_type_text, "unsigned long"))  def.return_type = &ffi_type_uint64;
    else if (SV_ENDS_WITH(return_type_text, "unsigned int"))   def.return_type = &ffi_type_uint32;
    else if (SV_ENDS_WITH(return_type_text, "unsigned short")) def.return_type = &ffi_type_uint16;
    else if (SV_ENDS_WITH(return_type_text, "unsigned char"))  def.return_type = &ffi_type_uint8;
    else if (SV_ENDS_WITH(return_type_text, "long"))           def.return_type = &ffi_type_sint64;
    else if (SV_ENDS_WITH(return_type_text, "int"))            def.return_type = &ffi_type_sint32;
    else if (SV_ENDS_WITH(return_type_text, "short"))          def.return_type = &ffi_type_sint16;
    else if (SV_ENDS_WITH(return_type_text, "char"))           def.return_type = &ffi_type_sint8;
    else {
        fprintf(
            stderr, "unsupported return type: %.*s\n",
            return_type_text.len, return_type_text.ptr
        );
        return;
    }

    stbds_arrput(stbds_arr_fndefs, def);
}

static bool
next_fncall2(TSNode node, unsigned char *data, fncall *dst, TSNode *dstnode)
{
    if (!sz_eql(ts_node_type(node), "call_expression")) {
recurse:
        for (int i = 0; i < ts_node_named_child_count(node); i++)
            if (next_fncall2(ts_node_named_child(node, i), data, dst, dstnode))
                return true;
        return false;
    }

    print_node_text(node, data);

    TSNode fun_ident = TS_CHILD_NODE(node, "function");
    if (ts_node_is_null(fun_ident)) UNREACHABLE();

    sv sv_ident = node_text(fun_ident, data);
    fncall call = {0};

    call.name = malloc_or_oom(sv_ident.len + 1);
    memcpy(call.name, sv_ident.ptr, sv_ident.len);
    call.name[sv_ident.len] = 0;

    TSNode arglist = TS_CHILD_NODE(node, "arguments");
    if (ts_node_is_null(arglist)) UNREACHABLE();

    for (int i = 0; i < ts_node_named_child_count(arglist); i++) {
        TSNode arg = ts_node_named_child(arglist, i);
        if (sz_eql(ts_node_type(arg), "call_expression"))
            if (next_fncall2(arg, data, dst, dstnode))
                return true;
    }

    for (int i = 0; i < ts_node_named_child_count(arglist); i++) {
        TSNode arg = ts_node_named_child(arglist, i);
        const char *arg_type = ts_node_type(arg);
        unsigned char *val;

        if (sz_eql(arg_type, "string_literal")) {
            sv quoted_string = node_text(arg, data);
            sv unquoted = (sv){quoted_string.ptr + 1, quoted_string.len - 2};

            // TODO: Handle escape sequences. Right now it's just a plain copy
            //       of the format string, so 'val' will contain literal
            //       backslashes. It's not an issue if the final preprocessed
            //       source code is passed to the compiler but for functions
            //       that performs IO at compile-time, they may be unattended
            //       results.

            val = malloc_or_oom(unquoted.len + 1);
            memcpy(val, unquoted.ptr, unquoted.len);
            val[unquoted.len] = 0;

            void **val_addr = malloc_or_oom(sizeof(*val));
            *val_addr = val;

            stbds_arrput(call.stbds_arr_arg_values, val_addr);
            stbds_arrput(call.stbds_arr_arg_types, &ffi_type_pointer);
        } else if (sz_eql(arg_type, "number_literal")) {
            sv unquoted = node_text(arg, data);

            val = malloc_or_oom(sizeof(long));
            *val = atol((char *)unquoted.ptr);

            stbds_arrput(call.stbds_arr_arg_values, val);
            stbds_arrput(call.stbds_arr_arg_types, &ffi_type_sint32);
        } else if (sz_eql(arg_type, "identifier")) {
            sv ident = node_text(arg, data);

            void *val;
            if (SV_EQL(ident, "stdin"))
                val = stdin;
            else if (SV_EQL(ident, "stdout"))
                val = stdout;
            else if (SV_EQL(ident, "stderr"))
                val = stderr;
            else {
                fprintf(stderr, "won't resolve identifier: %.*s\n", ident.len, ident.ptr);
                return false;
            }

            void **val_addr = malloc_or_oom(sizeof(*val));
            *val_addr = val;

            stbds_arrput(call.stbds_arr_arg_values, val_addr);
            stbds_arrput(call.stbds_arr_arg_types, &ffi_type_pointer);
        } else {
            fprintf(stderr, "unsupported argument type: %s\n", arg_type);
            return false;
        }
    }

    *dst = call;
    *dstnode = node;

    return true;
}

static bool
next_fncall(TSNode node, unsigned char *data, fncall *dst, TSNode *dstnode)
{
    TSNode comment_node;
    bool found_comptime_comment = false;

    for (int i = 0; i < ts_node_child_count(node); i++) {
        TSNode child = ts_node_child(node, i);
        bool is_comment = sz_eql(ts_node_type(child), "comment");
        if (is_comment && SV_EQL(node_text(child, data), "/* @comptime */")) {
            comment_node = child;
            found_comptime_comment = true;
            break;
        }
    }

    if (found_comptime_comment) {
        if (next_fncall2(ts_node_next_sibling(comment_node), data, dst, dstnode))
            return true;
    }

    for (int i = 0; i < ts_node_child_count(node); i++)
        if (next_fncall(ts_node_child(node, i), data, dst, dstnode))
            return true;
    return false;
}

int
main(int argc, char **argv, char **envp)
{
    TSParser *parser = ts_parser_new();
    TSLanguage *c_language = tree_sitter_c();
    if (!ts_parser_set_language(parser, c_language)) {
        int min = TREE_SITTER_MIN_COMPATIBLE_LANGUAGE_VERSION;
        int cur = ts_language_version(c_language);
        PANICF(
            "version mismatch: tree-sitter (>=%d) != tree-sitter-c (=%d)",
            min, cur
        );
    }

    char *program = SHIFT_ARGS(argc, argv);
    char **stbds_arr_funcs_to_run = 0;
    bool expand = false;

    // TODO: Clean up this mess. CLI is cool and all but the following looks odd enough.
    // TODO: Implement '--run' option.

    if (argc == 0)
        goto show_usage;

    while (argc > 0) {
        char *arg = SHIFT_ARGS(argc, argv);
        if (arg[0] != '-') {
show_usage:
            fprintf(stderr, "usage: %s [options] -- compiler_args\n", program);
            fprintf(stderr, "\n");
            fprintf(stderr, "options:\n");
            fprintf(stderr, "    --run     Run function after preprocessing\n");
            fprintf(stderr, "    --expand  Output preprocessed files but don't compile\n");
            fprintf(stderr, "    --help    Show this usage message\n");
            exit(-1);
        }
        char *option_name = arg + 2;

        if (*option_name == 0) {
            break;
        } else if (sz_eql(option_name, "run")) {
            stbds_arrput(stbds_arr_funcs_to_run, SHIFT_ARGS(argc, argv));
        } else if (sz_eql(option_name, "expand")) {
            expand = true;
        } else if (sz_eql(option_name, "help")) {
            goto show_usage;
        } else {
            fprintf(stderr, "%s: unknown option '%s'\n", program, option_name);
            exit(-1);
        }
    }

    sb *stbds_arr_files = 0;
    char **stbds_arr_ccE_argv = 0;
    char **stbds_arr_cc_argv = 0;
    char **stbds_arr_cc2_argv = 0;

    char *pwd = getenv("PWD");
    if (pwd == 0) PANIC("PWD environment variable is not set");

    char *cc = getenv("CC");
    if (cc == 0) cc = "cc";

    static char so_fname[256] = {0};
    if (sprintf(so_fname, "%s/comptime.so", pwd) > sizeof(so_fname))
        PANIC("buffer overflow occured while building 'comptime.so' path");

    FILE *so_file = fopen(so_fname, "abx");
    if (so_file == 0) {
        if (errno == EEXIST)
            PANIC("file 'comptime.so' already exists but it isn't owned by comptime");
        PANIC(strerror(errno));
    }
    if (fclose(so_file) < 0) PANIC(strerror(errno));

    stbds_arrput(stbds_arr_ccE_argv, cc);
    stbds_arrput(stbds_arr_ccE_argv, "-E");

    stbds_arrput(stbds_arr_cc_argv, cc);
    stbds_arrput(stbds_arr_cc_argv, "-O2");
    stbds_arrput(stbds_arr_cc_argv, "-shared");
    stbds_arrput(stbds_arr_cc_argv, "-fPIC");
    stbds_arrput(stbds_arr_cc_argv, "-o");
    stbds_arrput(stbds_arr_cc_argv, so_fname);

    for (int i = 0; i < argc; i++) {
        char *arg = argv[i];

        if (arg[0] == '-' && arg[1] == 'o') {
            i += 1;
            continue;
        }
        stbds_arrput(stbds_arr_cc_argv, arg);
        if (arg[0] == '-') continue;

        sv arg_as_sv = (sv){(void *)arg, strlen(arg)};
        if (!SV_ENDS_WITH(arg_as_sv, ".c")) continue;

        sb file;
        libc_errno err = file_try_read(arg, &file);
        if (err > 0) PANICF("%s: %s", arg, strerror(err));

        stbds_arrput(stbds_arr_ccE_argv, arg);
        stbds_arrput(stbds_arr_files, file);
    }
    stbds_arrput(stbds_arr_cc_argv, 0);
    stbds_arrput(stbds_arr_ccE_argv, 0);

    stbds_arrput(stbds_arr_cc2_argv, cc);
    stbds_arrput(stbds_arr_cc2_argv, "-xc");
    stbds_arrput(stbds_arr_cc2_argv, "-");
    stbds_arrput(stbds_arr_cc2_argv, "-xnone");

    for (int i = 0; i < argc; i++) {
        char *arg = argv[i];

        if (arg[0] == '-') {
            stbds_arrput(stbds_arr_cc2_argv, arg);
            if (arg[1] == 'o') {
                stbds_arrput(stbds_arr_cc2_argv, argv[i + 1]);
                i += 1;
            }
            continue;
        }

        sv arg_as_sv = (sv){(void *)arg, strlen(arg)};
        if (SV_ENDS_WITH(arg_as_sv, ".c")) continue;

        stbds_arrput(stbds_arr_cc2_argv, arg);
    }
    stbds_arrput(stbds_arr_cc2_argv, 0);

    fputs("comptime: ", stderr);
    for (int i = 0; i < stbds_arrlen(stbds_arr_ccE_argv); i++)
        fprintf(stderr, "%s ", stbds_arr_ccE_argv[i]);
    fputc('\n', stderr);

    fputs("comptime: ", stderr);
    for (int i = 0; i < stbds_arrlen(stbds_arr_cc_argv); i++)
        fprintf(stderr, "%s ", stbds_arr_cc_argv[i]);
    fputc('\n', stderr);

    fputs("comptime: ", stderr);
    for (int i = 0; i < stbds_arrlen(stbds_arr_cc2_argv); i++)
        fprintf(stderr, "%s ", stbds_arr_cc2_argv[i]);
    fputc('\n', stderr);

    static unsigned char expanded_blob[0x100000] = {0};
    int expanded_blob_len = 0;

    {
        static int child_to_parent_fds[2] = {0};
        if (pipe(child_to_parent_fds) < 0) PANIC(strerror(errno));

        switch (fork()) {
        case -1:
            PANIC(strerror(errno));

        case 0:
            if (close(child_to_parent_fds[0]) < 0)
                PANIC(strerror(errno));
            if (dup2(child_to_parent_fds[1], STDOUT_FILENO) < 0)
                PANIC(strerror(errno));
            execvp(stbds_arr_ccE_argv[0], stbds_arr_ccE_argv);
            PANIC(strerror(errno));

        default:
            if (close(child_to_parent_fds[1]) < 0)
                PANIC(strerror(errno));

            unsigned char *read_cursor = expanded_blob;
            int remaining_size = sizeof(expanded_blob);
            while (1) {
                if (remaining_size == 0) PANIC("expanded blob buffer is full");
                int nbytes = read(child_to_parent_fds[0], read_cursor, remaining_size);
                if (nbytes == -1) PANIC(strerror(errno));
                else if (nbytes == 0) break;
                read_cursor += nbytes;
                remaining_size -= nbytes;
            }
            expanded_blob_len = read_cursor - expanded_blob;

            if (close(child_to_parent_fds[0]) < 0)
                PANIC(strerror(errno));

            int status;
            if (wait(&status) < 0)
                PANIC(strerror(errno));
            if (!WIFEXITED(status))
                PANIC("cc subprocess exited abnormally");
            if (WEXITSTATUS(status) != 0)
                PANIC("cc subprocess exited with non-zero status code");
        }
    }

    TSTree *tree = ts_parser_parse_string(parser, 0, (char *)expanded_blob, expanded_blob_len);
    TSNode root = ts_tree_root_node(tree);
    find_fundefs(root, expanded_blob);

    pid_t cc_pid;
    if (posix_spawnp(&cc_pid, stbds_arr_cc_argv[0], 0, 0, stbds_arr_cc_argv, envp) < 0)
        PANIC(strerror(errno));

    int status;
    if (wait(&status) < 0)
        PANIC(strerror(errno));
    if (!WIFEXITED(status))
        PANIC("cc subprocess exited abnormally");
    if (WEXITSTATUS(status) != 0)
        PANIC("cc subprocess exited with non-zero status code");

    void *dl = dlopen(so_fname, RTLD_LAZY);
    if (dl == 0) PANIC(dlerror());

    while (1) {
        sb *file;
        fncall fncall;
        TSNode callnode;
        bool callfound = false;

        // NOTE: Because subsequent iterations mutate the file buffers,
        //       we keep parsing the files until there is no more
        //       function calls to process.

        for (int i = 0; i < stbds_arrlen(stbds_arr_files); i++) {
            file = &stbds_arr_files[i];
            TSTree *tree = ts_parser_parse_string(parser, 0, file->ptrc, file->len);
            TSNode root = ts_tree_root_node(tree);

            callfound = next_fncall(root, file->ptr, &fncall, &callnode);
            if (callfound) break;
        }
        if (!callfound) break;

        fndef *def = 0;
        for (int i = 0; i < stbds_arrlen(stbds_arr_fndefs); i++) {
            fndef cur = stbds_arr_fndefs[i];
            if (sz_eql(cur.name, fncall.name)) {
                def = &stbds_arr_fndefs[i];
                break;
            }
        }
        if (def == 0)
            PANIC("found comptime function call without matching definition");

        void (*fn)(void) = dlsym(dl, def->name);
        if (fn == 0) PANIC(dlerror());

        ffi_cif cif = {0};
        ffi_status status;
        if (def->is_variadic) {
            ffi_type **stbds_arg_types = 0;

            int i = 0;
            for (; i < stbds_arrlen(def->stbds_arr_arg_types); i++)
                stbds_arrput(stbds_arg_types, def->stbds_arr_arg_types[i]);
            for (; i < stbds_arrlen(fncall.stbds_arr_arg_values); i++)
                stbds_arrput(stbds_arg_types, fncall.stbds_arr_arg_types[i]);

            status = ffi_prep_cif_var(
                &cif, FFI_DEFAULT_ABI,
                stbds_arrlen(def->stbds_arr_arg_types),
                stbds_arrlen(fncall.stbds_arr_arg_values),
                def->return_type,
                stbds_arg_types
            );
        } else {
            status = ffi_prep_cif(
                &cif, FFI_DEFAULT_ABI,
                stbds_arrlen(def->stbds_arr_arg_types),
                def->return_type,
                def->stbds_arr_arg_types
            );
        }
        if (status != FFI_OK) PANIC("couldn't prepare comptime function call");

        // NOTE: 'retval' is 64-bit long. We may want change that later.
        unsigned char retval[8] = {0};

        ffi_call(&cif, fn, retval, fncall.stbds_arr_arg_values);

        // HACK: Static string, assuming the rendered string doesn't overflow.
        static char replace[256];
        int replacelen;

        ffi_type *ffi_rettype = def->return_type;

        // TODO: 'ffi_type_pointer' is handled so badly.
        //       It only works for null-terminated strings.
        //       Maybe turn this into an array of bytes?

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
        else PANIC("unhandled return ffi type");

        if (replacelen > sizeof(replace))
            PANIC("buffer overflow occured while rendering comptime return value");

        int start = ts_node_start_byte(callnode);
        int end = ts_node_end_byte(callnode);
        sb_splice(file, start, end, replace, replacelen);

        // DEBUG
        // fprintf(stderr, "===\n%.*s\n===\n", file->len, file->ptrc);
    }

    if (expand) {
        if (stbds_arrlen(stbds_arr_funcs_to_run) > 0)
            fprintf(stderr, "%s: ignoring option '--run' because '--expand' was provided", program);

        for (int i = 0; i < stbds_arrlen(stbds_arr_files); i++) {
            sb file = stbds_arr_files[i];
            printf("%.*s\n", file.len, file.ptrc);
        }
    } else {
        static int parent_to_child_fds[2] = {0};
        if (pipe(parent_to_child_fds) < 0) PANIC(strerror(errno));

        switch (fork()) {
        case -1:
            PANIC(strerror(errno));

        case 0: {
            if (close(parent_to_child_fds[1]) < 0)
                PANIC(strerror(errno));
            if (dup2(parent_to_child_fds[0], STDIN_FILENO) < 0)
                PANIC(strerror(errno));
            execvp(stbds_arr_cc2_argv[0], stbds_arr_cc2_argv);
            PANIC(strerror(errno));
        } break;

        default:
            if (close(parent_to_child_fds[0]) < 0)
                PANIC(strerror(errno));
            for (int i = 0; i < stbds_arrlen(stbds_arr_files); i++) {
                sb file = stbds_arr_files[i];
                if (write(parent_to_child_fds[1], file.ptr, file.len) < 0)
                    PANIC(strerror(errno));
            }
            if (close(parent_to_child_fds[1]) < 0)
                PANIC(strerror(errno));

            int status;
            if (wait(&status) < 0)
                PANIC(strerror(errno));
            if (!WIFEXITED(status))
                PANIC("cc subprocess exited abnormally");
            if (WEXITSTATUS(status) != 0)
                PANIC("cc subprocess exited with non-zero status code");
        }
    }

    // NOTE: Incoming dangerous operation. Surely a previous check would
    //       have ensured that the shared object file is owned by us.

    if (remove(so_fname) < 0)
        PANIC(strerror(errno));

    return 0;
}
