INCS := -Iexternal/tree-sitter-0.22.2/lib/include/ \
		-Iexternal/libffi-3.4.6/build/usr/include/

LIBS := external/tree-sitter-0.22.2/libtree-sitter.a \
		external/tree-sitter-c-0.20.7/src/parser.o   \
		external/libffi-3.4.6/build/usr/lib/libffi.a

SRCS := comptime.c $(LIBS)

# Not using '-Wpedantic'. For now, we're making sure we have support
# for GCC and Clang.

comptime: $(SRCS)
	$(CC) -o comptime -g3 -std=c99 -Wmissing-prototypes \
		$(INCS) $(SRCS)

test_selfhost: comptime
	./comptime -- -o test_selfhost -std=c99 -Wmissing-prototypes \
		$(INCS) comptime.c                           \
		external/tree-sitter-0.22.2/libtree-sitter.a \
		external/tree-sitter-c-0.20.7/src/parser.o   \
		external/libffi-3.4.6/build/usr/lib/libffi.so

test_selfhost2: test_selfhost
	./test_selfhost -- -o test_selfhost2 -std=c99 -Wmissing-prototypes \
		$(INCS) comptime.c                           \
		external/tree-sitter-0.22.2/libtree-sitter.a \
		external/tree-sitter-c-0.20.7/src/parser.o   \
		external/libffi-3.4.6/build/usr/lib/libffi.so
	diff -s test_selfhost test_selfhost2

external/tree-sitter-0.22.2/libtree-sitter.a:
	cd external/tree-sitter-0.22.2/; \
		make

external/tree-sitter-c-0.20.7/src/parser.o:
	cd external/tree-sitter-c-0.20.7/src/; \
		$(CC) -c parser.c

external/libffi-3.4.6/build/usr/lib/libffi.a:
	cd external/libffi-3.4.6/;                          \
		mkdir build;                                    \
		cd build;                                       \
		../configure --prefix=$$PWD/usr --disable-docs; \
		make && make install
