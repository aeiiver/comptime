INCS := -Iexternal/tree-sitter-0.22.2/lib/include/ -Iexternal/libffi-3.4.6/build/usr/include/
LIBS := external/tree-sitter-0.22.2/libtree-sitter.a external/tree-sitter-c-0.20.7/src/parser.o external/libffi-3.4.6/build/usr/lib/libffi.a

comptime: comptime.c external/tree-sitter-0.22.2/libtree-sitter.a external/tree-sitter-c-0.20.7/src/parser.o
	cc -g3 -std=gnu99 -Wmissing-prototypes $(INCS) comptime.c $(LIBS)

external/tree-sitter-0.22.2/libtree-sitter.a:
	cd external/tree-sitter-0.22.2/; \
		make

external/tree-sitter-c-0.20.7/src/parser.o:
	cd external/tree-sitter-c-0.20.7/src/; \
		cc -c parser.c

external/libffi-3.4.6/build/usr/lib/libffi.a:
	cd external/libffi-3.4.6/;            \
		make build;                       \
		cd build;                         \
		../configure --prefix=$(PWD)/usr; \
		make && make install
