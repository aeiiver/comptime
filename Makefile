CFLAGS := -std=gnu99 -Wmissing-prototypes
INCS   := -Isrc/external/tree-sitter-0.22.1/lib/include/
LIBS   := src/external/tree-sitter-0.22.1/libtree-sitter.a src/external/tree-sitter-c-0.20.7/src/parser.o

build/comptime: $(LIBS) src/comptime.c
	mkdir -p build
	cc -g3 $(CFLAGS) $(INCS) -o build/comptime src/comptime.c $(LIBS)

src/external/tree-sitter-c-0.20.7/src/parser.o:
	cc -c -o src/external/tree-sitter-c-0.20.7/src/parser.o src/external/tree-sitter-c-0.20.7/src/parser.c

src/external/tree-sitter-0.22.1/libtree-sitter.a:
	cd src/external/tree-sitter-0.22.1/ && make
