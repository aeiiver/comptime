#include <stdio.h>
#include <stdlib.h>

unsigned int unsigned_add(unsigned int, unsigned int);

unsigned int
unsigned_add(unsigned int a, unsigned int b)
{
    return a + b;
}

int
main(void)
{
    /* @comptime */ 11;

    printf("Comptime PWD: %s\n", /* @comptime */ "/home/foo/nnhr/comptime");
    printf("Runtime PWD:  %s\n", getenv("PWD"));

    return 0;
}

