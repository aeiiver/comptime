#include <assert.h>
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
    /* @comptime */ puts("AYAYA!");

    assert(/* @comptime */ unsigned_add(45, unsigned_add(11, 13)) == 69);
    puts(/* @comptime */ getenv("PWD"));

    return 0;
}
