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
    /* @comptime */ fprintf(stderr, "AYAYA! %d\n", unsigned_add(45, unsigned_add(11, 13)));

    printf("Comptime PWD: %s\n", /* @comptime */ getenv("PWD"));
    printf("Runtime PWD:  %s\n", getenv("PWD"));

    return 0;
}
