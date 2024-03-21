#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

void comptime_print(char *);
unsigned int comptime_unsigned_add(unsigned int, unsigned int);
char *comptime_getenv(char *);

void
comptime_print(char *s)
{
    puts(s);
}

unsigned int
comptime_unsigned_add(unsigned int a, unsigned int b)
{
    return a + b;
}

char *
comptime_getenv(char *key)
{
    return getenv(key);
}

int
main(void)
{
    comptime_print("AYAYA!");

    assert(comptime_unsigned_add(45, comptime_unsigned_add(11, 13)) == 69);
    puts(comptime_getenv("PWD"));

    return 0;
}
