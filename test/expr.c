#include <string.h>

int comptime_42(void)
{
    return 42;
}

int comptime_add3(int a, int b, int c)
{
    return a + b + c;
}

char comptime_get_second_char(char *s)
{
    return s[0] && s[1] ? s[1] : 0;
}

char comptime_get_last_char(char *s)
{
    for (; s[1];) s += 1;
    return s[0];
}

int comptime_strlen(char *s)
{
    return strlen(s);
}
