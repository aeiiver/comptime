#include <assert.h>
#include <stdio.h>

#include "comptime.h"

int main(void)
{
    puts("c: test: simple");
    {
        assert(42 == comptime_42());
        assert(69 == comptime_add3(13, 37, 19));
        assert('e' == comptime_get_second_char("hello"));
        assert('y' == comptime_get_second_char("ayaya"));
        assert('o' == comptime_get_last_char("hello"));
        assert('a' == comptime_get_last_char("ayaya"));
    }

    puts("c: test: compound");
    {
        assert(69 == comptime_add3(13, 37, comptime_add3(6, 6, 7)));
    }

    puts("c: test: io");
    {
        comptime_print_delayed("hello", 2);
        comptime_print_delayed("ayaya", 1);
        comptime_httpbin_postanything(comptime_env("VISUAL"), comptime_strlen(comptime_env("VISUAL")));
    }

    return 0;
}
