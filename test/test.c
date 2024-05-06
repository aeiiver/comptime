#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

static int primes[4269] = /* @comptime:compute_primes() */ {0};

unsigned int unsigned_add(unsigned int, unsigned int);
char *compute_primes(void);

unsigned int
unsigned_add(unsigned int a, unsigned int b)
{
    return a + b;
}

char *
compute_primes(void)
{
    static char buffer[0x10000] = {0};
    int len = 0;
    len += sprintf(buffer + len, "{");

    int count = 0;
    int next = 2;
    for (int i = 0; i < sizeof(primes)/sizeof(*primes); i++) {
        for (;; next++) {
            bool is_prime = true;
            for (int j = 0; j < count; j++) {
                if (next % primes[j] == 0) {
                    is_prime = false;
                    break;
                }
            }
            if (is_prime) break;
        }
        len += sprintf(buffer + len, "%d,", next);
        primes[i] = next;
        next++;
        count++;
    }

    len += sprintf(buffer + len, "}");
    return buffer;
}

int
main(void)
{
    /* @comptime */ fprintf(stderr, "AYAYA! %d\n", unsigned_add(45, unsigned_add(11, 13)));

    printf("Comptime PWD: %s\n", /* @comptime */ getenv("PWD"));
    printf("Runtime PWD:  %s\n", getenv("PWD"));

    printf("%d", primes[0]);
    for (int i = 1; i < sizeof(primes)/sizeof(*primes); i++)
        printf(", %d", primes[i]);
    puts("");

    return 0;
}
