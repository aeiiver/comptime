#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char *comptime_env(char *s)
{
    return getenv(s);
}

void comptime_print_delayed(char *s, int secs)
{
    sleep(secs);
    puts(s);
}

void comptime_httpbin_postanything(char *data, int len)
{
    curl_global_init(0);

    int nlen = sizeof("vi=") - 1 + len;
    char *vi = malloc(nlen + 1);
    memcpy(vi, "vi=", 3);
    memcpy(vi + 3, data, len);
    vi[nlen] = 0;
    puts(vi);

    CURL *handle = curl_easy_init();
    curl_easy_setopt(handle, CURLOPT_URL, "https://httpbin.org/anything");
    curl_easy_setopt(handle, CURLOPT_POSTFIELDS, vi);
    int err = curl_easy_perform(handle);

    curl_global_cleanup();
}
