#include <stdint.h>

void mayo_memset(void *dst, uint8_t val, uint32_t len)
{
    uint8_t *d = dst;

    for (uint32_t i = 0; i < len; i++)
        d[i] = val;
}

void mayo_memcpy(void *dst, const void *src, uint32_t len)
{
    uint8_t *d = dst;
    const uint8_t *s = src;

    for (uint32_t i = 0; i < len; i++)
        d[i] = s[i];
}