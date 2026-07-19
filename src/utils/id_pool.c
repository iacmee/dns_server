#include "dns.h"

static inline uint32_t xorshift32(uint32_t *s)
{
    uint32_t x = *s;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *s = x;
    return x;
}

static void id_pool_init_shuffled(t_id_pool *p, uint32_t seed)
{
    p->top = UINT16_MAX;
    for (uint32_t i = 0; i < UINT16_MAX; ++i)
        p->stack[i] = (uint16_t)i;

    // Fisher–Yates
    uint32_t rng = seed ? seed : 0x12345678u;
    for (uint32_t i = UINT16_MAX - 1; i > 0; --i)
    {
        uint32_t j = xorshift32(&rng) % (i + 1);
        uint16_t tmp = p->stack[i];
        p->stack[i] = p->stack[j];
        p->stack[j] = tmp;
    }
}

void id_pool_init(t_id_pool *p)
{
    memset(p->id_arr, 0, sizeof(*p->id_arr) * UINT16_MAX);
    // to randomize id
    id_pool_init_shuffled(p, time(NULL));
}

bool id_pool_alloc(t_id_pool *p, uint16_t *out)
{
    if (p->top == 0)
        return (true); // nessun ID libero
    *out = p->stack[--p->top];
    return (false);
}

void id_pool_free(t_id_pool *p, uint16_t id)
{
    p->stack[p->top] = id;
    p->top++;
}