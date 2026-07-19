#include "dns.h"


void ctx_pool_init(t_ctx_pool *p)
{
    p->top = MAX_CTX;
    for (uint32_t i = 0; i < MAX_CTX; ++i)
        p->free_stack[i] = i;
}

t_query_context* ctx_pool_alloc(t_ctx_pool *p)
{
    if (p->top == 0)
        return (NULL);
    --p->top;
    uint32_t idx = p->free_stack[p->top];
    return (&p->ctx_arr[idx]);
}

void ctx_pool_free(t_ctx_pool *p, t_query_context *c)
{
    uint32_t idx = (uint32_t)(c - p->ctx_arr);
    p->free_stack[p->top] = idx;
    p->top++;
}