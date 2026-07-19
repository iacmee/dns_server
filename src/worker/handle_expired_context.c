#include "dns.h"

void hande_expired_contex(void *arg)
{
    t_query_context *context = (t_query_context *)arg;

    (void)context;
    printf("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n");
    // htw_del(&worker->time_wheel, &context->timer);
    // id_pool_free(&worker->id_pool, context->);
    // ctx_pool_free(&worker->ctx_pool, context);
}