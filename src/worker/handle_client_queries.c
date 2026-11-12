#include "dns.h"

void handle_client_queries(t_worker *worker)
{
    (void)parse_queries(worker, worker->client_sock);
}
