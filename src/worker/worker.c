#include "dns.h"

void *worker_entry_point(void *arg)
{
    t_worker *worker = (t_worker *)arg;
    pin_to_cpu(worker->core_id);
    printf("worker bind to cpu n° %d\n", worker->core_id);

    worker_loop(worker);

    close(worker->client_sock);
    close(worker->epfd);
    printf("exit_worker\n");
    return (NULL);
}