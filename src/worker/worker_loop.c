#include "dns.h"

void worker_loop(t_worker *worker)
{
    struct epoll_event events[MAX_EPOLL_EVENT];

    while (server_running)
    {
        int n_event = epoll_wait(worker->epfd, events, MAX_EPOLL_EVENT, 250);
        if (n_event < 0)
        {
            if (errno == EINTR)
                continue;
            perror("epoll_wait");
            continue;
        }

        for (int i = 0; i < n_event; ++i)
        {
            uint32_t tag = events[i].data.u32;

            if (tag == UPSTREAM_RESPONSE)
                handle_upstream_response(worker);
            else if (tag == CLIENT_QUERIES)
                handle_client_queries(worker);
            else if (tag == TIMERFD)
                handle_timer(worker);
            else
            {
                printf("tag != 1");
                _exit(1);
            }
        }
    }
}