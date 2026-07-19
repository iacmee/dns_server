#include "dns.h"

void worker_init(t_worker *worker, int core_id)
{
    worker->core_id = core_id;

    worker->epfd = epoll_create1(EPOLL_CLOEXEC);
    if (worker->epfd == 0)
    {
        perror("epoll_create1");
        _exit(1);
    }

    worker->client_sock = make_udp_socket_client(DNS_PORT);
    worker->upstream_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (worker->upstream_sock < 0)
    {
        perror("socket upstream");
        _exit(1);
    }
    // Non-blocking for upstream
    int flags = fcntl(worker->upstream_sock, F_GETFL, 0);
    fcntl(worker->upstream_sock, F_SETFL, flags | O_NONBLOCK);

    struct epoll_event ev;

    ev.events = EPOLLIN;
    ev.data.u32 = CLIENT_QUERIES;
    if (epoll_ctl(worker->epfd, EPOLL_CTL_ADD, worker->client_sock, &ev) < 0)
    {
        perror("epoll_ctl client");
        _exit(1);
    }

    ev.events = EPOLLIN;
    ev.data.u32 = UPSTREAM_RESPONSE;
    if (epoll_ctl(worker->epfd, EPOLL_CTL_ADD, worker->upstream_sock, &ev) < 0)
    {
        perror("epoll_ctl upstream");
        _exit(1);
    }


    worker->timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (worker->timerfd == -1)
    {
        perror("timerfd_create");
        _exit(1);
    }
    struct itimerspec its = {0};
    its.it_interval.tv_nsec = HTW_TICK_NS; // 10ms periodico
    its.it_value.tv_nsec    = HTW_TICK_NS; // prima scadenza tra 10ms
    timerfd_settime(worker->timerfd, 0, &its, NULL);
    htw_init(&worker->time_wheel);

    ev.events = EPOLLIN;
    ev.data.u32 = TIMERFD;
    if (epoll_ctl(worker->epfd, EPOLL_CTL_ADD, worker->timerfd, &ev) < 0)
    {
        perror("epoll_ctl upstream");
        _exit(1);
    }

    id_pool_init(&worker->id_pool);
    ctx_pool_init(&worker->ctx_pool);
    // memset(worker->formerr_blueprint, 0, sizeof(worker->formerr_blueprint));
    // t_dns *header = worker->formerr_blueprint;
    // (void)header;
    // header->qdcount = 1;
    // header->flags = htons(UPSTREAM_FLAG);

}

int main()
{
    pthread_t threads[NCPU];
    t_worker workers[NCPU];

    // TMP
    worker_init(&workers[0], 1);
    worker_entry_point(&workers[0]);

    // for (int i = 0; i < NCPU; ++i)
    // {
    //     worker_init(&workers[i], i);
    //     if (pthread_create(&threads[i], NULL, worker_entry_point, &workers[i]) != 0)
    //     {
    //         perror("pthread_create");
    //         _exit(1);
    //     }
    // }

    for (int i = 0; i < NCPU; ++i)
        pthread_join(threads[i], NULL);

    printf("all thread closed\n");
}