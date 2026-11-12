#include "dns.h"

volatile sig_atomic_t server_running = 1;

static void stop_server(int signo)
{
    (void)signo;
    server_running = 0;
}

static int parse_port(const char *text)
{
    char *end;
    errno = 0;
    long port = strtol(text, &end, 10);
    if (errno || !*text || *end || port < 1 || port > 65535)
        return -1;
    return (int)port;
}

int main(int argc, char **argv)
{
    int port = 5353;
    int upstream_port = 53;
    const char *upstream = "1.1.1.1";
    if (argc == 2 && strcmp(argv[1], "--help") == 0)
    {
        printf("Usage: %s [listen-port [upstream-ipv4 [upstream-port]]]\n"
               "Defaults: 127.0.0.1:5353 -> 1.1.1.1:53 (UDP)\n", argv[0]);
        return 0;
    }
    if (argc > 4 || (argc > 1 && (port = parse_port(argv[1])) < 0)
        || (argc > 3 && (upstream_port = parse_port(argv[3])) < 0))
    {
        fprintf(stderr, "Invalid arguments; use --help\n");
        return 1;
    }
    if (argc > 2)
        upstream = argv[2];
    t_worker *worker = calloc(1, sizeof(*worker));
    if (!worker)
        return 1;
    worker->upstream_addr.sin_family = AF_INET;
    worker->upstream_addr.sin_port = htons((uint16_t)upstream_port);
    if (inet_pton(AF_INET, upstream, &worker->upstream_addr.sin_addr) != 1)
    {
        fprintf(stderr, "Invalid upstream IPv4 address\n");
        free(worker);
        return 1;
    }
    worker->epfd = epoll_create1(EPOLL_CLOEXEC);
    worker->client_sock = make_udp_socket_client((uint16_t)port);
    worker->upstream_sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    worker->timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (worker->epfd < 0 || worker->upstream_sock < 0 || worker->timerfd < 0)
    {
        perror("initialization");
        return 1;
    }
    /* A connected UDP socket accepts datagrams only from the selected resolver. */
    if (connect(worker->upstream_sock, (struct sockaddr *)&worker->upstream_addr,
                sizeof(worker->upstream_addr)) < 0)
    {
        perror("connect upstream");
        return 1;
    }
    int fds[] = {worker->client_sock, worker->upstream_sock, worker->timerfd};
    for (unsigned i = 0; i < 3; ++i)
    {
        struct epoll_event event = {.events = EPOLLIN, .data.u32 = i + 1};
        if (epoll_ctl(worker->epfd, EPOLL_CTL_ADD, fds[i], &event) < 0)
        {
            perror("epoll_ctl");
            return 1;
        }
    }
    struct itimerspec timer = {0};
    timer.it_interval.tv_nsec = HTW_TICK_NS;
    timer.it_value.tv_nsec = HTW_TICK_NS;
    htw_init(&worker->time_wheel);
    if (timerfd_settime(worker->timerfd, 0, &timer, NULL) < 0)
    {
        perror("timerfd_settime");
        return 1;
    }
    id_pool_init(&worker->id_pool);
    ctx_pool_init(&worker->ctx_pool);
    struct sigaction action = {0};
    action.sa_handler = stop_server;
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    LOG_INFO("Listening on 127.0.0.1:%d -> %s:%d (UDP)", port, upstream, upstream_port);
    worker_loop(worker);
    for (unsigned i = 0; i < 3; ++i)
        close(fds[i]);
    close(worker->epfd);
    free(worker);
    return 0;
}
