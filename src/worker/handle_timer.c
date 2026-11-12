#include "dns.h"

void handle_timer(t_worker *worker)
{
    uint64_t expirations;

    if (read(worker->timerfd, &expirations, sizeof(expirations)) != sizeof(expirations))
        return;

    // expirations is the number of elapsed ticks
    htw_advance(&worker->time_wheel, expirations);   
}