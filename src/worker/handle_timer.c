#include "dns.h"

void handle_timer(t_worker *worker)
{
    uint64_t expirations;

    if (read(worker->timerfd, &expirations, sizeof(expirations)) != sizeof(expirations))
        return;

    // expirations = how many tick ar passed
    htw_advance(&worker->time_wheel, expirations);   
}