#include "timing_wheel.h"
#include <assert.h>

static void fired(void *arg)
{
    ++*(unsigned *)arg;
}

int main(void)
{
    t_htw wheel;
    t_htw_timer timer = {0};
    unsigned calls = 0;
    htw_init(&wheel);
    wheel.now_tick = 0;
    htw_add(&wheel, &timer, 256, fired, &calls);
    htw_advance(&wheel, 255);
    assert(calls == 0);
    htw_advance(&wheel, 1);
    assert(calls == 1);
    htw_add(&wheel, &timer, 65536, fired, &calls);
    htw_advance(&wheel, 65535);
    assert(calls == 1);
    htw_advance(&wheel, 1);
    assert(calls == 2);
    htw_add(&wheel, &timer, 200, fired, &calls);
    htw_del(&wheel, &timer);
    htw_advance(&wheel, 300);
    assert(calls == 2);

    return (0);
}
