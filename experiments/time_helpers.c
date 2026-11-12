#include "dns.h"

// int64_t timespec_to_ms(const struct timespec *ts)
// {
//     int64_t ms;
//     ms = (int64_t)ts->tv_sec * 1000LL; // convert sec to millisecond
//     ms += (int64_t)(ts->tv_nsec / 1000000L); // convert nanosecond to millisecond
//     return (ms);
// }

// int64_t get_time_ms(void)
// {
//     struct timespec ts;
//     clock_gettime(CLOCK_MONOTONIC, &ts);
//     return (timespec_to_ms(&ts));
// }
