#pragma once
#define _GNU_SOURCE // for CLOCK_MONOTONIC
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <math.h>
#include <time.h>

#ifndef HTW_LEVELS
#define HTW_LEVELS 4
#endif

#ifndef HTW_SIZE
#define HTW_SIZE 256u
#endif

#ifndef HTW_TICK_NS
#define HTW_TICK_NS (10ULL * 1000 * 1000) // 10 ms in nanosecond
#endif

// For power-of-two wheels this is the natural mask.
// (If HTW_SIZE is not power-of-two, HTW_MASK won't be used in the generic path.)
#define HTW_MASK (HTW_SIZE - 1u)

/**
 * if this asserction fail we coud simply redefine the struct htw_timer,
 * int particulare slot and levels camp shoud not be > 8 bit.
 * note that could be increase pre allocated memory and introduce padding
 */
_Static_assert(HTW_LEVELS <= 256, "in htw_timer level is an 8 bit unsigned integer, can not have more then 256 levels");
_Static_assert(HTW_SIZE <= 256, "in htw_timer slot is an 8 bit unsigned integer, can not have more then 256 slot");

_Static_assert(HTW_LEVELS >= 1, "HTW_LEVELS must be >= 1");
_Static_assert(HTW_SIZE >= 2, "HTW_SIZE must be >= 2");

_Static_assert((HTW_SIZE != 256u) || (HTW_MASK != 0xFFu) || (HTW_LEVELS < 8), "htw_slot_for function optimization required");

typedef void (*t_htw_cb)(void *arg); // 48 byte for no

typedef struct htw_timer
{
    // intrusive doubly-linked list within a bucket
    struct htw_timer *prev;
    struct htw_timer *next;

    // absolute expiry in "ticks"
    uint64_t expiry_tick;

    // callback
    t_htw_cb cb; // function pointer
    void *arg;

    // bookkeeping to allow O(1) cancel/remove
    uint8_t active;
    uint8_t level; // 0..HTW_LEVELS-1
    uint8_t slot;  // 0..255
    /* 16 bit padding for now */
} t_htw_timer;

typedef struct htw
{
    // current time in ticks
    uint64_t now_tick;

    // wheel buckets: [level][slot] -> head of list
    t_htw_timer *slots[HTW_LEVELS][HTW_SIZE];
} t_htw;

void htw_init(t_htw *w);
void htw_del(t_htw *w, t_htw_timer *t);
void htw_add(t_htw *w, t_htw_timer *t,
             uint64_t offset, t_htw_cb cb, void *arg);
void htw_advance(t_htw *w, uint64_t ticks);
uint64_t get_now_tick(void);

// uint8_t htw_choose_level(uint64_t delta);
// uint8_t htw_slot_for(uint64_t expiry_tick, uint8_t level);