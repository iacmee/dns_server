#include "timing_wheel.h"

void htw_list_push(t_htw_timer **head, t_htw_timer *n)
{
    n->prev = NULL;
    n->next = *head;
    if (*head)
        (*head)->prev = n;
    *head = n;
}

void htw_list_remove(t_htw_timer **head, t_htw_timer *n)
{
    if (n->prev)
        n->prev->next = n->next;
    else
        *head = n->next;
    if (n->next)
        n->next->prev = n->prev;
    n->prev = n->next = NULL;
}

void htw_init(t_htw *w)
{
    memset(w, 0, sizeof(*w));
    w->now_tick = get_now_tick();
}

uint8_t htw_choose_level(uint64_t delta)
{
// default level and size optimization
#if (HTW_LEVELS == 4) && (HTW_SIZE == 256u)
    if (delta < (1ull << 8))
        return 0;
    if (delta < (1ull << 16))
        return 1;
    if (delta < (1ull << 24))
        return 2;
    return 3;

    // HTW_SIZE is a power of 2
#elif (HTW_SIZE != 0u) && (((HTW_SIZE) & ((HTW_SIZE) - 1u)) == 0u)
    if (HTW_LEVELS == 1)
        return 0;

    const unsigned k = (unsigned)__builtin_ctzll((uint64_t)HTW_SIZE); // should be optimize at compile-time
    uint64_t threshold = (uint64_t)HTW_SIZE;

    for (unsigned i = 0; i < (unsigned)HTW_LEVELS - 1u; ++i)
    {
        if (delta < threshold)
            return (uint8_t)i;

        //  overflow check
        if (k == 0 || threshold > (UINT64_MAX >> k))
            threshold = UINT64_MAX;
        else
            threshold <<= k;
    }
    return (uint8_t)(HTW_LEVELS - 1);

#else
    // HTW_SIZE not power of 2
    if (HTW_LEVELS == 1)
        return 0;

    const uint64_t base = (uint64_t)HTW_SIZE;

    uint64_t threshold = base;
    for (unsigned i = 0; i < (unsigned)HTW_LEVELS - 1u; ++i)
    {
        if (delta < threshold)
            return (uint8_t)i;

        if (threshold > UINT64_MAX / base)
            threshold = UINT64_MAX;
        else
            threshold *= base;
    }
    return (uint8_t)(HTW_LEVELS - 1);
#endif
}

// Compute slot for a given expiry at a given level.
// Semantics (generic): slot = floor(expiry_tick / (HTW_SIZE^level)) % HTW_SIZE
uint8_t htw_slot_for(uint64_t expiry_tick, uint8_t level)
{
#if (HTW_SIZE == 256u) && (HTW_MASK == 0xFFu)
    return ((uint8_t)((expiry_tick >> (level * 8u)) & 0xFFu));

#elif ((HTW_SIZE & HTW_MASK) == 0u)
    // Fast path for any power-of-two HTW_SIZE: shift + mask (no div/mod)
    const unsigned k = (unsigned)__builtin_ctz((unsigned)HTW_SIZE); // log2(HTW_SIZE)
    unsigned shift = (unsigned)level * k;
    if (shift >= 64u)
        return (0);
    return ((uint8_t)((expiry_tick >> shift) & (uint64_t)(HTW_SIZE - 1u)));

#else
    // Generic path for non power-of-two: divide level times, then modulo.
    // Early-exit when t becomes 0.
    const uint64_t base = (uint64_t)HTW_SIZE;

    for (uint8_t i = 0; i < level && expiry_tick; ++i)
        expiry_tick /= base;

    return ((uint8_t)(expiry_tick % base));
#endif
}

void htw_del(t_htw *w, t_htw_timer *t)
{
    if (!t->active)
        return;
    t_htw_timer **head = &w->slots[t->level][t->slot];
    htw_list_remove(head, t);
    t->active = 0;
}

// Add or re-arm a timer to expire at absolute expiry_tick.
void htw_add(t_htw *w, t_htw_timer *t,
             uint64_t offset, t_htw_cb cb, void *arg)
{
    // If already armed, remove first (safe re-arm).
    if (t->active)
        htw_del(w, t);

    t->expiry_tick = w->now_tick + offset;
    t->cb = cb;
    t->arg = arg;

    uint64_t now = w->now_tick;
    uint64_t delta = (t->expiry_tick > now) ? (t->expiry_tick - now) : 0;

    uint8_t level = htw_choose_level(delta);
    uint8_t slot = htw_slot_for(t->expiry_tick, level);

    t->level = level;
    t->slot = slot;
    t->active = 1;

    htw_list_push(&w->slots[level][slot], t);
}

// ---------------- cascading ----------------

// Move all timers from a given [level][slot] bucket down into appropriate buckets
// according to their actual expiry_tick.
void htw_cascade_bucket(t_htw *w, uint8_t level, uint8_t slot)
{
    t_htw_timer *head = w->slots[level][slot];
    w->slots[level][slot] = NULL;

    while (head)
    {
        t_htw_timer *t = head;
        head = head->next;

        // detach from old bucket
        t->prev = NULL;
        t->next = NULL;
        t->active = 0;

        // reinsert based on current now and its expiry
        htw_add(w, t, t->expiry_tick, t->cb, t->arg);
    }
}

// ---------------- tick/run ----------------

// Process current tick:
// - advance now_tick
// - run L0 bucket for this tick
// - cascade higher levels when lower wraps
#include "stdio.h"
void htw_advance(t_htw *w, uint64_t ticks)
{
    while (ticks--)
    {
        w->now_tick++;

        const uint64_t now = w->now_tick;

        // 1) run timers in L0 bucket for "now"
#if ((HTW_SIZE & HTW_MASK) == 0u)
        uint8_t slot0 = (uint8_t)(now & HTW_MASK);
#else
        // floor(expiry_tick / (HTW_SIZE^level)) % HTW_SIZE
        uint8_t slot0 = (uint8_t)(now % HTW_SIZE);
#endif

        t_htw_timer *head = w->slots[0][slot0];
        w->slots[0][slot0] = NULL;

        while (head)
        {
            t_htw_timer *t = head;
            head = head->next;

            t->prev = t->next = NULL;
            t->active = 0;

            // Normally expiry_tick <= now here.
            // If quantization or reinsert happens, check and re-add if not due yet.
            // if (t->expiry_tick > now)
            // {
            //     htw_add(w, t, t->expiry_tick, t->cb, t->arg);
            //     continue;
            // }
            t->cb(t->arg);
        }

        // 2) cascading conditions
        // If lower wheel wrapped, cascade one bucket from next level.
        // Wrap points:
        // - every 256 ticks, cascade L1
        // - every 256^2 ticks, cascade L2
        // - every 256^3 ticks, cascade L3
#if (HTW_LEVELS == 4) && (HTW_SIZE == 256u)
        if (slot0 == 0)
        {
            uint8_t slot1 = (uint8_t)((now >> 8) & HTW_MASK);
            htw_cascade_bucket(w, 1, slot1);

            if ((slot1 == 0))
            {
                uint8_t slot2 = (uint8_t)((now >> 16) & HTW_MASK);
                htw_cascade_bucket(w, 2, slot2);

                if ((slot2 == 0))
                {
                    uint8_t slot3 = (uint8_t)((now >> 24) & HTW_MASK);
                    htw_cascade_bucket(w, 3, slot3);
                }
            }
        }

#elif ((HTW_SIZE & HTW_MASK) == 0u)
        const unsigned k = (unsigned)__builtin_ctz((unsigned)HTW_SIZE); // log2(HTW_SIZE)
        uint8_t cur_slot = slot0;
        for (unsigned i = 0; i < HTW_LEVELS - 1; ++i)
        {
            if (cur_slot = != 0)
                break;

            cur_slot = (uint8_t)((now >> (k * (i + 1))) & HTW_MASK);
            htw_cascade_bucket(w, i + 1, cur_slot);
        }
#else
        uint8_t cur_slot = slot0;
        for (unsigned i = 0; i < (unsigned)HTW_LEVELS - 1u; ++i)
        {
            if (cur_slot != 0)
                break;

            // compute div = HTW_SIZE^(i+1) using integers
            uint64_t div = 1;
            for (unsigned j = 0; j < i + 1u; ++j)
            {
                // overflow-safe multiply: if div would overflow, clamp to UINT64_MAX
                if (div > UINT64_MAX / (uint64_t)HTW_SIZE)
                {
                    div = UINT64_MAX;
                    break;
                }
                div *= (uint64_t)HTW_SIZE;
            }

            // slot at level (i+1): floor(now / HTW_SIZE^(i+1)) % HTW_SIZE
            cur_slot = (uint8_t)((now / div) % (uint64_t)HTW_SIZE);
            htw_cascade_bucket(w, (uint8_t)(i + 1u), cur_slot);
        }
#endif
    }
}

uint64_t get_now_tick(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
    return (ns / HTW_TICK_NS); // floor
}