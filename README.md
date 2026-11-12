# DNS server — work in progress

An educational C project for Linux. The current version is a **UDP DNS
forwarder**: it accepts local queries, forwards them to a configurable resolver,
and returns the response to the client. Independent iterative resolution from
root servers is still incomplete; drafts are kept in `experiments/` and excluded
from the build.

## Requirements and build

Linux (the server uses `epoll` and `timerfd`), a C11 compiler, Make, pkg-config,
and ldns. On Debian/Ubuntu:

```sh
sudo apt install build-essential pkg-config libldns-dev python3 dnsutils
make
```

`python3` is required for tests; `dnsutils` provides `dig` for manual checks.
The compiled program is `./main`. `make clean` removes object files;
`make fclean` also removes the executable; `make re` rebuilds from scratch.

## Running

```sh
./main
```

By default, the server listens on **127.0.0.1:5353** and forwards queries to
**1.1.1.1:53**. Root privileges are not required. Querying the public resolver
requires outbound UDP Internet connectivity.

```sh
dig @127.0.0.1 -p 5353 example.com A
dig @127.0.0.1 -p 5353 example.com AAAA
```

Positional configuration:

```sh
./main [listen-port [upstream-ipv4 [upstream-port]]]
./main 8053 8.8.8.8 53
./main --help
```

The server always binds to IPv4 loopback. Ports below 1024 may require
additional privileges. Stop it with `Ctrl+C` or `SIGTERM`.

## Current features

- An event loop with nonblocking sockets, `epoll`, and `timerfd`.
- Packet parsing with ldns and one question per query.
- A pool of up to 8192 pending queries, separate upstream IDs, and restoration
  of the original client ID.
- Forwarding of the original packet, including an allowed EDNS option;
  preservation of upstream response codes, including NXDOMAIN.
- An upstream socket connected to the selected resolver, with question name,
  type, and class checked before accepting a response.
- A timeout of approximately two seconds, returning SERVFAIL and releasing
  query resources.
- FORMERR/NOTIMP responses for malformed requests or unsupported operations;
  datagrams that are too short, too large, or already marked as responses
  are discarded.

## Tests

```sh
make test
```

The tests do not require Internet access. They start a simulated UDP resolver
on loopback and check A/AAAA forwarding, IDs, NXDOMAIN, rejection of responses
with mismatched questions, malformed input, repeated timeouts, service recovery,
and clean shutdown. A C test also checks timing wheel expiration, cancellation,
and cascading. GitHub Actions builds and tests every push and pull request.

## Project structure

- `src/main.c`: configuration, initialization, and shutdown.
- `src/worker/`: query reception, event loop, and timeouts.
- `src/handle_upstream_response.c`: response validation and forwarding.
- `src/Hierarchical_Timing_Wheel/`: timers for pending queries.
- `src/utils/`: context and ID pools, utilities, and DNS message printing.
- `src/logger/`, `include/`: logging and shared declarations.
- `tests/`: automated local tests.
- `experiments/`: historical, incomplete drafts excluded from the Makefile.

## Limitations and next steps

This is a prototype for local development, not a production-ready resolver.
It does not implement caching, full iterative resolution, DNSSEC validation,
TCP or TCP fallback for truncated responses, IPv6 transport, DoT/DoH,
resolver retries or failover, rate limiting, or multiple workers.
The UDP buffer is limited to 4096 bytes; queries with compressed QNAMEs are
not accepted, and at most one additional record is allowed.
New requests are discarded when the context pool is exhausted.
IDs use a noncryptographic pseudorandom shuffle.
The next priorities are completing iterative resolution, adding caching and
TCP fallback, and improving load handling.
