#pragma once
#define _GNU_SOURCE // for sched.h and cpu affinity
#include <stdio.h>
#include <arpa/inet.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sched.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <limits.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/timerfd.h>
#include <stdalign.h>
#include <ldns/ldns.h>

#include "timing_wheel.h"
#include "logger.h"

#define DNS_PORT 53
#define MAX_EPOLL_EVENT (8192 / sizeof(struct epoll_event)) // 1024 richieste massime
#define QUERIES_BUFFER 4096UL                                 // 4 KB
#define MINUMUM_HEADER_SIZE 12
#define MAX_QNAME_LEN 256
#define MAX_CTX 8192
#define MAX_COMPRESSION_JUMP 5
#define MAX_LABLE_LEN 63
#define MAX_LEN_IP_TO_TRY 1 
#define FORMERR_BLUEPRINT_SIZE sizeof(t_dns)
#define MAX_TICK_WAIT 200 // 2 seconds

#define RETURN_ON_ERROR(expression)       \
    do                                    \
    {                                     \
        int _error_code = (expression);    \
        if (_error_code != 0)              \
            return (_error_code);          \
    } while (0)

#define IP_AROOT 0xC6290004 // 198.41.0.4
/*
0   1 2 3 4   5  6  7  8  9 10 11  12 13 14 15
+--+---------+--+--+--+--+--------+-----------+
|QR| Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
+--+---------+--+--+--+--+--------+-----------+
*/
/**
 * QR: 1 bit per indicare se è una query o una response (1 è response)
 * OPCODE: il tipo di operazione
 * AA: solo nelle risposte è autoritativo per quella zona o no
 * TC: il messaggio è troncato o no
 * RD: recursion desired
 * RA: recursion avaliable
 * Z: reseved, not in use
 * RCODE: returned code (0) NOERROR
 */

#define UPSTREAM_FLAG (0)
// è una query, quindi
#define DNS_FLAG_QR 0x8000 /* bit 15 */
#define DNS_FLAG_AA 0x0400 /* bit 10 */
#define DNS_FLAG_TC 0x0200 /* bit 9  */
#define DNS_FLAG_RD 0x0100 /* bit 8  */
#define DNS_FLAG_RA 0x0080 /* bit 7  */

#define DNS_OPCODE_MASK 0x7800 /* bits 14..11 */
#define DNS_RCODE_MASK 0x000F  /* bits 3..0  */

#define DNS_IS_RESPONSE(f) (((f) & DNS_FLAG_QR) != 0)
#define DNS_IS_QUERY(f) (((f) & DNS_FLAG_QR) == 0)

#define DNS_IS_AA(f) (((f) & DNS_FLAG_AA) != 0)
#define DNS_IS_TC(f) (((f) & DNS_FLAG_TC) != 0)
#define DNS_IS_RD(f) (((f) & DNS_FLAG_RD) != 0)
#define DNS_IS_RA(f) (((f) & DNS_FLAG_RA) != 0)

#define DNS_GET_OPCODE(f) (((f) & DNS_OPCODE_MASK) >> 11)
#define DNS_OPCODE_QUERY 0
#define DNS_OPCODE_IQUERY 1
#define DNS_OPCODE_STATUS 2
#define DNS_OPCODE_UPDATE 5
#define DNS_GET_RCODE(f) ((f) & DNS_RCODE_MASK)
#define DNS_RCODE_NOERROR 0
#define DNS_RCODE_FORMERR 1
#define DNS_RCODE_SERVFAIL 2
#define DNS_RCODE_NXDOMAIN 3
#define DNS_RCODE_NOTIMP 4
#define DNS_RCODE_REFUSED 5

#define DNS_SET_FLAG(f, flag) ((f) |= (flag))
#define DNS_CLR_FLAG(f, flag) ((f) &= ~(flag))
#define DNS_SET_OPCODE(f, op)      \
    do                             \
    {                              \
        (f) &= ~DNS_OPCODE_MASK;   \
        (f) |= ((op & 0xF) << 11); \
    } while (0)
#define DNS_SET_RCODE(f, rc)    \
    do                          \
    {                           \
        (f) &= ~DNS_RCODE_MASK; \
        (f) |= (rc & 0xF);      \
    } while (0)

/* DNS QTYPE (RR TYPE) values */
#define DNS_QTYPE_A 1     /* IPv4 address */
#define DNS_QTYPE_NS 2    /* Name Server */
#define DNS_QTYPE_CNAME 5 /* Canonical Name */
#define DNS_QTYPE_SOA 6   /* Start Of Authority */
#define DNS_QTYPE_PTR 12  /* Pointer (reverse) */
#define DNS_QTYPE_MX 15   /* Mail eXchanger */
#define DNS_QTYPE_TXT 16  /* Text */
#define DNS_QTYPE_AAAA 28 /* IPv6 address */

typedef struct s_dns
{
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount; // numero di domande (valido solo quando invio)
    uint16_t ancount; // numero di risposte vere (valido solo nelle risposte)
    uint16_t nscount; // numero di risposte authority (valido solo nelle risposte) (a chi devo chiedere per avere la risposta)
    uint16_t arcount; // numero di sezioni aggiuntive (valido solo nelle risposte oppure per impostazione nelle query)
} t_dns;

typedef enum
{
    RES_STATE_NEW = 0,
    RES_STATE_WAIT_UPSTREAM,
    RES_STATE_DONE,
    RES_STATE_FAILED,
    RES_STATE_EXPIRED
} res_state_t;

typedef struct s_query_context
{
    t_htw_timer timer;
    struct s_worker *worker;
    uint16_t upstream_id;

    char qname[MAX_QNAME_LEN];
    uint16_t qtype;
    uint16_t qclass;

    uint16_t query_id;
    uint8_t qname_len;

    uint8_t ua_count;
    struct sockaddr_in up_addrs[MAX_LEN_IP_TO_TRY];
    
    struct sockaddr_in origin_addr;
    socklen_t oa_len;
    uint8_t is_recursive;
    uint8_t try;
    /* 2 byte padding */

    /* puntatore usato nel caso debba risolvere un'altro dominio per quella query*/
    struct s_query_context *query_ref;

    // Puntatore a prossimo elemento in bucket hash
    struct ResolutionContext *next_hash;
} t_query_context;

typedef struct s_ctx_poll
{
    t_query_context ctx_arr[MAX_CTX];
    uint32_t free_stack[MAX_CTX];
    uint32_t top; // numero di elementi nello stack
} t_ctx_pool;

typedef struct
{
    t_query_context *id_arr[UINT16_MAX + 1u];
    uint16_t stack[UINT16_MAX + 1u];
    uint32_t top; // numero di elementi disponibili
} t_id_pool;

typedef struct s_worker
{
    struct sockaddr_in upstream_addr;
    int core_id;       // num of cpu will bind
    int epfd;          // epoll file descriptor
    int client_sock;   // socket bind with port 53;
    int upstream_sock; // socket for upstream internal queries
    int timerfd;
    t_id_pool id_pool;
    t_ctx_pool ctx_pool;
    t_htw time_wheel;
    uint8_t formerr_blueprint[FORMERR_BLUEPRINT_SIZE];
} t_worker;

// se voglio mandare più richieste in contemporanea modifico il contex
// typedef struct {
//   uint16_t id;
//   sockaddr_storage ns_addr;
//   uint64_t deadline_ns;
//   uint8_t  active;
// } inflight_t;

// inflight_t inflight[2 or 4];  // hedging

void pin_to_cpu(int cpu);
int make_udp_socket_client(uint16_t port);
void *worker_entry_point(void *arg);
void worker_loop(t_worker *worker);

void handle_client_queries(t_worker *worker);
void handle_upstream_response(t_worker *worker);
void dns_print_message(const void *data, size_t len, FILE *out);
const char *ipv4_to_string(uint32_t address);

int64_t timespec_to_ms(const struct timespec *ts);
int64_t get_time_ms(void);

t_query_context *ctx_pool_alloc(t_ctx_pool *p);
void ctx_pool_init(t_ctx_pool *p);
void ctx_pool_free(t_ctx_pool *p, t_query_context *c);

void id_pool_free(t_id_pool *p, uint16_t id);
void id_pool_init(t_id_pool *p);
bool id_pool_alloc(t_id_pool *p, uint16_t *out);
bool dns_read_name(const uint8_t *msg, size_t msg_len, ssize_t *offset,
                   unsigned char *out, size_t out_len);
int dns_encode_name(const char *domain, uint8_t *out, size_t out_len, size_t *offset);

void hande_expired_contex(void *arg);
void handle_timer(t_worker *worker);
void ntoh_dns_header(t_dns *header);
void hton_dns_header(t_dns *header);
bool skip_name(unsigned char buf[QUERIES_BUFFER], ssize_t byte_read, ssize_t *pos);


#define CLIENT_QUERIES 1
#define UPSTREAM_RESPONSE 2
#define TIMERFD 3

// tmp things
#define NCPU 1
extern volatile sig_atomic_t server_running;
int parse_queries(t_worker *worker, int fd);
void release_query(t_query_context *context);
