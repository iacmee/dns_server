#include "dns.h"

void handle_client_queries(t_worker *worker)
{
    // devo leggere e decifrare

    unsigned char buf[QUERIES_BUFFER];

    struct sockaddr_in origin_addr;
    socklen_t peer_len = sizeof(origin_addr);
    int byte_read = recvfrom(worker->client_sock, buf, sizeof(buf), 0, (struct sockaddr *)&origin_addr, &peer_len);
    if (byte_read < 0)
    {
        perror("recvfrom");
        _exit(1);
    }
    if (byte_read < MINUMUM_HEADER_SIZE)
    {
        printf("byte_read < 12\n");
        _exit(1);
    }

    // dns_print_message(buf, sizeof(buf), stdout);

    // verifiche
    t_dns *header = (t_dns *)buf;
    uint16_t flag = ntohs(header->flags);
#define QUERY_FLAG_MASK 0b1111101001010000
////////////////////////0b1000010110000000
////////////////////////0b1000000000000000
#define QUERY_FLAG 0b1000000000000000
    if ((flag & QUERY_FLAG_MASK) != 0 || ntohs(header->qdcount) != 1)
    {
        // devo inviare formerr
        DNS_SET_FLAG(flag, DNS_FLAG_QR);
        DNS_CLR_FLAG(flag, DNS_FLAG_AA);
        DNS_CLR_FLAG(flag, DNS_FLAG_TC);
        DNS_SET_FLAG(flag, DNS_FLAG_RA);
        DNS_SET_RCODE(flag, DNS_RCODE_FORMERR);
        header->flags = htons(flag);
        if (sendto(worker->client_sock, buf, byte_read, 0, (struct sockaddr *)&origin_addr, peer_len) < 0)
            perror("sendto");
    }

    // adesso costruiamo la query che noi dobbiamo fare
    // prendiamo un context libero
    t_query_context *context = ctx_pool_alloc(&worker->ctx_pool);
    if (context == NULL)
    {
        fprintf(stderr, "context is NULL\n");
        _exit(1);
    }
    memset(context, 0, sizeof(*context));
    if (DNS_IS_RD(flag))
        context->is_recursive = 1;
    else
        context->is_recursive = 0;
    // prendiamo un id libero
    uint16_t id_from_pool;
    if (id_pool_alloc(&worker->id_pool, &id_from_pool))
    {
        fprintf(stderr, "no id free\n");
        _exit(1);
    }
    worker->id_pool.id_arr[id_from_pool] = context;
    printf("messo l'id : %x\n", id_from_pool);
    int32_t pos = sizeof(*header);
    while (pos < byte_read && buf[pos] != 0)
        pos += buf[pos] + 1;
    ++pos;
    if (pos + 4 > byte_read)
    {
        // deve mandare formerr
        printf("ehehehehfweve\n");
        _exit(1);
    }
    context->qname_len = pos - sizeof(*header);
    memcpy(context->qname, buf + sizeof(*header), context->qname_len);
    context->qtype = ntohs(*(uint16_t *)(buf + pos));
    pos += 2;
    context->qclass = ntohs(*(uint16_t *)(buf + pos));
    pos += 2;
    context->query_id = ntohs(header->id);
    context->ua_count = 0;
    context->origin_addr = origin_addr;
    context->oa_len = peer_len;
    fprintf(stderr, "family=%d port=%u ip=%08x\n",
            context->origin_addr.sin_family,
            ntohs(context->origin_addr.sin_port),
            ntohl(context->origin_addr.sin_addr.s_addr));

    // ho riempito contex ora devo effettivamente inviare una richiesta all'upstream
    // per fare una richiesa ho bisogno di:
    /**
     * -un ip a cui mandarla (con una porta standard)
     * -un id univoco
     * -le flag giuste (da capire)
     * -encodato il nome
     * -il qtype
     * -il qname
     * -il qclass
     *
     * ad una funzione posso mandare il context
     */
    header->id = htons(id_from_pool);
    header->flags = UPSTREAM_FLAG;

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(DNS_PORT);
    dst.sin_addr.s_addr = htonl(IP_AROOT);
    sendto(worker->upstream_sock, buf, byte_read, 0, (struct sockaddr *)&dst, sizeof(dst));

    context->up_addrs[context->ua_count++] = dst;
    context->try = 0;

    htw_add(&worker->time_wheel, &context->timer, MAX_TICK_WAIT, hande_expired_contex, context);
}
