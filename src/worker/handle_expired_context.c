#include "dns.h"

void hande_expired_contex(void *arg)
{
    t_query_context *context = arg;
    alignas(t_dns) uint8_t buf[MINUMUM_HEADER_SIZE + MAX_QNAME_LEN + 4] = {0};
    t_dns *header = (t_dns *)buf;
    header->id = htons(context->query_id);
    header->flags = htons(DNS_FLAG_QR | DNS_FLAG_RA | DNS_RCODE_SERVFAIL
        | (context->is_recursive ? DNS_FLAG_RD : 0));
    header->qdcount = htons(1);
    size_t pos = sizeof(*header);
    memcpy(buf + pos, context->qname, context->qname_len);
    pos += context->qname_len;
    buf[pos++] = context->qtype >> 8;
    buf[pos++] = context->qtype & 255;
    buf[pos++] = context->qclass >> 8;
    buf[pos++] = context->qclass & 255;
    (void)sendto(context->worker->client_sock, buf, pos, 0,
        (struct sockaddr *)&context->origin_addr, context->oa_len);
    release_query(context);
}
