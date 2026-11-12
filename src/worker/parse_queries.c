#include "dns.h"

static int read_query(int fd, uint8_t buf[QUERIES_BUFFER], struct sockaddr_in *origin_addr, ssize_t *bytes_read)
{
    socklen_t peer_len;

    peer_len = sizeof(*origin_addr);
    *bytes_read = recvfrom(fd, buf, QUERIES_BUFFER, MSG_TRUNC, (struct sockaddr *)origin_addr, &peer_len);
    if (*bytes_read < 0)
    {
        LOG_ERROR_AT("recvfrom : %s",
            strerror(errno));
        return (1);
    }
    else if (*bytes_read > (ssize_t)QUERIES_BUFFER)
    {
        LOG_INFO(
            "UDP datagram truncated: datagram size %zd bytes, buffer size %zu bytes, "
            "%zd bytes discarded, Request from %s discarded",
            *bytes_read,
            QUERIES_BUFFER,
            *bytes_read - (ssize_t)QUERIES_BUFFER,
            ipv4_to_string(origin_addr->sin_addr.s_addr));
        return (1);
    }
    else if (*bytes_read < MINUMUM_HEADER_SIZE)
    {
        LOG_INFO(
            "DNS header is shorter than %d bytes. Request from %s discarded",
            MINUMUM_HEADER_SIZE,
            ipv4_to_string(origin_addr->sin_addr.s_addr));
        return (1);
    }

    return (0);
}

static int send_formerror(int fd, uint8_t buf[QUERIES_BUFFER], struct sockaddr_in *origin_addr)
{
    t_dns *header = (t_dns *)buf;
    uint16_t flag = header->flags;

    DNS_SET_FLAG(flag, DNS_FLAG_QR);
    DNS_CLR_FLAG(flag, DNS_FLAG_AA);
    DNS_CLR_FLAG(flag, DNS_FLAG_TC);
    DNS_SET_FLAG(flag, DNS_FLAG_RA);
    DNS_SET_RCODE(flag, DNS_RCODE_FORMERR);
    header->flags = flag;
    hton_dns_header(header);
    memset(&header->qdcount, 0, sizeof(header->qdcount) * 4);
    if (sendto(fd, buf, sizeof(t_dns), 0, (struct sockaddr *)origin_addr, sizeof(*origin_addr)) < 0)
    {
        LOG_ERROR_AT("sendto unable to send formerror : %s",
            strerror(errno));
        return (1);
    }
    return (0);
}

static int send_notimpl(int fd, uint8_t buf[QUERIES_BUFFER], struct sockaddr_in *origin_addr)
{
    t_dns *header = (t_dns *)buf;
    uint16_t flag = header->flags;

    DNS_SET_FLAG(flag, DNS_FLAG_QR);
    DNS_CLR_FLAG(flag, DNS_FLAG_AA);
    DNS_CLR_FLAG(flag, DNS_FLAG_TC);
    DNS_SET_FLAG(flag, DNS_FLAG_RA);
    DNS_SET_RCODE(flag, DNS_RCODE_NOTIMP);
    header->flags = flag;
    hton_dns_header(header);
    memset(&header->qdcount, 0, sizeof(header->qdcount) * 4);
    if (sendto(fd, buf, sizeof(t_dns), 0, (struct sockaddr *)origin_addr, sizeof(*origin_addr)) < 0)
    {
        LOG_ERROR_AT("sendto unable to send notimpl error : %s",
            strerror(errno));
        return (1);
    }
    return (0);
}

static int verify_validity_header(int error_fd, uint8_t buf[QUERIES_BUFFER], struct sockaddr_in *origin_addr)
{
    t_dns *header = (t_dns *)buf;
    ntoh_dns_header(header);
    uint16_t flag = header->flags;

    if ((flag & DNS_FLAG_QR) != 0)
    {
        LOG_INFO(
            "DNS QR flag is 1 meaning is not a query. Request from %s discarded",
            ipv4_to_string(origin_addr->sin_addr.s_addr));
        // there we are not sending formerror on purpose to avoid confusion between server
        return (1);
    }
    if ((flag & DNS_FLAG_TC) != 0)
    {
        LOG_INFO(
            "DNS TC flag is 1 meaning it is truncated. Request from %s discarded",
            ipv4_to_string(origin_addr->sin_addr.s_addr));
        (void)send_formerror(error_fd, buf, origin_addr);
        return (1);
    }
    if (DNS_GET_OPCODE(flag) != DNS_OPCODE_QUERY)
    {
        LOG_INFO(
            "DNS OPCODE flag is not a query, operation non implemented. Request from %s discarded",
            ipv4_to_string(origin_addr->sin_addr.s_addr));
        (void)send_notimpl(error_fd, buf, origin_addr);
        return (1);
    }
    if (header->qdcount != 1)
    {
        LOG_INFO(
            "DNS question count is %hu instead of 1. Request from %s discarded",
            header->qdcount,
            ipv4_to_string(origin_addr->sin_addr.s_addr));
        (void)send_formerror(error_fd, buf, origin_addr);
        return (1);
    }
    if (header->ancount != 0)
    {
        LOG_INFO(
            "DNS answear count is %hu instead of 0. Request from %s discarded",
            header->ancount,
            ipv4_to_string(origin_addr->sin_addr.s_addr));
        (void)send_formerror(error_fd, buf, origin_addr);
        return (1);
    }
    if (header->nscount != 0)
    {
        LOG_INFO(
            "DNS nscount count is %hu instead of 0. Request from %s discarded",
            header->nscount,
            ipv4_to_string(origin_addr->sin_addr.s_addr));
        (void)send_formerror(error_fd, buf, origin_addr);
        return (1);
    }
    if (header->arcount > 1)
    {
        LOG_INFO(
            "DNS arcount count is %hu instead of <= 1. Request from %s discarded",
            header->arcount,
            ipv4_to_string(origin_addr->sin_addr.s_addr));
        (void)send_formerror(error_fd, buf, origin_addr);
        return (1);
    }

    return (0);
}

static int verify_valid_qname(int fd, uint8_t buf[QUERIES_BUFFER],
    struct sockaddr_in *origin_addr, ssize_t bytes_read)
{
    const uint8_t *p = buf + sizeof(t_dns);
    size_t n = (size_t)bytes_read - sizeof(t_dns);
    size_t i = 0;

    while (i < n && p[i] != 0)
    {
        uint8_t label_len = p[i];

        if ((label_len & 0xC0) != 0)
        {
            LOG_INFO("Compressed or reserved QNAME label encountered. Request from %s discarded",
                ipv4_to_string(origin_addr->sin_addr.s_addr));
            (void)send_formerror(fd, buf, origin_addr);
            return (1);
        }
        if (label_len > MAX_LABLE_LEN)
        {
            LOG_INFO("QNAME label is longer than %d bytes. Request from %s discarded",
                MAX_LABLE_LEN, ipv4_to_string(origin_addr->sin_addr.s_addr));
            (void)send_formerror(fd, buf, origin_addr);
            return (1);
        }
        if (n - i - 1 < label_len)
        {
            LOG_INFO("Truncated QNAME. Request from %s discarded",
                ipv4_to_string(origin_addr->sin_addr.s_addr));
            (void)send_formerror(fd, buf, origin_addr);
            return (1);
        }
        i += (size_t)label_len + 1;
        if (i >= 255)
        {
            LOG_INFO("QNAME is too long. Request from %s discarded",
                ipv4_to_string(origin_addr->sin_addr.s_addr));
            (void)send_formerror(fd, buf, origin_addr);
            return (1);
        }
    }
    if (i >= n)
    {
        LOG_INFO("QNAME terminator is missing. Request from %s discarded",
            ipv4_to_string(origin_addr->sin_addr.s_addr));
        (void)send_formerror(fd, buf, origin_addr);
        return (1);
    }
    if (n - (i + 1) < 4)
    {
        LOG_INFO("QTYPE or QCLASS is truncated. Request from %s discarded",
            ipv4_to_string(origin_addr->sin_addr.s_addr));
        (void)send_formerror(fd, buf, origin_addr);
        return (1);
    }
    return (0);
}

int parse_queries(t_worker *worker, int fd)
{
    alignas(t_dns) uint8_t buf[QUERIES_BUFFER];
    struct sockaddr_in origin_addr;
    struct sockaddr_in dst;
    t_query_context *context;
    ldns_rr_list *questions;
    ldns_rr *question;
    ldns_rdf *qname;
    ldns_pkt *packet;
    ldns_status status;
    size_t qname_len;
    ssize_t bytes_read;
    ssize_t bytes_sent;
    uint16_t upstream_id;
    int result;

    RETURN_ON_ERROR(read_query(fd, buf, &origin_addr, &bytes_read));
    if (buf[2] & 0x80)
        return 1;
    packet = NULL;
    status = ldns_wire2pkt(&packet, buf, (size_t)bytes_read);
    if (status != LDNS_STATUS_OK)
    {
        LOG_INFO("Invalid DNS packet from %s: %s",
            ipv4_to_string(origin_addr.sin_addr.s_addr),
            ldns_get_errorstr_by_id(status));
        ntoh_dns_header((t_dns *)buf);
        (void)send_formerror(fd, buf, &origin_addr);
        if (packet != NULL)
            ldns_pkt_free(packet);
        return (1);
    }
    result = verify_validity_header(fd, buf, &origin_addr);
    if (result != 0)
    {
        ldns_pkt_free(packet);
        return (result);
    }
    result = verify_valid_qname(fd, buf, &origin_addr, bytes_read);
    if (result != 0)
    {
        ldns_pkt_free(packet);
        return (result);
    }
    hton_dns_header((t_dns *)buf);
    questions = ldns_pkt_question(packet);
    question = ldns_rr_list_rr(questions, 0);
    qname = ldns_rr_owner(question);
    qname_len = ldns_rdf_size(qname);
    if (qname_len == 0 || qname_len > UINT8_MAX
        || qname_len > sizeof(((t_query_context *)0)->qname))
    {
        LOG_INFO("Invalid QNAME length %zu in request from %s",
            qname_len, ipv4_to_string(origin_addr.sin_addr.s_addr));
        ntoh_dns_header((t_dns *)buf);
        (void)send_formerror(fd, buf, &origin_addr);
        ldns_pkt_free(packet);
        return (1);
    }
    context = ctx_pool_alloc(&worker->ctx_pool);
    if (context == NULL)
    {
        LOG_WARNING("No query context available; request from %s discarded",
            ipv4_to_string(origin_addr.sin_addr.s_addr));
        ldns_pkt_free(packet);
        return (1);
    }
    memset(context, 0, sizeof(*context));
    if (id_pool_alloc(&worker->id_pool, &upstream_id))
    {
        LOG_WARNING("No upstream query ID available; request from %s discarded",
            ipv4_to_string(origin_addr.sin_addr.s_addr));
        ctx_pool_free(&worker->ctx_pool, context);
        ldns_pkt_free(packet);
        return (1);
    }
    context->is_recursive = ldns_pkt_rd(packet);
    context->qname_len = (uint8_t)qname_len;
    memcpy(context->qname, ldns_rdf_data(qname), qname_len);
    context->qtype = (uint16_t)ldns_rr_get_type(question);
    context->qclass = (uint16_t)ldns_rr_get_class(question);
    context->query_id = ldns_pkt_id(packet);
    context->origin_addr = origin_addr;
    context->oa_len = sizeof(origin_addr);
    context->try = 0;
    worker->id_pool.id_arr[upstream_id] = context;
    ((t_dns *)buf)->id = htons(upstream_id);
    context->worker = worker;
    context->upstream_id = upstream_id;
    dst = worker->upstream_addr;
    bytes_sent = sendto(worker->upstream_sock, buf, (size_t)bytes_read, 0,
        (struct sockaddr *)&dst, sizeof(dst));
    if (bytes_sent != bytes_read)
    {
        if (bytes_sent < 0)
            LOG_ERROR_AT("Unable to send upstream DNS query: %s",
                strerror(errno));
        else
            LOG_ERROR_AT("Incomplete upstream DNS datagram: sent %zd of %zd bytes",
                bytes_sent, bytes_read);
        hande_expired_contex(context);
        ldns_pkt_free(packet);
        return (1);
    }
    context->up_addrs[context->ua_count++] = dst;
    htw_add(&worker->time_wheel, &context->timer, MAX_TICK_WAIT,
        hande_expired_contex, context);
    LOG_DEBUG("Forwarded query %u as upstream query %u for %s",
        context->query_id, upstream_id,
        ipv4_to_string(origin_addr.sin_addr.s_addr));
    ldns_pkt_free(packet);
    return (0);
}
