#include "dns.h"

void release_query(t_query_context *context)
{
    t_worker *worker = context->worker;
    htw_del(&worker->time_wheel, &context->timer);
    worker->id_pool.id_arr[context->upstream_id] = NULL;
    id_pool_free(&worker->id_pool, context->upstream_id);
    ctx_pool_free(&worker->ctx_pool, context);
}

void handle_upstream_response(t_worker *worker)
{
    alignas(t_dns) uint8_t buf[QUERIES_BUFFER];
    ssize_t size = recv(worker->upstream_sock, buf, sizeof(buf), MSG_TRUNC);
    if (size < (ssize_t)sizeof(t_dns) || size > (ssize_t)sizeof(buf))
        return;
    t_dns *header = (t_dns *)buf;
    t_query_context *context = worker->id_pool.id_arr[ntohs(header->id)];
    if (!context || !DNS_IS_RESPONSE(ntohs(header->flags)))
        return;
    ldns_pkt *packet = NULL;
    if (ldns_wire2pkt(&packet, buf, (size_t)size) != LDNS_STATUS_OK)
    {
        if (packet)
            ldns_pkt_free(packet);
        return;
    }
    ldns_rr_list *questions = ldns_pkt_question(packet);
    ldns_rr *question = questions && ldns_rr_list_rr_count(questions) == 1
        ? ldns_rr_list_rr(questions, 0) : NULL;
    ldns_rdf *expected = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_DNAME,
        context->qname_len, context->qname);
    bool matches = question && expected
        && ldns_dname_compare(ldns_rr_owner(question), expected) == 0
        && ldns_rr_get_type(question) == context->qtype
        && ldns_rr_get_class(question) == context->qclass;
    ldns_rdf_deep_free(expected);
    ldns_pkt_free(packet);
    if (!matches)
        return;
    header->id = htons(context->query_id);
    if (sendto(worker->client_sock, buf, (size_t)size, 0,
        (struct sockaddr *)&context->origin_addr, context->oa_len) < 0)
        LOG_WARNING("Unable to send response: %s", strerror(errno));
    release_query(context);
}
