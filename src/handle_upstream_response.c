#include "dns.h"

void send_servfail(t_worker *worker, unsigned char buf[QUERIES_BUFFER], t_query_context *context);

ssize_t read_and_verify_response(t_worker *worker, unsigned char buf[QUERIES_BUFFER], t_query_context **ct)
{
    struct sockaddr_in origin_addr;
    socklen_t peer_len = sizeof(origin_addr);
    ssize_t byte_read = recvfrom(worker->upstream_sock, buf, QUERIES_BUFFER, 0, (struct sockaddr *)&origin_addr, &peer_len);
    if (byte_read < 0)
    {
        perror("recvfrom (handle_upstream_response)");
        return (-1);
    }

    if (byte_read < MINUMUM_HEADER_SIZE)
        return (-1);
    if (peer_len > sizeof(origin_addr))
    {
        fprintf(stderr, "peer_len > origin_addr, (should never happen)\n");
        return (-1);
    }

    t_dns *header = (t_dns *)buf;
    ntoh_dns_header(header);
    t_query_context *context = worker->id_pool.id_arr[header->id];
    if (context == NULL)
        return (-1);

    // verify that i recive a packet from the same ip:port i sent 
    int i;
    for (i = 0; i < context->ua_count; ++i)
        if (memcmp(&origin_addr, context->up_addrs + i, sizeof(origin_addr)) == 0)
            break;
    if (i >= context->ua_count)
        return (-1);

    // verify flags
    if (DNS_IS_QUERY(header->flags) || DNS_GET_OPCODE(header->flags) != DNS_OPCODE_QUERY)
        return (-1);

    // verify that has the same questions
    // ora come ora confronta anche il padding quindi è un po' una merda
    if (header->qdcount != 1 || memcmp(context->qname, &buf[sizeof(*header)], context->qname_len) != 0)
        return (-1);
    
    // verify qtype and qclass
    uint16_t qtype;
    memcpy(&qtype, buf + sizeof(*header) + context->qname_len, sizeof(uint16_t));
    qtype = htons(qtype);
    uint16_t qclass;
    memcpy(&qclass, buf + sizeof(*header) + context->qname_len + 2, sizeof(uint16_t));
    qclass = htons(qclass);
    if (context->qclass != qclass || context->qtype != qtype)
        return (-1);
    
    *ct = context;
    // TMP DEVO GESTIRE IL RETURN CODE
    if (DNS_GET_RCODE(header->flags) != DNS_RCODE_NOERROR)
    {
        perror("cosa non gestita attualmente");
        _exit(1);
    }
    return (byte_read);
}

void handle_upstream_response(t_worker *worker)
{
    alignas(t_dns) unsigned char buf[QUERIES_BUFFER];
    t_query_context *context;

    ssize_t byte_read = read_and_verify_response(worker, buf, &context);
    if (byte_read < 0)
        return ;

    t_dns *header = (t_dns *)buf;
    ssize_t pos = sizeof(*header) + context->qname_len + 4;

    // ho la risposta effettiva e la devo "solo" inviare
    if (header->ancount != 0 || context->is_recursive == false)
    {
        // devo verificare il contenuto della risposta e inviarla
        /**
         * in particolare devo verificare che:
         * -sia formattata bene
         * -sia < 512 byte (ancora non supporto edns)
         */

        if (context->query_ref != NULL)
        {
            // questa query mi seviva per un'altro contex
            /**
             * devo prendere gli ip dalle risposte e metterli dentro gli up_addr
             * -eliminare il contex corrente e "risvegliare quello vecchio"
             */
            // pos sta gia dopo la question section
            t_query_context *old_context = context->query_ref;

            int ua_count = 0;
            for (int i = 0; i < header->arcount; ++i)
            {
                skip_name(buf, byte_read, &pos);
                if (buf[pos] == 0 && buf[pos + 1] == 1 && buf[pos + 8] == 0 && buf[pos + 9] == 4) // è type A (ipv4)
                {
                    memset(&old_context->up_addrs[ua_count], 0, sizeof(struct sockaddr_in));
                    memcpy(&old_context->up_addrs[ua_count].sin_addr.s_addr, buf + pos + 10, 4);

                    ++ua_count;
                }
                // skippo alla prossima entry
                pos += 8;
                pos += (uint16_t)((buf[pos] << 8) | buf[pos + 1]) + 2;
            }
            id_pool_free(&worker->id_pool, header->id);
            htw_del(&worker->time_wheel, &context->timer);
            ctx_pool_free(&worker->ctx_pool, context);
            context = old_context;
            goto send;
        }

        // aggiusto la flag
        DNS_CLR_FLAG(header->flags, DNS_FLAG_AA);
        DNS_CLR_FLAG(header->flags, DNS_FLAG_TC); // ATTENZIONE QUA DEVO VEDERE LE COSE PRIMA
        if (context->is_recursive == true   )
            DNS_SET_FLAG(header->flags, DNS_FLAG_RD);
        DNS_SET_FLAG(header->flags, DNS_FLAG_RA);
        DNS_SET_RCODE(header->flags, DNS_RCODE_NOERROR); // ATTENZIONE QUA DEVO VEDERE COSE PRIMA
        header->id = context->query_id;
        hton_dns_header(header);
        
        if (sendto(worker->client_sock, buf, byte_read, 0, (struct sockaddr *)&context->origin_addr, context->oa_len) < 0)
        {
            // Devo gestire questo caso non so bene come
            perror("sendto");
            _exit(1);
        }


        htw_del(&worker->time_wheel, &context->timer);
        id_pool_free(&worker->id_pool, header->id);
        ctx_pool_free(&worker->ctx_pool, context);
        worker->id_pool.id_arr[header->id] = NULL;
        return ;
    }

    /**
    * -scorro tutte le ns
    */
    // tutto questo inevitabilmente cambierà quando ci andrò ad aggiungere la cache
    unsigned char nss[MAX_LEN_IP_TO_TRY][MAX_QNAME_LEN];
    for (int i = 0; i < header->nscount; ++i)
    {
        if (i < MAX_LEN_IP_TO_TRY)
        {
            if (skip_name(buf, byte_read, &pos))
            {
                send_servfail(worker, buf, context);
                return ;
            }
            if (buf[pos] != 0 || buf[pos + 1] != 2) // type ns
            {
                send_servfail(worker, buf, context);
                return ;
            }
            pos += 10; // skip type, class, ttl and data_len
            if (!dns_read_name(buf, byte_read, &pos, nss[i], MAX_QNAME_LEN))
            {
                send_servfail(worker, buf, context);
                return ;
            }
            continue;
        }
        if (skip_name(buf, byte_read, &pos))
        {
            send_servfail(worker, buf, context);
            return ;
        }
        pos += 10; // skip type, class, ttl
        if (skip_name(buf, byte_read, &pos))
        {
            send_servfail(worker, buf, context);
            return ;
        }
    }

    if (header->arcount <= 1)
    {
        /**
         * -disarmo il timer, tolgo dagli id occupati
         * -creo nuovo context
         * 
         */

        t_query_context *new_context = ctx_pool_alloc(&worker->ctx_pool);
        new_context->is_recursive = true;
        alignas(t_dns) unsigned char buf2[QUERIES_BUFFER];
        header = (t_dns *)buf2;
        header->ancount = 0;
        header->arcount = 0;
        header->flags = UPSTREAM_FLAG;
        header->nscount = 0;
        header->qdcount = 1;
        if (id_pool_alloc(&worker->id_pool, &header->id))
        {
            send_servfail(worker, buf, context);
            ctx_pool_free(&worker->ctx_pool, new_context);
            return ;
        }
        worker->id_pool.id_arr[header->id] = new_context;
        hton_dns_header(header);
        size_t pos = sizeof(*header);
        dns_encode_name((char *)&nss[0][0], buf2, MAX_QNAME_LEN, &pos);
        new_context->qname_len = pos - sizeof(*header);
        memcpy(&new_context->qname, buf2 + sizeof(*header), new_context->qname_len);
        buf2[pos++] = 0; buf2[pos++] = 1; buf2[pos++] = 0; buf2[pos++] = 1; 
        new_context->qtype = DNS_QTYPE_A;
        new_context->qclass = 1; // IN
        new_context->query_id = 0;
        new_context->query_ref = context;
        htw_add(&worker->time_wheel, &new_context->timer, MAX_TICK_WAIT, hande_expired_contex, new_context);
        new_context->try = 0;
        new_context->ua_count = 0;


        struct sockaddr_in dst;
        memset(&dst, 0, sizeof(dst));
        dst.sin_family = AF_INET;
        dst.sin_port = htons(DNS_PORT);
        dst.sin_addr.s_addr = htonl(IP_AROOT);
        sendto(worker->upstream_sock, buf2, pos, 0, (struct sockaddr *)&dst, sizeof(dst));

        new_context->up_addrs[new_context->ua_count++] = dst;

        // shadow context
        htw_del(&worker->time_wheel, &context->timer);
        id_pool_free(&worker->id_pool, header->id);
        worker->id_pool.id_arr[header->id] = NULL;

        return ;
    }

    /* adesso sono sulle addictional */
    int ua_count = 0;

    for (int i = 0; i < header->arcount; ++i)
    {
        // prendo il primo nome
        unsigned char name_server[MAX_QNAME_LEN];
        if (!dns_read_name(buf, byte_read, &pos, name_server, MAX_QNAME_LEN))
        {
            send_servfail(worker, buf, context);
            return ;
        }
        if (buf[pos] == 0 && buf[pos + 1] == 1 && buf[pos + 8] == 0 && buf[pos + 9] == 4) // è type A (ipv4)
        {
            if (ua_count < MAX_LEN_IP_TO_TRY)
            {
                memset(&context->up_addrs[ua_count], 0, sizeof(struct sockaddr_in));
                memcpy(&context->up_addrs[ua_count].sin_addr.s_addr, buf + pos + 10, 4);
                // context->up_addrs[ua_count].sin_addr.s_addr = ntohl(context->up_addrs[ua_count].sin_addr.s_addr);

                ++ua_count;
            }
        }
        // skippo alla prossima entry
        pos += 8;
        pos += (uint16_t)((buf[pos] << 8) | buf[pos + 1]) + 2;
    }



    // preparazione della risposta
    worker->id_pool.id_arr[header->id] = NULL;
    id_pool_free(&worker->id_pool, header->id);
send:
    header->ancount = 0;
    header->arcount = 0;
    header->qdcount = 1;
    header->nscount = 0;
    if (id_pool_alloc(&worker->id_pool, &header->id))
    {
        // dovrei rispondere con serv_fail
        printf("wegfewgwe\n");
        _exit(1);
    }
    worker->id_pool.id_arr[header->id] = context;
    header->flags = UPSTREAM_FLAG;
    hton_dns_header(header);
    htw_add(&worker->time_wheel, &context->timer, MAX_TICK_WAIT, hande_expired_contex, context); 
    context->try = 0;
    context->ua_count = ua_count;

    // adesso rendiamo pos la lungheza della fine della questions section
    pos = sizeof(*header) + context->qname_len + 4;

    for (int i = 0; i < ua_count; ++i)
    {
        context->up_addrs[i].sin_family = AF_INET;
        context->up_addrs[i].sin_port = htons(DNS_PORT);
        memset(&context->up_addrs[i].sin_zero, 0, sizeof(context->up_addrs[i].sin_zero));

        sendto(worker->upstream_sock, buf, pos, 0, (struct sockaddr *)&context->up_addrs[i], sizeof(context->up_addrs[i]));
    }
    return ;

    // int pos = sizeof(t_dns) + context->qname_len + 4;
    // // adesso pos sta nelle answare sections
    // // se ci sono solo nscount allora devo aprire un'altro context che poi fa capo a questo
    // // invece se ci sono and 
    // if (header->arcount == 0)
    // {
    //     // qua devo aprire un'altro context
    //     printf("abudabi\n");
    //     _exit(1);
    // }
    
    // // faccio una cosa brutto, skippo le autorative risposte e vado direttamente alle addictional records per prendere gli ip
    // while (header->nscount--)
    // {
    //     /* skip NAME */
    //     while (pos < byte_read)
    //     {
    //         if (buf[pos] == 0) { pos += 1; break; }          // fine nome
    //         if ((buf[pos] & 0xC0) == 0xC0) { pos += 2; break; } // pointer compresso
    //         pos += buf[pos] + 1;                     // label normale
    //     }

    //     if (pos + 10 > byte_read) { printf("errore\n"); _exit(1); }

    //     /* skip fixed RR fields + RDATA */
    //     uint16_t rdlen = (uint16_t)((buf[pos + 8] << 8) | buf[pos + 9]);
    //     pos += 10 + rdlen;

    //     if (pos > byte_read) { printf("errore\n"); _exit(1); }
    // }
    // // adesso sono sulle addictional section, prendo il primo ip e mando la richiesta ahahaha
    // // come prima cosa skippo il nome
    // /* skip NAME */
    // while (pos < byte_read)
    // {
    //     if (buf[pos] == 0) { pos += 1; break; }          // fine nome
    //     if ((buf[pos] & 0xC0) == 0xC0) { pos += 2; break; } // pointer compresso
    //     pos += buf[pos] + 1;                     // label normale
    // }
    // printf("AAAAAAAAAAAAAAAAAAAAAAAAAAAA : %x, %x\n", buf[pos], buf[pos + 1]);

    // uint16_t type  = (uint16_t)((buf[pos] << 8) | buf[pos + 1]);
    // uint16_t rdlen = (uint16_t)((buf[pos + 8] << 8) | buf[pos + 9]);

    // if (type != 1)
    // {                 // 1 = A
    //     pos += 10 + rdlen;           // next RR (starts with NAME)
    //     /* skip NAME */
    //     while (pos < byte_read)
    //     {
    //         if (buf[pos] == 0) { pos += 1; break; }          // fine nome
    //         if ((buf[pos] & 0xC0) == 0xC0) { pos += 2; break; } // pointer compresso
    //         pos += buf[pos] + 1;                     // label normale
    //     }
    // }
    // // if (!(buf[pos] == 0 && buf[pos + 1] == 1))
    // // {
    // //     printf("sono entrato\n ");
    // //     pos += buf[pos + 6] + 7;
    // //     while (pos < byte_read)
    // //     {
    // //         if (buf[pos] == 0) { pos += 1; break; }          // fine nome
    // //         if ((buf[pos] & 0xC0) == 0xC0) { pos += 2; break; } // pointer compresso
    // //         pos += buf[pos] + 1;                     // label normale
    // //     }   
    // // }
    // pos += 10; // e dovrei essere all'ip
    // header->ancount = 0;
    // header->arcount = 0;
    // header->qdcount = htons(1);
    // header->nscount = 0;
    // worker->id_pool.id_arr[header->id] = NULL;
    // if (id_pool_alloc(&worker->id_pool, &header->id))
    // {
    //     printf("wegfewgwe\n");
    //     _exit(1);
    // }
    // worker->id_pool.id_arr[header->id] = context;
    // header->id = htons(header->id);
    // printf("messo il context dentro %x\n", header->id);
    // header->flags = UPSTREAM_FLAG;
    

    // struct sockaddr_in dst;
    // memset(&dst, 0, sizeof(dst));
    // dst.sin_family = AF_INET;
    // dst.sin_port = htons(DNS_PORT);
    // dst.sin_addr.s_addr = *(uint32_t *)(buf + pos);
    // // adesso rendiamo pos la lungheza della fine della questions section
    // pos = sizeof(*header) + context->qname_len + 4;
    // sendto(worker->upstream_sock, buf, pos, 0, (struct sockaddr *)&dst, sizeof(dst));
}

void send_servfail(t_worker *worker, unsigned char buf[QUERIES_BUFFER], t_query_context *context)
{
    // se tutte le query che ho inviato non mi hanno risposto mando un serverror
    
    if (++context->try < context->ua_count)
        return ;
    
    t_dns *header = (t_dns *)buf;
    ssize_t pos = sizeof(*header) + context->qname_len + 4;

    DNS_SET_FLAG(header->flags, DNS_FLAG_QR);
    DNS_CLR_FLAG(header->flags, DNS_FLAG_AA);
    DNS_CLR_FLAG(header->flags, DNS_FLAG_TC);
    DNS_SET_FLAG(header->flags, DNS_FLAG_RA);
    DNS_SET_RCODE(header->flags, DNS_RCODE_SERVFAIL);
    header->ancount = 0;
    header->arcount = 0;
    header->nscount = 0;
    header->id = context->query_id;
    hton_dns_header(header);
    if (sendto(worker->client_sock, buf, pos, 0, (struct sockaddr *)&context->origin_addr, context->oa_len) < 0)
        perror("sendto");

    htw_del(&worker->time_wheel, &context->timer);
    id_pool_free(&worker->id_pool, header->id);
    ctx_pool_free(&worker->ctx_pool, context);
    worker->id_pool.id_arr[header->id] = NULL;
}