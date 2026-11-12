// #include "dns.h"

// static int read_query(int fd, uint8_t buf[QUERIES_BUFFER], struct sockaddr_in *origin_addr, ssize_t *bytes_read)
// {
//     socklen_t peer_len;

//     peer_len = sizeof(*origin_addr);
//     *bytes_read = recvfrom(fd, buf, QUERIES_BUFFER, MSG_TRUNC, (struct sockaddr *)origin_addr, &peer_len);
//     if (*bytes_read < 0)
//     {
//         LOG_ERROR_AT("recvfrom : %s",
//             strerror(errno));
//         return (1);
//     }
//     else if (*bytes_read > (ssize_t)QUERIES_BUFFER)
//     {
//         LOG_INFO(
//             "UDP datagram truncated: datagram size %zd bytes, buffer size %zu bytes, "
//             "%zd bytes discarded, Request from %s discarded",
//             *bytes_read,
//             QUERIES_BUFFER,
//             *bytes_read - (ssize_t)QUERIES_BUFFER,
//             ipv4_to_string(origin_addr->sin_addr.s_addr));
//         return (1);
//     }
//     else if (*bytes_read < MINUMUM_HEADER_SIZE)
//     {
//         LOG_INFO(
//             "DNS header is shorter than %d bytes. Request from %s discarded",
//             MINUMUM_HEADER_SIZE,
//             ipv4_to_string(origin_addr->sin_addr.s_addr));
//         return (1);
//     }
//     // else if (*bytes_read < MINUMUM_HEADER_SIZE + 5)
//     // {   // +5 because 1 byte for qname + 2 byte for qtype + 2 byte for qclass minumum
//     //     LOG_INFO(
//     //         "DNS message is too short to contain a question: %zd bytes. "
//     //         "Request from %s discarded",
//     //         *bytes_read,
//     //         ipv4_to_string(origin_addr->sin_addr.s_addr));
//     //     return (1);
//     // }

//     return (0);
// }

// static int send_formerror(int fd, uint8_t buf[QUERIES_BUFFER], struct sockaddr_in *origin_addr)
// {
//     t_dns *header = (t_dns *)buf;
//     uint16_t flag = header->flags;

//     DNS_SET_FLAG(flag, DNS_FLAG_QR);
//     DNS_CLR_FLAG(flag, DNS_FLAG_AA);
//     DNS_CLR_FLAG(flag, DNS_FLAG_TC);
//     DNS_SET_FLAG(flag, DNS_FLAG_RA);
//     DNS_SET_RCODE(flag, DNS_RCODE_FORMERR);
//     header->flags = flag;
//     hton_dns_header(header);
//     memset(&header->qdcount, 0, sizeof(header->qdcount) * 4);
//     if (sendto(fd, buf, sizeof(t_dns), 0, (struct sockaddr *)origin_addr, sizeof(*origin_addr)) < 0)
//     {
//         LOG_ERROR_AT("sendto unable to send formerror : %s",
//             strerror(errno));
//         return (1);
//     }
//     return (0);
// }

// static int send_notimpl(int fd, uint8_t buf[QUERIES_BUFFER], struct sockaddr_in *origin_addr)
// {
//     t_dns *header = (t_dns *)buf;
//     uint16_t flag = header->flags;

//     DNS_SET_FLAG(flag, DNS_FLAG_QR);
//     DNS_CLR_FLAG(flag, DNS_FLAG_AA);
//     DNS_CLR_FLAG(flag, DNS_FLAG_TC);
//     DNS_SET_FLAG(flag, DNS_FLAG_RA);
//     DNS_SET_RCODE(flag, DNS_RCODE_NOTIMP);
//     header->flags = flag;
//     hton_dns_header(header);
//     memset(&header->qdcount, 0, sizeof(header->qdcount) * 4);
//     if (sendto(fd, buf, sizeof(t_dns), 0, (struct sockaddr *)origin_addr, sizeof(*origin_addr)) < 0)
//     {
//         LOG_ERROR_AT("sendto unable to send notimpl error : %s",
//             strerror(errno));
//         return (1);
//     }
//     return (0);
// }

// static int verify_validity_header(int error_fd, uint8_t buf[QUERIES_BUFFER], struct sockaddr_in *origin_addr)
// {
//     t_dns *header = (t_dns *)buf;
//     ntoh_dns_header(header);
//     uint16_t flag = header->flags;

//     if ((flag & DNS_FLAG_QR) != 0)
//     {
//         LOG_INFO(
//             "DNS QR flag is 1 meaning is not a query. Request from %s discarded",
//             ipv4_to_string(origin_addr->sin_addr.s_addr));
//         // there we are not sending formerror on purpose to avoid confusion between server
//         return (1);
//     }
//     if ((flag & DNS_FLAG_TC) != 0)
//     {
//         LOG_INFO(
//             "DNS TC flag is 1 meaning it is truncated. Request from %s discarded",
//             ipv4_to_string(origin_addr->sin_addr.s_addr));
//         (void)send_formerror(error_fd, buf, origin_addr);
//         return (1);
//     }
//     if (DNS_GET_OPCODE(flag) != DNS_OPCODE_QUERY)
//     {
//         LOG_INFO(
//             "DNS OPCODE flag is not a query, operation non implemented. Request from %s discarded",
//             ipv4_to_string(origin_addr->sin_addr.s_addr));
//         (void)send_notimpl(error_fd, buf, origin_addr);
//         return (1);
//     }
//     if (header->qdcount != 1)
//     {
//         LOG_INFO(
//             "DNS question count is %hu instead of 1. Request from %s discarded",
//             header->qdcount,
//             ipv4_to_string(origin_addr->sin_addr.s_addr));
//         (void)send_formerror(error_fd, buf, origin_addr);
//         return (1);
//     }
//     if (header->ancount != 0)
//     {
//         LOG_INFO(
//             "DNS answear count is %hu instead of 0. Request from %s discarded",
//             header->ancount,
//             ipv4_to_string(origin_addr->sin_addr.s_addr));
//         (void)send_formerror(error_fd, buf, origin_addr);
//         return (1);
//     }
//     if (header->nscount != 0)
//     {
//         LOG_INFO(
//             "DNS nscount count is %hu instead of 0. Request from %s discarded",
//             header->nscount,
//             ipv4_to_string(origin_addr->sin_addr.s_addr));
//         (void)send_formerror(error_fd, buf, origin_addr);
//         return (1);
//     }
//     if (header->arcount > 1)
//     {
//         LOG_INFO(
//             "DNS arcount count is %hu instead of <= 1. Request from %s discarded",
//             header->arcount,
//             ipv4_to_string(origin_addr->sin_addr.s_addr));
//         (void)send_formerror(error_fd, buf, origin_addr);
//         return (1);
//     }

//     return (0);
// }

// static int verify_valid_qname(int fd, uint8_t buf[QUERIES_BUFFER],
//     struct sockaddr_in *origin_addr, ssize_t bytes_read)
// {
//     const uint8_t *p = buf + sizeof(t_dns);
//     size_t n = (size_t)bytes_read - sizeof(t_dns);
//     size_t i = 0;

//     while (i < n && p[i] != 0)
//     {
//         uint8_t label_len = p[i];

//         if ((label_len & 0xC0) != 0)
//         {
//             LOG_INFO("Compressed or reserved QNAME label encountered. Request from %s discarded",
//                 ipv4_to_string(origin_addr->sin_addr.s_addr));
//             (void)send_formerror(fd, buf, origin_addr);
//             return (1);
//         }
//         if (label_len > MAX_LABLE_LEN)
//         {
//             LOG_INFO("QNAME label is longer than %d bytes. Request from %s discarded",
//                 MAX_LABLE_LEN, ipv4_to_string(origin_addr->sin_addr.s_addr));
//             (void)send_formerror(fd, buf, origin_addr);
//             return (1);
//         }
//         if (n - i - 1 < label_len)
//         {
//             LOG_INFO("Truncated QNAME. Request from %s discarded",
//                 ipv4_to_string(origin_addr->sin_addr.s_addr));
//             (void)send_formerror(fd, buf, origin_addr);
//             return (1);
//         }
//         i += (size_t)label_len + 1;
//         if (i >= 255)
//         {
//             LOG_INFO("QNAME is too long. Request from %s discarded",
//                 ipv4_to_string(origin_addr->sin_addr.s_addr));
//             (void)send_formerror(fd, buf, origin_addr);
//             return (1);
//         }
//     }
//     if (i >= n)
//     {
//         LOG_INFO("QNAME terminator is missing. Request from %s discarded",
//             ipv4_to_string(origin_addr->sin_addr.s_addr));
//         (void)send_formerror(fd, buf, origin_addr);
//         return (1);
//     }
//     if (n - (i + 1) < 4)
//     {
//         LOG_INFO("QTYPE or QCLASS is truncated. Request from %s discarded",
//             ipv4_to_string(origin_addr->sin_addr.s_addr));
//         (void)send_formerror(fd, buf, origin_addr);
//         return (1);
//     }
//     return (0);
// }

// int parse_queries(t_worker *worker, int fd)
// {
//     alignas(t_dns) uint8_t buf[QUERIES_BUFFER];
//     struct sockaddr_in origin_addr;
//     ssize_t bytes_read;

//     RETURN_ON_ERROR(read_query(fd, buf, &origin_addr, &bytes_read));
//     RETURN_ON_ERROR(verify_validity_header(fd ,buf, &origin_addr));
//     RETURN_ON_ERROR(verify_valid_qname(fd, buf, &origin_addr, bytes_read));
//     LOG_DEBUG("AGAGAGAGA YES\n");


//     (void)worker;

//     return (0);
// }
