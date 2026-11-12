#include "dns.h"

size_t dns_write_qname(uint8_t *buf, const char *domain);

int main()
{
    srand(time(NULL));
    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(DNS_PORT);
    dst.sin_addr.s_addr = htonl(0x7F000007); // 127.0.0.1

    char buf[QUERIES_BUFFER];
    t_dns *header = (t_dns *)buf;
    header->id = rand();
    header->qdcount = htons(1);
    header->flags = htons(0b1000010110000000);
    header->ancount = htons(0);
    header->nscount = htons(0);
    header->arcount = htons(0);

    char domain[] = "example.com";
    int pos = dns_write_qname(buf + sizeof(*header), "example.com") + sizeof(*header);
    *(uint16_t *)(buf + pos) = htons(DNS_QTYPE_A);
    pos += 2;
    *(uint16_t *)(buf + pos) = htons(1);
    pos += 2;

    sendto(sock_fd, buf, pos, 0, (struct sockaddr *)&dst, sizeof(dst));
}


size_t dns_write_qname(uint8_t *buf, const char *domain)
{
    size_t i = 0;
    size_t label_len_pos = 0;
    size_t label_len = 0;

    buf[i++] = 0;               // placeholder lunghezza prima label
    label_len_pos = 0;

    for (size_t d = 0; domain[d] != '\0'; d++)
    {
        if (domain[d] == '.')
        {
            buf[label_len_pos] = (uint8_t)label_len;
            label_len_pos = i;
            buf[i++] = 0;       // placeholder nuova label
            label_len = 0;
        }
        else
        {
            buf[i++] = (uint8_t)domain[d];
            label_len++;
        }
    }

    buf[label_len_pos] = (uint8_t)label_len;
    buf[i++] = 0;               // terminatore QNAME

    return i;
}
