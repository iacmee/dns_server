#include "dns.h"

int make_udp_socket_client(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0); // IPv6 + v4-mapped, tipicamente
    if (fd < 0)
    {
        perror("socket");
        _exit(1);
    }

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));

    // Non-blocking
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind");
        _exit(1);
    }
    return (fd);
}

void pin_to_cpu(int cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (pthread_setaffinity_np(pthread_self(), sizeof(set), &set) != 0)
    {
        perror("pthread_setaffinity_np");
    }
}

bool dns_read_name(const uint8_t *msg, size_t msg_len, ssize_t *offset,
                   unsigned char *out, size_t out_len)
{
    size_t pos = *offset;
    size_t out_pos = 0;
    bool jumped = false;
    int jumps_left = MAX_COMPRESSION_JUMP;

    while (1)
    {
        if (pos >= msg_len)
            return false;
        const uint8_t b = msg[pos];

        // end of name
        if (b == 0)
            break;

        // compression pointer
        if ((b & 0xC0) == 0xC0)
        {
            if (pos + 1 >= msg_len)
                return false;
            if (!jumped)
                *offset = pos + 2;
            uint16_t ptr = (uint16_t)(((b & 0x3F) << 8) | msg[pos + 1]);
            if (ptr >= msg_len)
                return (false);

            jumped = true;

            if (--jumps_left == 0)
                return (false);

            pos = ptr; // segui il puntatore per espandere
            continue;
        }

        // other label types (01/10) are invalid in standard DNS names
        if ((b & 0xC0) != 0x00)
            return (false);

        uint8_t lable_len = b; // 0..63
        if (lable_len > MAX_LABLE_LEN)
            return (false);
        if (pos + 1 + lable_len > msg_len)
            return (false);

        // add dot if needed
        if (out_pos != 0)
        {
            if (out_pos + 1 >= out_len)
                return (false);
            out[out_pos++] = '.';
        }
        // copy label
        if (out_pos + lable_len >= out_len)
            return (false);
        memcpy(out + out_pos, msg + pos + 1, lable_len);
        out_pos += lable_len;

        // advance
        pos += 1 + lable_len;
    }
    if (!jumped)
        *offset = pos + 1;

    // root name => empty string (o "." se preferisci)
    if (out_pos >= out_len)
        return (false);
    out[out_pos] = '\0';

    return (true);
}

// restrict?
int dns_encode_name(const char *domain, uint8_t *out, size_t out_len, size_t *offset)
{
    const unsigned char *p = (const unsigned char *)domain;
    size_t pos = *offset;

    // Special case: root name ""
    if (!p || *p == '\0')
    {
        if (pos >= out_len)
            return -1;
        out[pos++] = 0;
        *offset = pos;
        return 0;
    }

    // Reserve first length byte
    if (pos >= out_len)
        return -1;
    size_t len_pos = pos++;
    uint8_t lab_len = 0;

    while (*p)
    {
        if (*p == '.')
        {
            if (lab_len == 0)
                return -1; // empty label (.. or leading .)
            out[len_pos] = lab_len;
            lab_len = 0;

            // Trailing dot means FQDN ends here (root next)
            if (*(p + 1) == '\0')
            {
                if (pos >= out_len)
                    return -1;
                out[pos++] = 0;
                *offset = pos;
                return 0;
            }

            // Start next label: reserve its length byte
            if (pos >= out_len)
                return -1;
            len_pos = pos++;
        }
        else
        {
            if (lab_len == 63)
                return -1; // label too long
            if (pos >= out_len)
                return -1;
            out[pos++] = *p;
            lab_len++;
        }
        p++;
    }

    // Finalize last label and add root terminator
    out[len_pos] = lab_len;
    if (pos >= out_len)
        return -1;
    out[pos++] = 0;

    *offset = pos;
    return 0;
}

bool skip_name(unsigned char buf[QUERIES_BUFFER], ssize_t byte_read, ssize_t *pos)
{
    while (*pos < byte_read)
    {
        if (buf[*pos] == 0)
        {
            *pos += 1;
            break;
        }
        if ((buf[*pos] & 0xC0) == 0xC0)
        {
            *pos += 2;
            break;
        }
        *pos += buf[*pos] + 1;
    }
    if (*pos > byte_read)
        return (true);
    return (false);
}

void ntoh_dns_header(t_dns *header)
{
    header->ancount = ntohs(header->ancount);
    header->arcount = ntohs(header->arcount);
    header->flags = ntohs(header->flags);
    header->id = ntohs(header->id);
    header->nscount = ntohs(header->nscount);
    header->qdcount = ntohs(header->qdcount);
}

void hton_dns_header(t_dns *header)
{
    header->ancount = htons(header->ancount);
    header->arcount = htons(header->arcount);
    header->flags = htons(header->flags);
    header->id = htons(header->id);
    header->nscount = htons(header->nscount);
    header->qdcount = htons(header->qdcount);
}