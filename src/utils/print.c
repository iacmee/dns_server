#include "dns.h"

/*
 * Standalone DNS wire-format pretty-printer (dig-like).
 * C99
 *
 * Usage:
 *   dns_print_message(buf, len, stdout);
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <ctype.h>
#include <arpa/inet.h>

/* -------------------- helpers: endian-safe reads -------------------- */

static int read_u16(const uint8_t *buf, size_t len, size_t *off, uint16_t *out) {
    if (*off + 2 > len) return 0;
    *out = (uint16_t)((buf[*off] << 8) | buf[*off + 1]);
    *off += 2;
    return 1;
}

static int read_u32(const uint8_t *buf, size_t len, size_t *off, uint32_t *out) {
    if (*off + 4 > len) return 0;
    *out = ((uint32_t)buf[*off] << 24) |
           ((uint32_t)buf[*off + 1] << 16) |
           ((uint32_t)buf[*off + 2] << 8) |
           ((uint32_t)buf[*off + 3]);
    *off += 4;
    return 1;
}

/* -------------------- type/class/rcode strings -------------------- */

static const char* dns_class_to_str(uint16_t c) {
    switch (c) {
        case 1: return "IN";
        case 3: return "CH";
        case 4: return "HS";
        case 255: return "ANY";
        default: return "CLASS?";
    }
}

static const char* dns_type_to_str(uint16_t t) {
    switch (t) {
        case 1:  return "A";
        case 2:  return "NS";
        case 5:  return "CNAME";
        case 6:  return "SOA";
        case 12: return "PTR";
        case 15: return "MX";
        case 16: return "TXT";
        case 28: return "AAAA";
        case 33: return "SRV";
        case 41: return "OPT";   /* EDNS(0) */
        case 43: return "DS";
        case 46: return "RRSIG";
        case 47: return "NSEC";
        case 48: return "DNSKEY";
        case 50: return "NSEC3";
        case 51: return "NSEC3PARAM";
        case 52: return "TLSA";
        case 53: return "SMIMEA";
        case 59: return "CDS";
        case 60: return "CDNSKEY";
        case 61: return "OPENPGPKEY";
        case 62: return "CSYNC";
        case 63: return "ZONEMD";
        case 64: return "SVCB";
        case 65: return "HTTPS";
        case 255:return "ANY";
        default: return "TYPE?";
    }
}

static const char* rcode_to_str(uint8_t rcode) {
    switch (rcode) {
        case 0: return "NOERROR";
        case 1: return "FORMERR";
        case 2: return "SERVFAIL";
        case 3: return "NXDOMAIN";
        case 4: return "NOTIMP";
        case 5: return "REFUSED";
        case 6: return "YXDOMAIN";
        case 7: return "YXRRSET";
        case 8: return "NXRRSET";
        case 9: return "NOTAUTH";
        case 10:return "NOTZONE";
        default:return "RCODE?";
    }
}

/* -------------------- name parsing with compression --------------------
 *
 * Parses a DNS name at *off, writing into out (NUL-terminated).
 * Supports compression pointers.
 *
 * On success:
 *  - returns 1
 *  - advances *off past the encoded name (unless pointer jump, then uses original advancement rules)
 *
 * Robustness:
 *  - loop guards (max jumps)
 *  - bounds checks
 */

static int dns_parse_name(const uint8_t *buf, size_t len, size_t *off,
                          char *out, size_t out_sz) {
    if (!buf || !off || !out || out_sz == 0) return 0;

    size_t pos = *off;
    size_t out_i = 0;
    int jumped = 0;
    size_t jump_guard = 0;

    if (pos >= len) return 0;

    while (1) {
        if (pos >= len) return 0;

        uint8_t labellen = buf[pos];

        /* end of name */
        if (labellen == 0) {
            pos += 1;
            break;
        }

        /* compression pointer: 11xxxxxx xxxxxxxx */
        if ((labellen & 0xC0) == 0xC0) {
            if (pos + 1 >= len) return 0;
            uint16_t ptr = (uint16_t)(((labellen & 0x3F) << 8) | buf[pos + 1]);
            if (ptr >= len) return 0;

            if (!jumped) {
                /* if first jump, original offset consumes 2 bytes */
                *off = pos + 2;
                jumped = 1;
            }
            pos = ptr;

            if (++jump_guard > 128) return 0; /* prevent infinite loops */
            continue;
        }

        /* reserved label types 01/10 are not used in classic DNS */
        if ((labellen & 0xC0) != 0x00) return 0;

        pos += 1;
        if (pos + labellen > len) return 0;

        /* add dot if needed */
        if (out_i != 0) {
            if (out_i + 1 >= out_sz) return 0;
            out[out_i++] = '.';
        }

        /* copy label, escape non-printables */
        for (uint8_t i = 0; i < labellen; i++) {
            unsigned char ch = buf[pos + i];
            if (isprint(ch) && ch != '.') {
                if (out_i + 1 >= out_sz) return 0;
                out[out_i++] = (char)ch;
            } else {
                /* \DDD escape */
                char tmp[5];
                int n = snprintf(tmp, sizeof(tmp), "\\%03u", (unsigned)ch);
                if (n <= 0) return 0;
                if (out_i + (size_t)n >= out_sz) return 0;
                memcpy(out + out_i, tmp, (size_t)n);
                out_i += (size_t)n;
            }
        }

        pos += labellen;

        if (++jump_guard > 1024) return 0; /* general guard */
    }

    if (!jumped) {
        *off = pos;
    }

    if (out_i == 0) {
        /* root */
        if (out_sz < 2) return 0;
        out[0] = '.';
        out[1] = '\0';
    } else {
        if (out_i >= out_sz) return 0;
        out[out_i] = '\0';
    }

    return 1;
}

/* -------------------- formatting helpers -------------------- */

static void print_hex(FILE *out, const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        fprintf(out, "%02x", p[i]);
        if (i + 1 != n) fputc(' ', out);
    }
}

static void print_ipv4(FILE *out, const uint8_t *p) {
    fprintf(out, "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
}

static void print_ipv6(FILE *out, const uint8_t *p) {
    /* minimal RFC5952-ish compression would be longer; keep simple hextets */
    for (int i = 0; i < 16; i += 2) {
        uint16_t hextet = (uint16_t)((p[i] << 8) | p[i + 1]);
        fprintf(out, "%x", hextet);
        if (i != 14) fputc(':', out);
    }
}

static void print_txt(FILE *out, const uint8_t *rdata, size_t rdlen) {
    /* TXT: sequence of <len><bytes> ... */
    size_t i = 0;
    int first = 1;
    while (i < rdlen) {
        uint8_t slen = rdata[i++];
        if (i + slen > rdlen) {
            fprintf(out, "\"<bad-txt>\"");
            return;
        }
        if (!first) fputc(' ', out);
        first = 0;
        fputc('"', out);
        for (uint8_t j = 0; j < slen; j++) {
            unsigned char ch = rdata[i + j];
            if (ch == '"' || ch == '\\') {
                fputc('\\', out);
                fputc(ch, out);
            } else if (isprint(ch)) {
                fputc(ch, out);
            } else {
                fprintf(out, "\\%03u", (unsigned)ch);
            }
        }
        fputc('"', out);
        i += slen;
    }
}

/* -------------------- RDATA parser (common types) -------------------- */

static int print_rdata(FILE *out, const uint8_t *buf, size_t len,
                       uint16_t type, const uint8_t *rdata, size_t rdlen,
                       size_t rdata_off_in_msg) {
    (void)rdata_off_in_msg;

    if (type == 1) { /* A */
        if (rdlen != 4) { fprintf(out, "<bad-A>"); return 1; }
        print_ipv4(out, rdata);
        return 1;
    }

    if (type == 28) { /* AAAA */
        if (rdlen != 16) { fprintf(out, "<bad-AAAA>"); return 1; }
        print_ipv6(out, rdata);
        return 1;
    }

    if (type == 2 || type == 5 || type == 12) { /* NS / CNAME / PTR -> domain name */
        size_t off = (size_t)(rdata - buf);
        char name[1024];
        if (!dns_parse_name(buf, len, &off, name, sizeof(name))) {
            fprintf(out, "<bad-name>");
            return 1;
        }
        fprintf(out, "%s", name);
        return 1;
    }

    if (type == 15) { /* MX: preference + exchange */
        if (rdlen < 3) { fprintf(out, "<bad-MX>"); return 1; }
        size_t off = (size_t)(rdata - buf);
        uint16_t pref;
        if (!read_u16(buf, len, &off, &pref)) { fprintf(out, "<bad-MX>"); return 1; }
        char exch[1024];
        if (!dns_parse_name(buf, len, &off, exch, sizeof(exch))) {
            fprintf(out, "<bad-MX-name>");
            return 1;
        }
        fprintf(out, "%" PRIu16 " %s", pref, exch);
        return 1;
    }

    if (type == 16) { /* TXT */
        print_txt(out, rdata, rdlen);
        return 1;
    }

    if (type == 6) { /* SOA */
        size_t off = (size_t)(rdata - buf);
        char mname[1024], rname[1024];
        if (!dns_parse_name(buf, len, &off, mname, sizeof(mname))) { fprintf(out, "<bad-SOA>"); return 1; }
        if (!dns_parse_name(buf, len, &off, rname, sizeof(rname))) { fprintf(out, "<bad-SOA>"); return 1; }
        uint32_t serial, refresh, retry, expire, minimum;
        if (!read_u32(buf, len, &off, &serial) ||
            !read_u32(buf, len, &off, &refresh) ||
            !read_u32(buf, len, &off, &retry) ||
            !read_u32(buf, len, &off, &expire) ||
            !read_u32(buf, len, &off, &minimum)) {
            fprintf(out, "<bad-SOA-nums>");
            return 1;
        }
        fprintf(out, "%s %s %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32,
                mname, rname, serial, refresh, retry, expire, minimum);
        return 1;
    }

    if (type == 33) { /* SRV */
        if (rdlen < 7) { fprintf(out, "<bad-SRV>"); return 1; }
        size_t off = (size_t)(rdata - buf);
        uint16_t pri, weight, port;
        if (!read_u16(buf, len, &off, &pri) ||
            !read_u16(buf, len, &off, &weight) ||
            !read_u16(buf, len, &off, &port)) {
            fprintf(out, "<bad-SRV>");
            return 1;
        }
        char target[1024];
        if (!dns_parse_name(buf, len, &off, target, sizeof(target))) {
            fprintf(out, "<bad-SRV-name>");
            return 1;
        }
        fprintf(out, "%" PRIu16 " %" PRIu16 " %" PRIu16 " %s", pri, weight, port, target);
        return 1;
    }

    if (type == 41) { /* OPT (EDNS0) - pseudo-RR */
        /* For OPT: "CLASS" field is UDP payload size; TTL packs ext-rcode, version, flags */
        /* RDATA = list of options: (code,u16) (length,u16) (data...) */
        fprintf(out, "; EDNS0 options: ");
        size_t i = 0;
        int first = 1;
        while (i + 4 <= rdlen) {
            uint16_t oc = (uint16_t)((rdata[i] << 8) | rdata[i + 1]);
            uint16_t ol = (uint16_t)((rdata[i + 2] << 8) | rdata[i + 3]);
            i += 4;
            if (i + ol > rdlen) { fprintf(out, "<bad-opt-len>"); return 1; }
            if (!first) fprintf(out, ", ");
            first = 0;
            fprintf(out, "code=%" PRIu16 " len=%" PRIu16, oc, ol);
            /* Option data can be printed hex (avoid huge dumps) */
            if (ol > 0) {
                fprintf(out, " data=");
                size_t dump = ol > 32 ? 32 : ol;
                print_hex(out, rdata + i, dump);
                if (ol > dump) fprintf(out, " ...");
            }
            i += ol;
        }
        if (i != rdlen) fprintf(out, " <trailing-bytes>");
        return 1;
    }

    /* fallback: hex */
    fprintf(out, "\\# %zu ", rdlen);
    print_hex(out, rdata, rdlen);
    return 1;
}

/* -------------------- RR parsing + section printing -------------------- */

static int parse_question(FILE *out, const uint8_t *buf, size_t len, size_t *off) {
    char qname[1024];
    uint16_t qtype, qclass;

    if (!dns_parse_name(buf, len, off, qname, sizeof(qname))) return 0;
    if (!read_u16(buf, len, off, &qtype)) return 0;
    if (!read_u16(buf, len, off, &qclass)) return 0;

    fprintf(out, ";%s\t\t%s\t%s\n", qname, dns_class_to_str(qclass), dns_type_to_str(qtype));
    return 1;
}

static int parse_rr(FILE *out, const uint8_t *buf, size_t len, size_t *off, int is_additional) {
    (void)is_additional;
    char name[1024];
    uint16_t type, class_;
    uint32_t ttl;
    uint16_t rdlen;

    size_t rr_start = *off;

    if (!dns_parse_name(buf, len, off, name, sizeof(name))) return 0;
    if (!read_u16(buf, len, off, &type)) return 0;
    if (!read_u16(buf, len, off, &class_)) return 0;
    if (!read_u32(buf, len, off, &ttl)) return 0;
    if (!read_u16(buf, len, off, &rdlen)) return 0;

    if (*off + rdlen > len) return 0;

    const uint8_t *rdata = buf + *off;
    size_t rdata_off_in_msg = *off;

    /* dig-like line prefix */
    if (type == 41) {
        /* OPT pseudo-RR: TTL is special, CLASS is UDP size, NAME usually root */
        uint8_t ext_rcode = (uint8_t)((ttl >> 24) & 0xFF);
        uint8_t edns_ver  = (uint8_t)((ttl >> 16) & 0xFF);
        uint16_t edns_flags = (uint16_t)(ttl & 0xFFFF);

        fprintf(out, ";%s\t\t%s\t%s\t", name, dns_class_to_str(class_), "OPT");
        fprintf(out, "udp=%" PRIu16 " ext_rcode=%u ver=%u flags=0x%04x ",
                class_, ext_rcode, edns_ver, edns_flags);
        print_rdata(out, buf, len, type, rdata, rdlen, rdata_off_in_msg);
        fputc('\n', out);
    } else {
        fprintf(out, "%s\t%" PRIu32 "\t%s\t%s\t",
                name, ttl, dns_class_to_str(class_), dns_type_to_str(type));
        print_rdata(out, buf, len, type, rdata, rdlen, rdata_off_in_msg);
        fputc('\n', out);
    }

    *off += rdlen;

    /* sanity guard: avoid stalling if something weird happened */
    if (*off <= rr_start) return 0;
    return 1;
}

/* -------------------- main entry: dns_print_message -------------------- */

void dns_print_message(const void *data, size_t len, FILE *out) {
    const uint8_t *buf = (const uint8_t*)data;
    if (!buf || !out) return;

    if (len < 12) {
        fprintf(out, ";; <packet too short: %zu bytes>\n", len);
        return;
    }

    size_t off = 0;
    uint16_t id, flags, qd, an, ns, ar;

    if (!read_u16(buf, len, &off, &id) ||
        !read_u16(buf, len, &off, &flags) ||
        !read_u16(buf, len, &off, &qd) ||
        !read_u16(buf, len, &off, &an) ||
        !read_u16(buf, len, &off, &ns) ||
        !read_u16(buf, len, &off, &ar)) {
        fprintf(out, ";; <failed reading header>\n");
        return;
    }

    /* decode header flags */
    uint8_t qr     = (uint8_t)((flags >> 15) & 0x1);
    uint8_t opcode = (uint8_t)((flags >> 11) & 0xF);
    uint8_t aa     = (uint8_t)((flags >> 10) & 0x1);
    uint8_t tc     = (uint8_t)((flags >> 9)  & 0x1);
    uint8_t rd     = (uint8_t)((flags >> 8)  & 0x1);
    uint8_t ra     = (uint8_t)((flags >> 7)  & 0x1);
    uint8_t z      = (uint8_t)((flags >> 6)  & 0x1); /* historically "Z", now sometimes used; keep */
    uint8_t ad     = (uint8_t)((flags >> 5)  & 0x1);
    uint8_t cd     = (uint8_t)((flags >> 4)  & 0x1);
    uint8_t rcode  = (uint8_t)(flags & 0xF);

    fprintf(out, ";; ->>HEADER<<- opcode: %u, status: %s, id: %" PRIu16 "\n",
            opcode, rcode_to_str(rcode), id);
    fprintf(out, ";; flags:%s%s%s%s%s%s%s%s; QUERY: %" PRIu16 ", ANSWER: %" PRIu16
                 ", AUTHORITY: %" PRIu16 ", ADDITIONAL: %" PRIu16 "\n\n",
            qr ? " qr" : "",
            aa ? " aa" : "",
            tc ? " tc" : "",
            rd ? " rd" : "",
            ra ? " ra" : "",
            z  ? " z"  : "",
            ad ? " ad" : "",
            cd ? " cd" : "",
            qd, an, ns, ar);

    /* QUESTION SECTION */
    if (qd > 0) {
        fprintf(out, ";; QUESTION SECTION:\n");
        for (uint16_t i = 0; i < qd; i++) {
            if (!parse_question(out, buf, len, &off)) {
                fprintf(out, ";; <failed parsing question %u>\n", (unsigned)i);
                return;
            }
        }
        fputc('\n', out);
    }

    /* ANSWER SECTION */
    if (an > 0) {
        fprintf(out, ";; ANSWER SECTION:\n");
        for (uint16_t i = 0; i < an; i++) {
            if (!parse_rr(out, buf, len, &off, 0)) {
                fprintf(out, ";; <failed parsing answer rr %u>\n", (unsigned)i);
                return;
            }
        }
        fputc('\n', out);
    }

    /* AUTHORITY SECTION */
    if (ns > 0) {
        fprintf(out, ";; AUTHORITY SECTION:\n");
        for (uint16_t i = 0; i < ns; i++) {
            if (!parse_rr(out, buf, len, &off, 0)) {
                fprintf(out, ";; <failed parsing authority rr %u>\n", (unsigned)i);
                return;
            }
        }
        fputc('\n', out);
    }

    /* ADDITIONAL SECTION */
    if (ar > 0) {
        fprintf(out, ";; ADDITIONAL SECTION:\n");
        for (uint16_t i = 0; i < ar; i++) {
            if (!parse_rr(out, buf, len, &off, 1)) {
                fprintf(out, ";; <failed parsing additional rr %u>\n", (unsigned)i);
                return;
            }
        }
        fputc('\n', out);
    }

    if (off < len) {
        fprintf(out, ";; <trailing bytes: %zu>\n", len - off);
    } else if (off > len) {
        fprintf(out, ";; <internal error: parsed beyond end>\n");
    }

    /* dig usually prints timing, server, etc. We can’t from raw packet alone. */
}

const char *ipv4_to_string(uint32_t address)
{
    static _Thread_local char buffer[INET_ADDRSTRLEN];
    struct in_addr ipv4_address;

    ipv4_address.s_addr = address;
    if (inet_ntop(AF_INET, &ipv4_address, buffer, sizeof(buffer)) == NULL)
        return ("invalid IPv4");
    return (buffer);
}
