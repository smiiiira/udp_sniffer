#include "parser.h"
#include "packet_format.h"
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <string.h>

int parse_udp_packet(const u_char *pkt, uint32_t len, parsed_packet_t *out) {
    if (!pkt || !out || len < sizeof(struct ether_header)) return -1;

    const struct ether_header *eth = (const struct ether_header *)pkt;
    uint16_t etype = ntohs(eth->ether_type);
    uint32_t offset = sizeof(struct ether_header);

    // Поддержка VLAN (802.1Q)
    if (etype == 0x8100) {
        if (len < offset + 4) return -1;
        etype = ntohs(*(const uint16_t *)(pkt + offset + 2));
        offset += 4;
    }

    if (etype != ETHERTYPE_IP) return -1;
    if (len < offset + sizeof(struct ip)) return -1;

    const struct ip *ip = (const struct ip *)(pkt + offset);
    if (ip->ip_p != IPPROTO_UDP) return -1;

    offset += ip->ip_hl * 4;
    if (len < offset + sizeof(struct udphdr)) return -1;

    const struct udphdr *udp = (const struct udphdr *)(pkt + offset);
    uint16_t udplen = ntohs(udp->uh_ulen);
    if (udplen < sizeof(struct udphdr)) return -1;

    out->payload_len = udplen - sizeof(struct udphdr);
    out->dport = ntohs(udp->uh_dport);
    inet_ntop(AF_INET, &ip->ip_src, out->src_ip, sizeof(out->src_ip));
    out->has_seq = 0;

    if (out->payload_len >= sizeof(struct headerbuffer)) {
        const struct headerbuffer *hdr = (const struct headerbuffer *)(pkt + offset + sizeof(struct udphdr));
        out->seq_num = hdr->numberpack;
        out->has_seq = 1;
    }

    return 0;
}