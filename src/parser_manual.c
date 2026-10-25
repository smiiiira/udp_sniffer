#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <pcap.h>
#include "packet_format.h"

int parse_udp_packet(const u_char *pkt, uint32_t len, uint64_t *out_seq) {
    if (len < sizeof(struct ether_header)) return -1;
    struct ether_header *eth = (struct ether_header*)pkt;
    uint16_t etype = ntohs(eth->ether_type);
    uint32_t offset = sizeof(struct ether_header);

    if (etype == 0x8100 && len >= offset + 4) {
        etype = ntohs(*(uint16_t*)(pkt + offset + 2));
        offset += 4;
    }
    if (etype != ETHERTYPE_IP) return -1;
    
    struct ip *ip = (struct ip*)(pkt + offset);
    if (ip->ip_p != IPPROTO_UDP) return -1;
    offset += ip->ip_hl * 4;

    struct udphdr *udp = (struct udphdr*)(pkt + offset);
    int payload_len = ntohs(udp->uh_ulen) - 8;
    if (payload_len < sizeof(struct headerbuffer)) return -1;

    struct headerbuffer *hdr = (struct headerbuffer*)(pkt + offset + 8);
    *out_seq = hdr->numberpack;
    return 0;
}