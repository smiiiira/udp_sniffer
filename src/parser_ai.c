int parse_udp_packet(const u_char *pkt, uint32_t len, uint64_t *out_seq) {
    if (!pkt || !out_seq || len < sizeof(struct ether_header)) return -1;
    // ... (далее стандартный разбор с VLAN и проверками)
    const struct ip *ip = (const struct ip *)(pkt + offset);
    if (ip->ip_p != IPPROTO_UDP) return -1;
    // ...
    *out_seq = (uint64_t)hdr->numberpack;
    return 0;
}
