#ifndef PARSER_H
#define PARSER_H

#include <stdint.h>
#include <pcap.h>

// Структура для передачи результатов разбора
typedef struct {
    char src_ip[16];
    uint16_t dport;
    int payload_len;
    long seq_num;
    int has_seq;
} parsed_packet_t;

/**
 * @brief Разбирает Ethernet-кадр и извлекает данные UDP.
 * @return 0 при успехе, -1 при ошибке.
 */
int parse_udp_packet(const u_char *pkt, uint32_t len, parsed_packet_t *out);

#endif // PARSER_H