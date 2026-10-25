#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <pcap.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>

// Подключаем структуры
#include "../src/packet_format.h"

// 1. Подтягиваем ручную реализацию с переименованием
#define parse_udp_packet parse_udp_packet_manual
#include "../src/parser_manual.c"
#undef parse_udp_packet

// 2. Подтягиваем ChatGPT
#define parse_udp_packet parse_udp_packet_ai
#include "../src/parser_ai.c"
#undef parse_udp_packet

// 3. Подтягиваем DeepSeek
#define parse_udp_packet parse_udp_packet_deepseek
#include "../src/parser_deepseek.c"
#undef parse_udp_packet

// Функция для создания фейкового UDP-пакета
void create_valid_udp_packet(u_char *buffer, uint32_t *len) {
    memset(buffer, 0, 256); // Очищаем весь буфер
    buffer[12] = 0x08; buffer[13] = 0x00; // Ethernet type: IPv4
    buffer[14] = 0x45; // IPv4 version/IHL
    buffer[14 + 9] = 17; // Protocol: UDP
    
    uint16_t udp_len = 8 + sizeof(struct headerbuffer);
    buffer[34 + 4] = (udp_len >> 8) & 0xFF;
    buffer[34 + 5] = udp_len & 0xFF;

    struct headerbuffer *hdr = (struct headerbuffer *)(buffer + 34 + 8);
    hdr->numberpack = 42;
    *len = 34 + 8 + sizeof(struct headerbuffer);
}

// Универсальная функция для запуска тестов
void run_tests(const char *impl_name, int (*parse_func)(const u_char*, uint32_t, uint64_t*)) {
    printf("--- Тестирование реализации: %s ---\n", impl_name);
    int passed = 0;
    u_char pkt[256]; // Увеличенный буфер
    uint32_t len;
    uint64_t seq;

    // Тест 1: Корректный пакет
    create_valid_udp_packet(pkt, &len);
    if (parse_func(pkt, len, &seq) == 0 && seq == 42) {
        printf("[PASS] Тест 1: Корректный UDP пакет\n"); passed++;
    } else printf("[FAIL] Тест 1\n");

    // Тест 2: VLAN
    create_valid_udp_packet(pkt, &len);
    memmove(pkt + 16, pkt + 12, len - 12); 
    pkt[12] = 0x81; pkt[13] = 0x00; pkt[16] = 0x08; pkt[17] = 0x00;
    len += 4;
    if (parse_func(pkt, len, &seq) == 0 && seq == 42) {
        printf("[PASS] Тест 2: Пакет с VLAN\n"); passed++;
    } else printf("[FAIL] Тест 2\n");

    // Тест 3: Не UDP (TCP)
    create_valid_udp_packet(pkt, &len);
    pkt[14 + 9] = 6; 
    if (parse_func(pkt, len, &seq) == -1) {
        printf("[PASS] Тест 3: Не UDP пакет\n"); passed++;
    } else printf("[FAIL] Тест 3\n");

    // Тест 4: NULL (Передаем NULL, но с валидной длиной len=100)
    pid_t pid = fork();
    if (pid == 0) {
        // Дочерний процесс
        exit(parse_func(NULL, 100, &seq) == -1 ? 0 : 1);
    } else {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            printf("[PASS] Тест 4: Обработка NULL указателя\n"); passed++;
        } else {
            printf("[FAIL] Тест 4: Программа упала (Segfault) при передаче NULL\n");
        }
    }
    printf("Итого: %d/4 тестов пройдено.\n\n", passed);
}

int main() {
    printf("==========================================\n");
    printf("ЗАПУСК UNIT-ТЕСТОВ \n");
    printf("==========================================\n\n");
    run_tests("Ручная реализация (Manual)", parse_udp_packet_manual);
    run_tests("ChatGPT (GPT-4o)", parse_udp_packet_ai);
    run_tests("DeepSeek-Coder", parse_udp_packet_deepseek);
    return 0;
}