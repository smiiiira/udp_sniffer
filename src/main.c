#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <pcap.h>
#include <pthread.h>

#include "parser.h"
#include "stats.h"
#include "output.h"
#include "temp_monitor.h"
#include "utils.h"

#define REPORT_INTERVAL 2
#define DEFAULT_PORT 6065
#define LOG_FILE "udp_log.csv"
#define RESULTS_FILE "results.csv"
#define TEMP_LOG_FILE "temperature_log.csv"

/* Глобальные переменные, которые видны другим модулям */
int capture_running = 1;
uint16_t target_port = DEFAULT_PORT;
char snmp_target_ip[16] = "192.168.1.30";
char ssh_password[64] = "";
pcap_t *handle = NULL;
FILE *log_file = NULL;
FILE *temp_log_file = NULL;
time_t last_report_time = 0;
struct pcap_stat initial_stats;

void sigint_handler(int signum) {
    printf("\n\n[!] Получен сигнал завершения. Заканчиваем захват...\n");
    capture_running = 0;
    if (handle) pcap_breakloop(handle);
}

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *pkt) {
    stats.total_packets++;
    stats.total_bytes += h->len;

    parsed_packet_t parsed = {0};
    
    // Вызов нашего модуля парсинга
    if (parse_udp_packet(pkt, h->len, &parsed) == 0) {
        stats.total_payload_bytes += parsed.payload_len;

        struct ip_port_stats *s = find_or_create_ip_port(parsed.src_ip, parsed.dport);
        if (s) {
            s->packets++;
            s->bytes += parsed.payload_len;
            if (s->first_seen.tv_sec == 0) s->first_seen = h->ts;
            s->last_seen = h->ts;
            update_period_stats(s, &h->ts);

            if (parsed.has_seq) {
                long seq = parsed.seq_num;
                if (!s->has_seq) {
                    s->first_seq = s->last_seq = seq;
                    s->has_seq = 1;
                } else {
                    if (seq < s->last_seq - SEQ_OVERFLOW_THRESHOLD) {
                        s->first_seq = s->last_seq = seq;
                    } else if (seq > s->last_seq) {
                        if (seq > s->last_seq + 1) {
                            s->loss_count += (seq - s->last_seq - 1);
                        }
                        s->last_seq = seq;
                    }
                }
            }
        }

        if (log_file) {
            fprintf(log_file, "%ld.%06ld,%s,%d,%d,%u\n",
        h->ts.tv_sec, h->ts.tv_usec, parsed.src_ip, parsed.dport, parsed.payload_len, h->len);
            fflush(log_file);
        }
    }

    time_t now = time(NULL);
    if (now - last_report_time >= REPORT_INTERVAL) {
        last_report_time = now;
        print_current_stats();
    }
}

int main(int argc, char *argv[]) {
    pthread_t temp_thread;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devs, *d;

    if (argc > 1) {
        int p = atoi(argv[1]);
        if (p > 0 && p < 65536) target_port = p;
    }
    if (argc > 2) {
        strncpy(snmp_target_ip, argv[2], sizeof(snmp_target_ip) - 1);
        snmp_target_ip[sizeof(snmp_target_ip)-1] = '\0';
    }
    if (argc > 3) {
        strncpy(ssh_password, argv[3], sizeof(ssh_password) - 1);
        ssh_password[sizeof(ssh_password)-1] = '\0';
    } else {
        fprintf(stderr, "Пароль не указан. Используйте: ./udp_sniffer <порт> <IP> <пароль>\n");
        return 1;
    }

    signal(SIGINT, sigint_handler);
    clear_screen();

    printf("ПРОМЫШЛЕННЫЙ UDP АНАЛИЗАТОР v3.4 (SSH+sshpass)\n");
    printf("Целевой порт: %d | IP коммутатора: %s\n\n", target_port, snmp_target_ip);

    log_file = fopen(LOG_FILE, "w");
    if (log_file) fprintf(log_file, "timestamp,src_ip,port,payload_len,total_len\n");

    temp_log_file = fopen(TEMP_LOG_FILE, "w");
    if (temp_log_file) fprintf(temp_log_file, "timestamp,temperature_celsius\n");

    // Запуск фонового потока температуры
    if (pthread_create(&temp_thread, NULL, temperature_polling_thread, NULL) != 0) {
        fprintf(stderr, "Ошибка создания потока SSH-опроса\n");
    }

    if (pcap_findalldevs(&devs, errbuf) < 0) {
        printf("Ошибка получения списка интерфейсов: %s\n", errbuf);
        return 1;
    }

    printf("Доступные сетевые интерфейсы:\n");
    int num = 0;
    for (d = devs; d; d = d->next) {
        printf(" %d. %s%s%s\n", ++num, d->name,
               d->description ? " - " : "", d->description ? d->description : "");
    }

    printf("\nВыберите номер интерфейса (0 = авто): ");
    int choice = 0;
    if (scanf("%d", &choice) != 1) choice = 0;

    char *dev_name = NULL;
    if (choice > 0 && choice <= num) {
        d = devs;
        for (int i = 1; i < choice; i++) d = d->next;
        dev_name = d->name;
    } else {
        for (d = devs; d; d = d->next) {
            if (strcmp(d->name, "lo") != 0) {
                dev_name = d->name;
                break;
            }
        }
    }
    if (!dev_name) dev_name = (char*)"any";

    printf("\nОткрываем интерфейс %s...\n", dev_name);
    handle = pcap_open_live(dev_name, 65535, 1, 1000, errbuf);
    if (!handle) {
        printf("Ошибка открытия интерфейса: %s\n", errbuf);
        pcap_freealldevs(devs);
        return 1;
    }

    if (pcap_stats(handle, &initial_stats) == 0) {
        stats.dropped_by_kernel_start = initial_stats.ps_drop;
    }

    char filter_exp[256];
    snprintf(filter_exp, sizeof(filter_exp), "ip proto UDP and port %d", target_port);
    printf("Устанавливаем фильтр: %s\n", filter_exp);

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Ошибка компиляции фильтра: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        pcap_freealldevs(devs);
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Ошибка установки фильтра: %s\n", pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        pcap_freealldevs(devs);
        return 1;
    }
    pcap_freecode(&fp);

    printf("Готово. Захват запущен. Нажмите Ctrl+C для остановки.\n\n");
    last_report_time = time(NULL);
    print_current_stats();

    pcap_loop(handle, 0, packet_handler, NULL);

    capture_running = 0;
    pthread_join(temp_thread, NULL);

    struct pcap_stat final_stats;
    if (pcap_stats(handle, &final_stats) == 0) {
        stats.dropped_by_kernel_end = final_stats.ps_drop;
        stats.dropped_by_kernel = stats.dropped_by_kernel_end - stats.dropped_by_kernel_start;
    }

    pcap_close(handle);
    pcap_freealldevs(devs);
    if (log_file) fclose(log_file);
    if (temp_log_file) fclose(temp_log_file);

    save_results(RESULTS_FILE);
    
    // Вывод температуры в итоговый лог (дописываем в конец файла)
    FILE *f = fopen(RESULTS_FILE, "a");
    if (f) {
        pthread_mutex_lock(&temp.lock);
        if (temp.count > 0) {
            fprintf(f, "\n# Статистика температуры\n");
            fprintf(f, "temp_count,%d\n", temp.count);
            fprintf(f, "temp_avg,%.1f\n", temp.sum_temp / temp.count);
            fprintf(f, "temp_min,%.1f\n", temp.min_temp);
            fprintf(f, "temp_max,%.1f\n", temp.max_temp);
        }
        pthread_mutex_unlock(&temp.lock);
        fclose(f);
    }

    print_final_stats();

    printf("\nЗавершено. Результаты сохранены в %s, %s и %s\n",
           LOG_FILE, RESULTS_FILE, TEMP_LOG_FILE);

    return 0;
}