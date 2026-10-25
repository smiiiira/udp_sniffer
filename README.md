# udp_sniffer
Программное средство для мониторинга зеркального Ethernet-трафика промышленных коммутаторов.

## Сборка
Для сборки проекта выполните:
gcc -o udp_sniffer src/main.c src/parser.c src/stats.c src/output.c src/temp_monitor.c src/utils.c -lpcap -lm -lpthread

## Запуск
sudo ./udp_sniffer <порт> <IP_коммутатора> <SSH_пароль>