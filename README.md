# udp_sniffer
Программное средство для мониторинга зеркального Ethernet-трафика промышленных коммутаторов.

## Сборка
Для сборки проекта выполните:
gcc -o udp_sniffer src/main.c src/parser.c src/stats.c src/output.c src/temp_monitor.c src/utils.c -lpcap -lm -lpthread

## Запуск
sudo ./udp_sniffer <порт> <IP_коммутатора> <SSH_пароль>

## 🧪 Ветка эксперимента (experiment/ai-agent)
В данной ветке представлены результаты сравнения ручного написания кода и генерации с помощью LLM (ChatGPT и DeepSeek).

Файлы для сравнения в папке `src/`:
* `parser_manual.c` — ручная реализация (без проверки NULL)
* `parser_ai.c` — реализация от ChatGPT (с проверкой NULL)
* `parser_deepseek.c` — реализация от DeepSeek (использованы магические числа)
* `tests/test_parser.c` — unit-тесты для проверки всех трех реализаций