# Packet Sender HTTP Lite

Packet Sender HTTP Lite - попытка реализовать клон модуля http в Zgrab2 на Python3. Реализация подобного модулю http понадобилась ввиду
отсутствия в модуле http динамически создаваемых payloads и прочих возможностей.

Ключевые моменты:

- Python aiohttp (python3.8)
- работает достаточно быстро

###### Для чего написан и почему так:
1. Код запускается на машинах с 1 vCPU и минимум памяти
2. Много сетевых соединений
3. Читает из stdin ip-адреса, ip-адреса сетей (CIDR) и FQDN записи хостов!
4. Читает из файла(приоритет - чтение из stdin)
5. Пишет в stdout результаты
6. Пишет в файл результаты(приоритет - пишет в stdout)



**_Важно_**: На вход только IP-адреса, подсети в CIDR нотации или FQDN записи.

**_Важно_**: На выходе только записи в виде json, заданной в коде структуры.

###### Examples:

- python3 packetsenderhttplite.py -f /targets/targets.txt --port=443 --user-agent='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/603.3.8 (KHTML, like Gecko) Version/10.1.2 Safari/603.3.8' --show-only-success --use-https
- python3 packetsenderhttplite.py -f /targets/targets.txt --port=443 --use-https
- cat /targets/targets.txt | python3 packetsenderhttplite.py --port=443 --use-https


