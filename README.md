
# Анализатор трафика

Использована библиотека PcapPlusPlus [https://pcapplusplus.github.io/]

Пример работы:
```
❯ sudo ./trafficAnalyzer_exec wlp4s0
Interface info:
   Interface name:        wlp4s0
   Interface IP address   192.168.1.138
   MAC address:           54:27:1e:0d:77:31
   Default gateway:       192.168.1.1
   Interface MTU:         1500
   DNS server:            192.168.1.1

Starting async capture...
Results:
Ethernet packet count: 554
IPv4 packet count:     535
IPv6 packet count:     16
TCP packet count:      296
UDP packet count:      251
DNS packet count:      62
HTTP packet count:     4
SSL packet count:      53

HTTP method: GET
HTTP URI: /1/resh/1_119.htm
HTTP host: exir.ru
HTTP user-agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36
HTTP cookie: _ym_uid=168176828189713435; _ym_d=1681768281; _ym_isad=1
HTTP full URL: exir.ru/1/resh/1_119.htm

HTTP method: GET
HTTP URI: /1/resh/1_119.htm
HTTP host: exir.ru
HTTP user-agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36
HTTP cookie: _ym_uid=168176828189713435; _ym_d=1681768281; _ym_isad=1
HTTP full URL: exir.ru/1/resh/1_119.htm
----------------------------------------------------
| Hostname                                 | Count |
----------------------------------------------------
| play.google.com                          | 9     |
| e2cs34.gcp.gvt2.com                      | 2     |
| e2c12.gcp.gvt2.com                       | 1     |
----------------------------------------------------
```
