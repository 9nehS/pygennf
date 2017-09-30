# pygennf

Netflow packets generator with Scapy library

* How to install:
> git clone https://github.com/9nehS/pygennf.git
>
> python setup.py install

# Usage:

 * pygennf_v9.py --help

>usage: pygennf_v9.py [-h] [-s SRC_IP] [-sp SRC_PORT] [-d DST_IP]
>                     [-dp DST_PORT] [-t TIME_INTERVAL] [-c PKT_COUNT]
>                     [-fd FLOWS_DATA]
>
>Netflow packets generator with scapy
>
>optional arguments:
>
>  -h, --help            show this help message and exit
>
>  -s SRC_IP, --source-ip SRC_IP
>                        Source IP of netflow packet(s).
>
>  -sp SRC_PORT, --source-port SRC_PORT
>                        Source port of netflow packet(s).
>
>  -d DST_IP, --dst-ip DST_IP
>                        Destination IP of netflow packet(s).
>
>  -dp DST_PORT, --dst-port DST_PORT
>                        Destination port of netflow packet(s).
>
>  -t TIME_INTERVAL, --time-interval TIME_INTERVAL
>                        Time interval to wait before sending each netflow packet.
>
>  -c PKT_COUNT, --pkt-count PKT_COUNT
>                        Packets count to be sent before this generator stopping.
>
>  -fd FLOWS_DATA, --flows-data FLOWS_DATA
>                       Contents in flows data, e.g. ip1/mask:port1:ip2/mask:port2:protocol:direction:bytes.
>


# Example of use:

 * Netflow 9:
> pygennf_v9.py --source-ip 10.9.255.54 --dst-ip 10.9.255.118 --dst-port 2062 -t 1 -c 3600 -fd '69.31.102.10/32:12345:209.81.108.20/32:80:tcp:ingress:1024, 70.32.103.11/32:54321:210.81.108.21/32:21:udp:ingress:1024'
>
> ![2017-09-30_console_snapshot_01.png](https://github.com/9nehS/pygennf/blob/master/resources/2017-09-30_console_snapshot_01.png)
>
> ![2017-09-28_web_snapshot_01.png](https://github.com/9nehS/pygennf/blob/master/resources/2017-09-28_web_snapshot_01.png)