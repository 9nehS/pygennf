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
>                     [-p PROTOCOL] [-b BYTES]
>
>UDP packets producer with scapy
>
>optional arguments:
>  -h, --help            show this help message and exit
>  -s SRC_IP, --source-ip SRC_IP
>                        Source IP of netflow packet(s).
>  -sp SRC_PORT, --source-port SRC_PORT
>                        Source port of netflow packet(s).
>  -d DST_IP, --dst-ip DST_IP
>                        Destination IP of netflow packet(s).
>  -dp DST_PORT, --dst-port DST_PORT
>                        Destination port of netflow packet(s).
>  -t TIME_INTERVAL, --time-interval TIME_INTERVAL
>                        Time interval to wait before sending each netflow packet.
>  -c PKT_COUNT, --pkt-count PKT_COUNT
>                        Packets count to be sent before this generator stopping.
>  -p PROTOCOL, --protocol PROTOCOL
>                        Protocols included in netflow data part, e.g. tcp(6) or udp(17).
>  -b BYTES, --bytes BYTES
>                        Bytes(octets) in single flow, e.g. 1024.


# Example of use:

 * Netflow 9:
> pygennf_v9.py --source-ip 10.19.5.54 --dst-ip 10.19.5.118 --dst-port 2062 -t 1 -c 3600 -p tcp -b 1024
