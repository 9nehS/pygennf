#!/bin/env python
#
#  pygennf: UDP packets producer with scapy.
#  Copyright (C) 2016-2017  Sheng Zhao <sheng.zhao@calix.com>
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Affero General Public License as
#  published by the Free Software Foundation, either version 3 of the
#  License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU Affero General Public License for more details.
#
#  You should have received a copy of the GNU Affero General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import time
import signal
import re

import scapy
from scapy.all import *

import rb_netflow.rb_netflow as rbnf

SIGNAL_RECEIVED = 0

DIC_PROTOCOL_NUM = {'tcp': 6, 'udp': 17}
DIC_DIRECTION_NUM = {'ingress': 0, 'egress': 1}

# ip1/mask:port1:ip2/mask:port2:protocol:direction:bytes
# e.g. 11.11.11.11/32:1001:11.11.11.22/32:1002:tcp:ingress:1024
FLOW_DATA_PATTERN = r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}:\d{1,4}:){2}\w+:(ingress|egress):\d{1,4}$'
DEFAULT_FLOW_DATA = '11.11.11.11/32:1001:11.11.11.22/32:80:tcp:ingress:1024'

def preexec():
    os.setpgrp()  # Don't forward signals


def signal_handler(signal, frame):
    global SIGNAL_RECEIVED
    SIGNAL_RECEIVED = 1


def valid_flow_data(flow_data_str=''):
    global FLOW_DATA_PATTERN
    m = re.match(FLOW_DATA_PATTERN, flow_data_str)
    if m is not None:
        return True
    return False


# Netflow9
def main():

    print "\n****************************"
    print "* Flow Generator Ver. 0.11 *"
    print "* Modified by Sheng Zhao   *"
    print "* Calix Cloud SIT          *"
    print "* sheng.zhao@calix.com     *"
    print "****************************\n\n"

    if os.getuid() != 0:
        print "You need to be root to run this, sorry."
        return

    parser = argparse.ArgumentParser(description='Netflow packets generator with scapy')
    parser.add_argument('-s', '--source-ip', dest='src_ip',
                        help='Source IP of netflow packet(s).')
    parser.add_argument('-sp', '--source-port', dest='src_port',
                        help='Source port of netflow packet(s).')
    parser.add_argument('-d', '--dst-ip', dest='dst_ip',
                        help='Destination IP of netflow packet(s).')
    parser.add_argument('-dp', '--dst-port', dest='dst_port',
                        help='Destination port of netflow packet(s).')
    parser.add_argument('-t', '--time-interval', dest='time_interval',
                        help='Time interval to wait before sending each netflow packet.')
    parser.add_argument('-c', '--pkt-count', dest='pkt_count',
                        help='Packets count to be sent before this generator stopping.')
    parser.add_argument('-p', '--protocol', dest='protocol',
                        help='Protocols included in netflow data part, e.g. tcp(6) or udp(17).')
    parser.add_argument('-b', '--bytes', dest='bytes',
                        help='Bytes(octets) in single flow, e.g. 1024.')
    parser.add_argument('-fd', '--flows-data', dest='flows_data',
                        help='Contents in flows data, e.g. ip1/mask:port1:ip2/mask:port2:protocol:direction:bytes.')

    args = parser.parse_args()
    if args.src_ip:
        IP_SRC = args.src_ip
    else:
        IP_SRC = "10.0.203.2"

    if args.dst_ip:
        IP_DST = args.dst_ip
    else:
        IP_DST = "10.0.30.89"

    if IP_DST == "127.0.0.1":
        conf.L3socket=L3RawSocket

    if args.src_port:
        PORT_SRC = int(args.src_port)
    else:
        PORT_SRC = int(2056)

    if args.dst_port:
        PORT_DST = int(args.dst_port)
    else:
        PORT_DST = int(2055)

    if args.time_interval:
        TIME_INTERVAL = args.time_interval
    else:
        TIME_INTERVAL = 1

    if args.pkt_count:
        PKT_COUNT = int(args.pkt_count)
    else:
        # 0xFFFFFFFF - 1
        PKT_COUNT = 4294967294

    if args.protocol:
        try:
            PROTOCOL_NUM = DIC_PROTOCOL_NUM[args.protocol]
        except KeyError:
            print "Protocol '%s' cannot be mapped to existing protocols, use TCP[6] as default" % (args.protocol)
            PROTOCOL_NUM = 6
    else:
        PROTOCOL_NUM = 6    # TCP by default

    if args.bytes:
        try:
            BYTES = int(args.bytes)
            if BYTES < 1 or BYTES > 4096:
                raise ValueError
        except ValueError:
            print "Bytes '%s' should be integer between 1 and 4096, use 1024 as default" % (args.bytes)
            BYTES = 1024
    else:
        BYTES = 1024

    if args.flows_data:
        FLOW_DATA_LIST = args.flows_data.split(',')
        FLOW_DATA_LIST = map(str.strip, FLOW_DATA_LIST)
        FLOW_DATA_LIST = filter(valid_flow_data, FLOW_DATA_LIST)
        print 'FLOW_DATA_LIST: ' % FLOW_DATA_LIST
    else:
        print "'args.flows_data' is empty, default flow data list will be used..."
        print "Default flow data: %s" % (DEFAULT_FLOW_DATA)
        FLOW_DATA_LIST = []
        FLOW_DATA_LIST.append(DEFAULT_FLOW_DATA)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    flow_sequence = 1

    gen_send_pkt('tmpl', flow_sequence=flow_sequence, src_ip=IP_SRC, dst_ip=IP_DST, sport=PORT_SRC, dport=PORT_DST)

    while TIME_INTERVAL is not 0:
        if SIGNAL_RECEIVED == 1:
            print "\nSignal received. %s packets have been sent. Stopping and Exiting..." % flow_sequence
            sys.exit(0)
        time.sleep(float(TIME_INTERVAL))

        flow_sequence = flow_sequence + 1
        if flow_sequence > PKT_COUNT:
            print "\nPackets count[%s] reached. Stopping and Exiting..." % PKT_COUNT
            sys.exit(0)
        if flow_sequence % 100 == 0:
            gen_send_pkt('tmpl', flow_sequence=flow_sequence, src_ip=IP_SRC, dst_ip=IP_DST,
                         sport=PORT_SRC, dport=PORT_DST, protocol_num=PROTOCOL_NUM, octets=BYTES)
            continue
        gen_send_pkt('data', flow_sequence, src_ip=IP_SRC, dst_ip=IP_DST, sport=PORT_SRC, dport=PORT_DST,
                     protocol_num=PROTOCOL_NUM, octets=BYTES, flow_data_list=FLOW_DATA_LIST)


def gen_send_pkt(pkt_type='data', flow_sequence=1, src_ip='1.1.1.1', dst_ip = '2.2.2.2', sport=2056, dport=2055,
                 protocol_num=6, octets=1024, flow_data_list=[]):
    timestamp = int(time.time())
    if pkt_type == 'tmpl':
        pkt_netflow_tmpl = gen_pkt_netflow_tmpl(timestamp=timestamp, flow_sequence=flow_sequence,
                                                src_ip=src_ip, dst_ip =dst_ip, sport=sport, dport=dport)
        #wrpcap('v9_test_tmpl.pcap', pkt_netflow_tmpl)
        sys.stdout.write("Sending packet: %d \r" % (flow_sequence))
        send(pkt_netflow_tmpl, verbose=0)
        sys.stdout.flush()
    elif pkt_type == 'data':
        sys_uptime = 3600 * 1000
        pkt_netflow_data = gen_pkt_netflow_data(timestamp=timestamp, sys_uptime=sys_uptime, flow_sequence=flow_sequence,
                                                src_ip=src_ip, dst_ip=dst_ip, sport=sport, dport=dport,
                                                protocol_num=protocol_num, octets=octets, flow_data_list=flow_data_list)
        #wrpcap('v9_test_data.pcap', pkt_netflow_data)
        sys.stdout.write("Sending packet: %d \r" % (flow_sequence))
        send(pkt_netflow_data, verbose=0)
        sys.stdout.flush()


def gen_pkt_netflow_data(timestamp=1503652676, flow_sequence=1, sys_uptime=3600000, src_ip='121.41.5.67',
                         dst_ip='121.41.5.68', sport=2056, dport=2055, protocol_num=6, octets=1024, flow_data_list=[]):
    header_v9 = rbnf.Netflow_Headerv9(version=9, count=1, SysUptime=0x000069d7, Timestamp=timestamp,
                                      FlowSequence=flow_sequence, SourceId=2177)
    flowset_flow_header_v9 = rbnf.FlowSet_Header_v9(FlowSet_id=260, FlowSet_length=72)

    # List for SrcAddr and DstAddr in netflow data
    # src_dst_addr_list = []
    # src_dst_addr_list.append(['69.31.102.10', '209.81.108.20'])
    # src_dst_addr_list.append(['70.32.103.11', '210.81.108.21'])
    # src_dst_addr_list.append(['70.32.103.12', '210.81.108.22'])
    # src_dst_addr_list.append(['70.32.103.13', '210.81.108.23'])
    # src_dst_addr_list.append(['70.32.103.14', '210.81.108.24'])
    # src_dst_addr_list.append(['70.32.103.15', '210.81.108.25'])
    # src_dst_addr_list.append(['70.32.103.16', '210.81.108.26'])
    # src_dst_addr_list.append(['70.32.103.17', '210.81.108.27'])
    # src_dst_addr_list.append(['70.32.103.18', '210.81.108.28'])
    # src_dst_addr_list.append(['70.32.103.19', '210.81.108.29'])
    # src_dst_addr_list.append(['70.32.103.20', '210.81.108.30'])
    # src_dst_addr_list.append(['70.32.103.21', '210.81.108.31'])
    # src_dst_addr_list.append(['70.32.103.22', '210.81.108.32'])
    # src_dst_addr_list.append(['70.32.103.23', '210.81.108.33'])
    # src_dst_addr_list.append(['70.32.103.24', '210.81.108.34'])
    # src_dst_addr_list.append(['70.32.103.25', '210.81.108.35'])
    # src_dst_addr_list.append(['70.32.103.26', '210.81.108.36'])
    # src_dst_addr_list.append(['70.32.103.27', '210.81.108.37'])
    # src_dst_addr_list.append(['70.32.103.28', '210.81.108.38'])
    # src_dst_addr_list.append(['70.32.103.29', '210.81.108.39'])
    # src_dst_addr_list.append(['70.32.103.30', '210.81.108.40'])
    # src_dst_port_list = []
    # src_dst_port_list.append([12345, 80])

    # List for flows in one packet
    flows = []
    # for src_dst_addr in src_dst_addr_list:
    #     #end_time = sys_uptime + 3600 * 1000
    #     end_time = timestamp
    #     start_time = end_time - 1000     # Duration 1s
    #     flows.append(rbnf.Flow_260_v9(
    #         Packets=1, Octets=octets, SrcAddr=src_dst_addr[0], DstAddr=src_dst_addr[1], InputInt=145, OutputInt=142,
    #         EndTime=end_time, StartTime=start_time, SrcPort=src_dst_port_list[0][0], DstPort=src_dst_port_list[0][1],
    #         SrcAS=0, DstAS=0, BGPNextHop='0.0.0.0', SrcMask=17, DstMask=28, Protocol=protocol_num, TCPFlags=0x10, IPToS=0x00,
    #         Direction=0, ForwardingStatus=0x40, SamplerID=2, IngressVRFID=0x60000000, EgressVRFID=0x60000000
    #     ))

    # To process flow_data_list
    for flow_data in flow_data_list:
        data_item_list = flow_data.split(':')
        src_addr = data_item_list[0].split('/')[0]
        src_mask = int(data_item_list[0].split('/')[1])
        src_port = int(data_item_list[1])
        dst_addr = data_item_list[2].split('/')[0]
        dst_mask = int(data_item_list[2].split('/')[1])
        dst_port = int(data_item_list[3])
        protocol_num = DIC_PROTOCOL_NUM[data_item_list[4]]
        direction = DIC_DIRECTION_NUM[data_item_list[5]]
        bytes = int(data_item_list[6])
        end_time = timestamp
        start_time = end_time - 1000  # Duration 1s
        flows.append(rbnf.Flow_260_v9(
            Packets=1, Octets=bytes, SrcAddr=src_addr, DstAddr=dst_addr, InputInt=145, OutputInt=142,
            EndTime=end_time, StartTime=start_time, SrcPort=src_port, DstPort=dst_port,
            SrcAS=0, DstAS=0, BGPNextHop='0.0.0.0', SrcMask=src_mask, DstMask=dst_mask, Protocol=protocol_num,
            TCPFlags=0x10, IPToS=0x00, Direction=direction, ForwardingStatus=0x40, SamplerID=2, IngressVRFID=0x60000000,
            EgressVRFID=0x60000000
        ))

    # Calculate the length of netflow data before padding
    len_netflow = 0
    len_netflow = calc_netflow_len(header_v9, flowset_flow_header_v9, flows)
    pad_len = 0
    pad = None
    #print 'len_netflow:', len_netflow
    #sys.stdout.write("len_netflow: %d\n" % (len_netflow))
    len_after_padding = 0

    # Padding to make sure that FlowSet starts at a 4-byte aligned boundary -- rfc3954.txt
    if len_netflow % 4 != 0:
        len_after_padding = ((len_netflow / 4) + 1) * 4
        pad_len = len_after_padding - len_netflow
        #print 'pad_len:', pad_len
        #sys.stdout.write("pad_len: %d\n" % (pad_len))
    else:
        len_after_padding = len_netflow

    header_v9.setfieldval('count', len(flows))
    flowset_flow_header_v9.setfieldval('FlowSet_length', len_after_padding - 20)
    pkt_netflow_data = IP(src=src_ip, dst=dst_ip, len=len_after_padding + 28) / UDP(sport=sport, dport=dport,
                                                                                    len=len_after_padding + 8)
    pkt_netflow_data /= header_v9 / flowset_flow_header_v9
    for flow in flows:
        pkt_netflow_data /= flow

    if pad_len > 0:
        pad = Padding()
        pad.load = '\x00' * pad_len
        pkt_netflow_data = pkt_netflow_data / pad

    return pkt_netflow_data


def calc_netflow_len(header, flowset_flow_header, flows):
    len_netflow = 0
    len_netflow = len(header) + len(flowset_flow_header)
    for flow in flows:
        len_netflow = len_netflow + len(flow)

    return len_netflow


def gen_pkt_netflow_tmpl(timestamp=1503652676, flow_sequence=1, source_id=2177, template_id=260, src_ip='121.41.5.67',
                         dst_ip='121.41.5.68', sport=2056, dport=2055):
    header_v9 = rbnf.Netflow_Headerv9(version=9, count=1, SysUptime=0x000069d7, Timestamp=timestamp, FlowSequence=flow_sequence,SourceId=source_id)
    flowset_tmpl_header_v9 = rbnf.FlowSet_Header_v9(FlowSet_id=0, FlowSet_length=100)
    flowset_tmpl_data_header_v9 = rbnf.FlowTemplate_ID_v9(template_id=template_id,count=23)
    flowset_tmpl_data_260_v9 = [
        # Field (1/23): PKTS, Type: 2, Length: 4
        rbnf.NetFlowTemplatev9Field(type_template=2, length= 4),
        # Field (2/23): BYTES, Type: 1, Length: 4
        rbnf.NetFlowTemplatev9Field(type_template=1, length= 4),
        # Field (3/23): IP_SRC_ADDR, Type: 8, Length: 4
        rbnf.NetFlowTemplatev9Field(type_template=8, length= 4),
        # Field (4/23): IP_DST_ADDR, Type: 12, Length: 4
        rbnf.NetFlowTemplatev9Field(type_template=12, length= 4),
        # Field (5/23): INPUT_SNMP, Type: 10, Length: 4
        rbnf.NetFlowTemplatev9Field(type_template=10, length= 4),
        # Field (6/23): OUTPUT_SNMP, Type: 14, Length: 4
        rbnf.NetFlowTemplatev9Field(type_template=14, length= 4),
        # Field (7/23): LAST_SWITCHED, Type: 21, Length: 4
        rbnf.NetFlowTemplatev9Field(type_template=21, length= 4),
        # Field (8/23): FIRST_SWITCHED, Type: 22, Length: 4
        rbnf.NetFlowTemplatev9Field(type_template=22, length= 4),
        # Field (9/23): L4_SRC_PORT, Type: 7, Length: 2
        rbnf.NetFlowTemplatev9Field(type_template=7, length= 2),
        # Field (10/23): L4_DST_PORT, Type: 11, Length: 2
        rbnf.NetFlowTemplatev9Field(type_template=11, length= 2),
        # Field (11/23): SRC_AS, Type: 16, Length: 4
        rbnf.NetFlowTemplatev9Field(type_template=16, length= 4),
        # Field (12/23): DST_AS, Type: 17, Length: 4
        rbnf.NetFlowTemplatev9Field(type_template=17, length= 4),
        # Field (13/23): BGP_NEXT_HOP, Type: 18, Length: 4
        rbnf.NetFlowTemplatev9Field(type_template=18, length= 4),
        # Field (14/23): SRC_MASK, Type: 9, Length: 1
        rbnf.NetFlowTemplatev9Field(type_template=9, length= 1),
        # Field (15/23): DST_MASK, Type: 13, Length: 1
        rbnf.NetFlowTemplatev9Field(type_template=13, length= 1),
        # Field (16/23): PROTOCOL, Type: 4, Length: 1
        rbnf.NetFlowTemplatev9Field(type_template=4, length= 1),
        # Field (17/23): TCP_FLAGS, Type: 6, Length: 1
        rbnf.NetFlowTemplatev9Field(type_template=6, length= 1),
        # Field (18/23): IP_TOS, Type: 5, Length: 1
        rbnf.NetFlowTemplatev9Field(type_template=5, length= 1),
        # Field (19/23): DIRECTION, Type: 61, Length: 1
        rbnf.NetFlowTemplatev9Field(type_template=61, length=1),
        # Field (20/23): FORWARDING_STATUS, Type: 89, Length: 1
        rbnf.NetFlowTemplatev9Field(type_template=89, length=1),
        # Field (21/23): FLOW_SAMPLER_ID, Type: 48, Length: 2
        rbnf.NetFlowTemplatev9Field(type_template=48, length=2),
        # Field (22/23): ingressVRFID, Type: 234, Length: 4
        rbnf.NetFlowTemplatev9Field(type_template=234, length=4),
        # Field (23/23): egressVRFID, Type: 235, Length: 4
        rbnf.NetFlowTemplatev9Field(type_template=235, length=4)
        ]

    pkt_netflow_tmpl = IP(src=src_ip,dst=dst_ip)/UDP(sport=sport,dport=dport)
    pkt_netflow_tmpl/=header_v9/flowset_tmpl_header_v9/flowset_tmpl_data_header_v9

    for t in flowset_tmpl_data_260_v9:
        pkt_netflow_tmpl/=t

    return pkt_netflow_tmpl


if __name__ == '__main__':
    main()

