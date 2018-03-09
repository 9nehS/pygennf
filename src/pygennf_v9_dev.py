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
import signal
import threading

from flask import Flask, jsonify, request, abort
from scapy.all import *

import rb_netflow.rb_netflow as rbnf
from utils.logger_util import get_logger, set_logger_level
from utils.uuid_util import get_uuid

SIGNAL_RECEIVED = 0
DIC_PROTOCOL_NUM = {'tcp': 6, 'udp': 17}
DIC_DIRECTION_NUM = {'ingress': 0, 'egress': 1}

# ip1/mask:port1:ip2/mask:port2:protocol:direction:bytes
# e.g. 11.11.11.11/32:1001:11.11.11.22/32:1002:tcp:ingress:1024
FLOW_DATA_PATTERN = r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}:\d{1,5}:){2}\w+:(ingress|egress):\d{1,4}$'
DEFAULT_FLOW_DATA = '11.11.11.11/32:1001:11.11.11.22/32:80:tcp:ingress:1024'
DEFAULT_APP_HOST = '0.0.0.0'
DEFAULT_APP_PORT = 15000


app = Flask(__name__)
logger = get_logger('pygennf')
threads_dict = collections.OrderedDict()


@app.route('/pygennf/help')
def help():
    return jsonify(
        {'Create sending task': '/pygennf/tasks/create',
         'Check tasks status': '/pygennf/tasks/status',
         'List tasks details': '/pygennf/tasks/detail',
         'Stop the running tasks': '/pygennf/tasks/stop',
         'Clear tasks': '/pygennf/tasks/clear',
         'Print help info': '/pygennf/help'
         })


# Get the status of all threads
@app.route('/pygennf/tasks/status', methods=['GET'])
def status_all():
    status_info_dict = {}
    for k, v in threads_dict.items():
        status_info_dict[k] = {'start_time': v['start_time'], 'end_time': v['end_time'],
                               'task_info': v['thread'].__repr__(),
                               'pkt_sent': v['pkt_sent'],
                               'status': v['status']}
    # status_info = json.dumps(status_info_dict)
    return jsonify(status_info_dict)


# Get the status of specific thread
@app.route('/pygennf/tasks/status/<task_id>', methods=['GET'])
def status_specific(task_id):
    if task_id not in threads_dict:
        return jsonify(
            {'status': 'Error',
             'desc': 'The task_id cannot be found in task list',
             'task_uuid': task_id,
             'task_info': ''
             })
    else:
        status_info_dict = {}
        status_info_dict[task_id] = {'start_time': threads_dict[task_id]['start_time'],
                                     'end_time': threads_dict[task_id]['end_time'],
                                     'task_info': threads_dict[task_id]['thread'].__repr__(),
                                     'pkt_sent': threads_dict[task_id]['pkt_sent'],
                                     'status': threads_dict[task_id]['status']}
        return jsonify(status_info_dict)


# Get the detail of all threads
@app.route('/pygennf/tasks/detail', methods=['GET'])
def detail_all():
    detail_info_dict = {}
    for k, v in threads_dict.items():
        detail_info_dict[k] = {'task_detail': v['task_detail']}

    return jsonify(detail_info_dict)


# Get the detail of specific thread
@app.route('/pygennf/tasks/detail/<task_id>', methods=['GET'])
def detail_specific(task_id):
    if task_id not in threads_dict:
        return jsonify(
            {'status': 'Error',
             'desc': 'The task_id cannot be found in task list',
             'task_uuid': task_id,
             'task_info': ''
             })
    else:
        detail_info_dict = {}
        detail_info_dict[task_id] = {'task_detail': threads_dict[task_id]['task_detail']}
        return jsonify(detail_info_dict)


# Stop the specific thread
@app.route('/pygennf/tasks/stop/<task_id>', methods=['GET'])
def stop_specific(task_id):
    if task_id not in threads_dict:
        return jsonify(
            {'status': 'Error',
             'desc': 'The task_id cannot be found in task list',
             'task_uuid': task_id,
             'task_info': ''
             })
    else:
        if threads_dict[task_id]['status'] in ('completed', 'user stopped'):
            return jsonify(
                {'status': 'Success',
                 'desc': 'The task with this task_id is already completed, no need to be stopped',
                 'task_uuid': task_id,
                 'task_info': ''
                 })
        else:
            logger.debug("Task with task_id '%s' will be stopped now" % task_id)
            task_thread = threads_dict[task_id]['thread']
            if task_thread.isAlive():
                threads_dict[task_id]['stop_flag'] = 'true'
                return jsonify(
                    {'status': 'Success',
                     'desc': 'The stop_flag for this task_id is set, it will be completed soon',
                     'task_uuid': task_id,
                     'task_info': ''
                     })
            else:
                return jsonify(
                    {'status': 'Success',
                     'desc': 'The task with this task_id is already completed, no need to be stopped',
                     'task_uuid': task_id,
                     'task_info': ''
                     })


# Stop all the running threads
@app.route('/pygennf/tasks/stop', methods=['GET'])
def stop_all():
    thread_name_list = []
    for task_id in threads_dict.keys():
        threads_dict[task_id]['stop_flag'] = 'true'
        thread_name_list.append(task_id)

    return jsonify(
        {'status': 'Success',
         'desc': 'The stop_flag for all the tasks have been set, those tasks will be completed soon',
         'task_uuid': thread_name_list,
         'task_info': ''
         })


# Clear specific task
@app.route('/pygennf/tasks/clear/<task_id>', methods=['GET'])
def clear(task_id):
    if task_id not in threads_dict:
        return jsonify(
            {'status': 'Error',
             'desc': 'The task_id cannot be found in task list',
             'task_uuid': task_id,
             'task_info': ''
             })
    else:
        if threads_dict[task_id]['status'] not in ('completed', 'user stopped'):
            return jsonify(
                {'status': 'Error',
                 'desc': 'The task with this task_id is still running, it should be completed or stopped first',
                 'task_uuid': task_id,
                 'task_info': ''
                 })
        else:
            logger.debug("Task with task_id '%s' will be cleared from threads_dict now" % task_id)
            del threads_dict[task_id]
            return jsonify(
                {'status': 'Success',
                 'desc': 'Task has been cleared',
                 'task_uuid': task_id,
                 'task_info': ''
                 })


# Create the thread to send packets
@app.route('/pygennf/tasks/create', methods=['POST'])
def create():
    prefix_logger = '[Method][create]'
    # print "create() invoked..."
    if not request.json:
        logger.debug(prefix_logger + "Json body is expected in POST message!!")
        abort(404)
    # print request.json
    ip_src = request.json['ip_src'].encode("ascii")
    # print 'ip_src: %s' % ip_src
    logger.debug(prefix_logger + 'ip_src: %s' % ip_src)
    ip_dst = request.json['ip_dst'].encode("ascii")
    # print 'ip_dst: %s' % ip_dst
    logger.debug(prefix_logger + 'ip_dst: %s' % ip_dst)
    port_src = int(request.json['port_src'])
    # print 'port_src:', port_src
    logger.debug(prefix_logger + 'port_src: %s' % port_src)
    port_dst = int(request.json['port_dst'])
    # print 'port_dst:', port_dst
    logger.debug(prefix_logger + 'port_dst: %s' % port_dst)
    flow_data_list = get_flow_data_list(request.json['flows-data'].encode("ascii"), DEFAULT_FLOW_DATA)
    # print 'flow_data_list: %s' % flow_data_list
    logger.debug(prefix_logger + 'flow_data_list: %s' % flow_data_list)
    pkt_count = int(request.json['pkt_count'])
    # print 'pkt_count:', pkt_count
    logger.debug(prefix_logger + 'pkt_count: %s' % pkt_count)
    time_interval = request.json['time_interval'].encode("ascii")
    # print 'time_interval: %s' % time_interval
    logger.debug(prefix_logger + 'time_interval: %s' % time_interval)
    # print 'Thread %s is running...' % threading.current_thread().name
    logger.info(prefix_logger + 'Thread %s is running...' % threading.current_thread().name)

    task_uuid = get_uuid()
    t = threading.Thread(target=start_send, name=task_uuid, args=(ip_src, ip_dst, port_src, port_dst,
                                                                  flow_data_list, pkt_count, time_interval, True))
    # t.do_run = True
    # t.setDaemon(True)

    threads_dict[task_uuid] = {"start_time": "", "end_time": "", "thread": t, "pkt_sent": 0, "status": "not started",
                               "task_detail": {"ip_src": ip_src, "ip_dst": ip_dst, "port_src": port_src,
                                               "port_dst": port_dst, "flow_data_list": flow_data_list,
                                               "pkt_count": pkt_count, "time_interval": time_interval}
                               }
    logger.debug(prefix_logger + 'threads_dict: %s' % threads_dict)
    t.start()
    threads_dict[task_uuid]['start_time'] = datetime.now().isoformat()
    threads_dict[task_uuid]['status'] = 'started'

    return jsonify(
        {'status': 'Success',
         'desc': 'Packets sending task created and started successfully',
         'task_uuid': task_uuid,
         'task_info': t.__repr__()
         })


def signal_handler(signal, frame):
    global SIGNAL_RECEIVED
    SIGNAL_RECEIVED = 1
    print 'signal_handler invoked...'


def valid_flow_data(flow_data_str=''):
    global FLOW_DATA_PATTERN
    m = re.match(FLOW_DATA_PATTERN, flow_data_str)
    return True if m is not None else False


def get_parser():
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
    parser.add_argument('-fd', '--flows-data', dest='flows_data',
                        help='Contents in flows data, e.g. ip1/mask:port1:ip2/mask:port2:protocol:direction:bytes.')
    parser.add_argument('-r', '--remote', dest='remote', action="store_true",
                        help='Listen on TCP port 15000 as API server. All other parameters will be ignored.')
    parser.add_argument('-ll', '--log-level', dest='log_level', type=str, choices=['info', 'debug'],
                        help='Log level, default log level is info')
    return parser.parse_args()


# Netflow9
def main():
    print "\n***************************************************************************"
    print "* ______ _                 _____                           _              *"
    print "* |  ___| |               |  __ \                         | |             *"
    print "* | |_  | | _____      __ | |  \/ ___ _ __   ___ _ __ __ _| |_ ___  _ __  *"
    print "* |  _| | |/ _ \ \ /\ / / | | __ / _ \ '_ \ / _ \ '__/ _` | __/ _ \| '__| *"
    print "* | |   | | (_) \ V  V /  | |_\ \  __/ | | |  __/ | | (_| | || (_) | |    *"
    print "* \_|   |_|\___/ \_/\_/    \____/\___|_| |_|\___|_|  \__,_|\__\___/|_|    *"
    print "*                                                                         *"
    print "* Flow Generator Ver. 0.11                                                *"
    print "* Modified by Sheng Zhao                                                  *"
    print "* Calix Cloud SIT                                                         *"
    print "* sheng.zhao@calix.com                                                    *"
    print "***************************************************************************\n\n"

    if os.getuid() != 0:
        print "You need to be root to run this, sorry."
        return

    args = get_parser()

    if args.log_level:
        set_logger_level(logger, args.log_level)

    if args.remote:
        logger.info("Flow Generator starting to listen on '%s':'%s'" % (DEFAULT_APP_HOST, str(DEFAULT_APP_PORT)))
        app.run(host=DEFAULT_APP_HOST, port=DEFAULT_APP_PORT)
        sys.exit(0)

    if args.src_ip:
        ip_src = args.src_ip
    else:
        ip_src = "10.0.203.2"

    if args.dst_ip:
        ip_dst = args.dst_ip
    else:
        ip_dst = "10.0.30.89"

    if ip_dst == "127.0.0.1":
        conf.L3socket=L3RawSocket

    if args.src_port:
        port_src = int(args.src_port)
    else:
        port_src = int(2056)

    if args.dst_port:
        port_dst = int(args.dst_port)
    else:
        port_dst = int(2055)

    if args.time_interval:
        time_interval = args.time_interval
    else:
        time_interval = 1

    if args.pkt_count:
        pkt_count = int(args.pkt_count)
    else:
        # 0xFFFFFFFF - 1
        pkt_count = 4294967294

    if args.flows_data:
        flow_data_list = get_flow_data_list(args.flows_data, DEFAULT_FLOW_DATA)
    else:
        print "'args.flows_data' is empty, default flow data list will be used..."
        print "Default flow data: %s" % (DEFAULT_FLOW_DATA)
        flow_data_list = []
        flow_data_list.append(DEFAULT_FLOW_DATA)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print 'Thread %s is running...' % threading.current_thread().name
    t = threading.Thread(target=start_send, name='SendingThread', args=(ip_src, ip_dst, port_src, port_dst,
                                                                        flow_data_list, pkt_count, time_interval))
    #t.do_run = True
    #t.setDaemon(True)
    t.start()
    while True:
        t.join(5)
        if not t.isAlive():
            break

    print 'Thread %s ended.' % threading.current_thread().name


def get_flow_data_list(args_flows_data, default_flow_data):
    prefix_logger = '[Method][get_flow_data_list]'
    logger.debug(prefix_logger + 'Entering...')

    flow_data_list = args_flows_data.split(',')
    flow_data_list = map(str.strip, flow_data_list)
    flow_data_list = filter(valid_flow_data, flow_data_list)
    if len(flow_data_list) == 0:
        # print 'No valid flow data list, default flow data list will be used...'
        logger.info(prefix_logger + 'No valid flow data list, default flow data list will be used...')
        # print "Default flow data: %s" % (default_flow_data)
        logger.info(prefix_logger + 'Default flow data: %s' % (default_flow_data))
        flow_data_list.append(default_flow_data)
    # print 'flow_data_list before return:', flow_data_list
    logger.debug(prefix_logger + 'flow_data_list before return: %s' % flow_data_list)
    logger.debug(prefix_logger + 'Leaving...')
    return flow_data_list


def start_send(ip_src, ip_dst, port_src, port_dst, flow_data_list, pkt_count, time_interval, is_remote=False):
    current_thread_name = threading.current_thread().name
    print 'Thread %s is running...' % current_thread_name
    flow_sequence = 1
    gen_send_pkt('tmpl', flow_sequence=flow_sequence, src_ip=ip_src, dst_ip=ip_dst, sport=port_src, dport=port_dst,
                 is_remote=is_remote)
    print 'Flows to be sent: '
    print flow_data_list
    while time_interval is not 0:
        if SIGNAL_RECEIVED == 1:
            print "\nSignal received. %s packets have been sent. Stopping and Exiting..." % flow_sequence
            #sys.exit(0)
            break
        time.sleep(float(time_interval))

        if is_remote:
            try:
                if 'true' == threads_dict[current_thread_name]['stop_flag']:
                    logger.info("Detected stop_flag for task '%s', task will be completed" % current_thread_name)
                    break
            except KeyError:
                pass

        flow_sequence = flow_sequence + 1
        if flow_sequence > pkt_count:
            print "\nPackets count[%s] reached. Stopping and Exiting..." % pkt_count
            #sys.exit(0)
            break
        if flow_sequence % 100 == 0:
            gen_send_pkt('tmpl', flow_sequence=flow_sequence, src_ip=ip_src, dst_ip=ip_dst, sport=port_src,
                         dport=port_dst, is_remote=is_remote)
            continue
        gen_send_pkt('data', flow_sequence, src_ip=ip_src, dst_ip=ip_dst, sport=port_src, dport=port_dst,
                     flow_data_list=flow_data_list, is_remote=is_remote)

    print 'Thread %s ended.' % threading.current_thread().name
    if is_remote:
        current_time = datetime.now().isoformat()
        threads_dict[current_thread_name]['end_time'] = current_time
        logger.debug(
            "end_time '%s' has been set to threads_dict for thread '%s'" % (current_time, current_thread_name))

        try:
            if 'true' == threads_dict[current_thread_name]['stop_flag']:
                threads_dict[current_thread_name]['status'] = "user stopped"
            else:
                threads_dict[current_thread_name]['status'] = "completed"
        except KeyError:
            threads_dict[current_thread_name]['status'] = "completed"


def gen_send_pkt(pkt_type='data', flow_sequence=1, src_ip='1.1.1.1', dst_ip='2.2.2.2', sport=2056, dport=2055,
                 flow_data_list=[], is_remote=False):
    current_thread_name = threading.current_thread().name
    timestamp = int(time.time())
    if pkt_type == 'tmpl':
        pkt_netflow_tmpl = gen_pkt_netflow_tmpl(timestamp=timestamp, flow_sequence=flow_sequence,
                                                src_ip=src_ip, dst_ip =dst_ip, sport=sport, dport=dport)
        #wrpcap('v9_test_tmpl.pcap', pkt_netflow_tmpl)
        sys.stdout.write("Sending packets: %d \r" % flow_sequence)
        send(pkt_netflow_tmpl, verbose=0)
        sys.stdout.flush()
    elif pkt_type == 'data':
        sys_uptime = 3600 * 1000
        pkt_netflow_data = gen_pkt_netflow_data(timestamp=timestamp, sys_uptime=sys_uptime, flow_sequence=flow_sequence,
                                                src_ip=src_ip, dst_ip=dst_ip, sport=sport, dport=dport,
                                                flow_data_list=flow_data_list)
        #wrpcap('v9_test_data.pcap', pkt_netflow_data)
        sys.stdout.write("Sending packets: %d \r" % flow_sequence)
        send(pkt_netflow_data, verbose=0)
        sys.stdout.flush()

    if is_remote:
        try:
            threads_dict[current_thread_name]['pkt_sent'] = flow_sequence
        except KeyError:
            logger.info("pkt_sent cannot be assigned to thread '%s' in thread_dict" % current_thread_name)


def gen_pkt_netflow_data(timestamp=1503652676, flow_sequence=1, sys_uptime=3600000, src_ip='121.41.5.67',
                         dst_ip='121.41.5.68', sport=2056, dport=2055, flow_data_list=[]):
    header_v9 = rbnf.Netflow_Headerv9(version=9, count=1, SysUptime=0x000069d7, Timestamp=timestamp,
                                      FlowSequence=flow_sequence, SourceId=2177)
    flowset_flow_header_v9 = rbnf.FlowSet_Header_v9(FlowSet_id=260, FlowSet_length=72)

    # List for flows in one packet
    flows = []

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