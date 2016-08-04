#!/usr/bin/env python2
from itertools import izip
from lxml import etree
import argparse, dpkt, multiprocessing, os, re, struct, subprocess

DEVNULL = open(os.devnull, 'r+b')
TCP_IGNORE = '!tcp.analysis.ack_lost_segment and !tcp.analysis.duplicate_ack and !tcp.analysis.retransmission'
delay_threshold = 0.1
opt_force = False
opt_service = 'service'

tasks = []


def split_sessions(pcap_path):
    # Ref: https://www.wireshark.org/docs/dfref/t/tcp.html
    tshark_output = subprocess.check_output(['tshark', '-r', pcap_path, '-2R', TCP_IGNORE, '-T', 'fields', '-e', 'tcp.stream'], stderr=DEVNULL)
    session = {}
    with open(pcap_path) as f:
        for (ts, pkt), stream_id in izip(dpkt.pcap.Reader(f).readpkts(), tshark_output.splitlines()):
            if len(stream_id) == 0: continue
            stream_id = int(stream_id)
            ether = dpkt.ethernet.Ethernet(pkt)
            if ether.type != 2048: continue # not IP
            ip = ether.data
            if not hasattr(ip, 'tcp'): continue # not TCP
            tcp = ip.tcp
            client_ip = struct.unpack('>I', ip.src)[0]
            server_ip = struct.unpack('>I', ip.dst)[0]
            if stream_id not in session:
                session[stream_id] = {'client_ip': client_ip,
                                      'server_ip': server_ip,
                                      'client_port': tcp.sport,
                                      'server_port': tcp.dport,
                                      'packets': [(ts, ip)]}
            else:
                session[stream_id]['packets'].append((ts, ip))

    # Ref: https://github.com/CyberGrandChallenge/cgc-release-documentation/blob/master/pov-markup-spec.txt
    root = etree.Element('cfepov')
    cbid = etree.Element('cbid')
    cbid.text = opt_service
    root.append(cbid)
    replay = etree.Element('replay')
    replay.append(etree.fromstring('<negotiate><type2 /></negotiate>'))

    for session in session.itervalues():
        first = True
        last = 0
        for ts, ip in session['packets']:
            tcp = ip.tcp
            if len(tcp.data) > 0:
                if struct.unpack('>I', ip.src)[0] == session['client_ip']:
                    if ts-last > delay_threshold and not first:
                        delay = etree.Element('delay')
                        delay.text = str(int(round((ts-last)*1000)))
                        replay.append(delay)
                    payload = ''
                    node = etree.Element('write')
                    data = etree.Element('data')
                    for i in tcp.data:
                        if 33 <= ord(i) < 127 and i not in '&<>':
                            payload += i
                        else:
                            payload += '\\x%0*x' % (2, ord(i))
                    data.text = payload
                    node.append(data)
                else:
                    node = etree.Element('read')
                    length = etree.Element('length')
                    length.text = str(len(tcp.data))
                    node.append(length)
                replay.append(node)
                first = False
            last = ts

    root.append(replay)
    xml_path = os.path.splitext(pcap_path)[0]+'.xml'
    with open(xml_path, 'w') as f:
        print('Generating {}'.format(xml_path))
        f.write('<?xml version="1.0" standalone="no" ?>\n')
        f.write('<!DOCTYPE cfepov SYSTEM "/usr/share/cgc-docs/cfe-pov.dtd">\n')
        s = etree.tostring(root, pretty_print=True)
        s = re.sub('<(read|write)>\n      ', '<\\1>', s)
        s = re.sub('\n    </(read|write)>', '</\\1>', s)
        f.write(s)
    return xml_path


def main():
    global delay_threshold, opt_force, opt_recursive
    ap = argparse.ArgumentParser(description='pcap2xml')
    ap.add_argument('--delay_threshold', type=float, help='insert a <delay> element if the time interval between two I/O is larger than the specified value')
    ap.add_argument('-f', '--force', action='store_true', help='override existent XML files')
    ap.add_argument('-p', '--parallel', type=int, default=0, help='number of parallel workers (default: 0, the number of cores)')
    ap.add_argument('-r', '--recursive', action='store_true', help='convert PCAP files recursively')
    ap.add_argument('-s', '--service', help='service name')
    ap.add_argument('pcap_paths', nargs='+', help='files or directories to convert')
    args = ap.parse_args()
    delay_threshold = args.delay_threshold
    opt_force = args.force
    opt_recursive = args.recursive
    opt_service = args.service

    tasks = []

    def walk(path, depth):
        if depth > 0 and opt_recursive: return
        if os.path.isdir(path):
            for i in os.listdir(path):
                walk(os.path.join(path, i), depth+1)
        elif re.search(r'\.(cap|pcap)$', path):
            try:
                if opt_force or os.path.getsize(path) == 0:
                    tasks.append(path)
            except FileNotFoundError:
                tasks.append(path)

    for pcap_path in args.pcap_paths:
        walk(pcap_path, 0)

    parallel = args.parallel or multiprocessing.cpu_count()
    for _ in multiprocessing.Pool(parallel).imap_unordered(split_sessions, tasks, 1):
        pass


if __name__ == '__main__':
    main()
    DEVNULL.close()