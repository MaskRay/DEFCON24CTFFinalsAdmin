#!/usr/bin/env python2
from itertools import izip
import argparse, multiprocessing, os, re, struct, subprocess, sys

try:
    import dpkt
except ImportError:
    print('pip2 install --user dpkt')
    sys.exit(1)
if not any(os.access(os.path.join(path, 'tshark'), os.X_OK) for path in os.environ['PATH'].split(os.pathsep)):
    print('please install tshark')
    sys.exit(1)

DEVNULL = open(os.devnull, 'r+b')
# Ref: https://www.wireshark.org/docs/dfref/t/tcp.html
TCP_IGNORE = '!tcp.analysis.ack_lost_segment and !tcp.analysis.duplicate_ack and !tcp.analysis.retransmission'
delay_threshold = 0.1
opt_force = False
opt_name = ''
opt_cfe_pov = False
opt_protocol = ''
opt_reverse = False
opt_recursive = False
opt_substitute = []
opt_reverse = False

tasks = []

def to_write_path(pcap_path, i):
    base = os.path.splitext(pcap_path)[0]
    if len(opt_substitute):
        base = re.sub(opt_substitute[1], opt_substitute[2], base)
    try:
        os.makedirs(base)
    except OSError:
        pass
    return '{}/{}.write'.format(base, i)


def to_read_path(pcap_path, i):
    base = os.path.splitext(pcap_path)[0]
    if len(opt_substitute):
        base = re.sub(opt_substitute[1], opt_substitute[2], base)
    try:
        os.makedirs(base)
    except OSError:
        pass
    return '{}/{}.read'.format(base, i)


def split_sessions(pcap_path):
    sessions = {}
    with open(pcap_path) as f:
        try:
            frames = dpkt.pcap.Reader(f).readpkts()
        except dpkt.dpkt.NeedData:
            return
        # custom ethertype, key is 'stream_id'
        if opt_protocol == 'cgc':
            for ts, pkt in frames:
                ether = dpkt.ethernet.Ethernet(pkt)
                if ether.type != 0xffff: continue
                csid, connection_id, msg_id, msg_len, side = struct.unpack('IIIHB', ether.data[:15])
                if connection_id not in sessions:
                    sessions[connection_id] = {'client_ip': 0,
                                               'server_ip': 1,
                                               'packets': [(ts, ether.data)]}
                else:
                    sessions[connection_id]['packets'].append((ts, ether.data))
        # IP, key is 'tcp.stream' printed by tshark
        elif opt_protocol == 'tcp':
            tshark_output = subprocess.check_output(['tshark', '-r', pcap_path, '-2R', TCP_IGNORE, '-T', 'fields', '-e', 'tcp.stream'], stderr=DEVNULL)
            for (ts, pkt), stream_id in izip(frames, tshark_output.splitlines()):
                if len(stream_id) == 0: continue
                stream_id = int(stream_id)
                ether = dpkt.ethernet.Ethernet(pkt)
                if ether.type != 2048: continue # not IP
                ip = ether.data
                if not hasattr(ip, 'tcp'): continue
                tcp = ip.tcp
                client_ip = struct.unpack('>I', ip.src)[0]
                server_ip = struct.unpack('>I', ip.dst)[0]
                if stream_id not in sessions:
                    sessions[stream_id] = {'client_ip': client_ip,
                                           'server_ip': server_ip,
                                           'packets': [(ts, ip)]}
                else:
                    sessions[stream_id]['packets'].append((ts, ip))
                if tcp.flags & dpkt.tcp.TH_SYN and not (tcp.flags & dpkt.tcp.TH_ACK):
                    sessions[stream_id]['has_begin'] = True
                if tcp.flags & dpkt.tcp.TH_FIN or tcp.flags & dpkt.tcp.TH_RST:
                    sessions[stream_id]['has_end'] = True
        else:
            tshark_output = subprocess.check_output(['tshark', '-r', pcap_path, '-T', 'fields', '-e', 'udp.stream'], stderr=DEVNULL)
            for (ts, pkt), stream_id in izip(frames, tshark_output.splitlines()):
                if len(stream_id) == 0: continue
                stream_id = int(stream_id)
                ether = dpkt.ethernet.Ethernet(pkt)
                if ether.type != 2048: continue # not IP
                ip = ether.data
                if not hasattr(ip, 'udp'): continue
                udp = ip.udp
                client_ip = struct.unpack('>I', ip.src)[0]
                server_ip = struct.unpack('>I', ip.dst)[0]
                if stream_id not in sessions:
                    sessions[stream_id] = {'client_ip': client_ip,
                                           'server_ip': server_ip,
                                           'packets': [(ts, ip)]}
                else:
                    sessions[stream_id]['packets'].append((ts, ip))

    i = 0
    for session in sessions.itervalues():
        if opt_protocol == 'tcp' and not ('has_begin' in session and 'has_end' in session):
            continue

        # I/O
        payload = ''
        payload2 = ''
        t = session['client_ip']
        for ts, pkt in session['packets']:
            if opt_protocol == 'cgc':
                src_ip = struct.unpack('B', pkt[14])[0] # side, 0: from client
                data = pkt[15:]
            elif opt_protocol == 'tcp':
                src_ip = struct.unpack('>I', ip.src)[0]
                ip = pkt
                data = ip.tcp.data
            else:
                src_ip = struct.unpack('>I', ip.src)[0]
                ip = pkt
                data = ip.udp.data
            if len(data) > 0:
                if (src_ip == t) == opt_reverse:
                    payload += data
                else:
                    payload2 += data

        # Write
        write_path = to_write_path(pcap_path, i)
        i += 1
        with open(write_path, 'wb') as f:
            f.write(payload)
        read_path = to_read_path(pcap_path, i)
        i += 1
        with open(read_path, 'wb') as f:
            f.write(payload2)

    print('Found {} session(s){}'.format(i, ', generated {}'.format(to_write_path(pcap_path, '*')) if i > 0 else ''))


def main():
    global delay_threshold, opt_cfe_pov, opt_force, opt_name, opt_protocol, opt_recursive, opt_substitute,opt_reverse
    ap = argparse.ArgumentParser(description='pcap2write',
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog='''
Ethernet-IP-TCP packets (captured by tcpdump, dumpcap...) and ethertype 0xffff packets (by cb-packet-log) are both supported.

Examples:
./pcap2write.py /tmp/a.pcap /tmp/b.cap # /tmp/a.pcap -> /tmp/a.write ; /tmp/b.cap -> /tmp/b.write
./pcap2write.py /tmp/dir/ # /tmp/dir/*.(cap|pcap) -> /tmp/dir/*.$session_id.write
./pcap2write.py -c /tmp/dir/ # <!DOCTYPE cfe-pov SYSTEM "/usr/share/cgc-docs/cfe-pov.dtd">
./pcap2write.py -d 0.1 /tmp/dir/ # time intervals between two I/O operations greater than 0.1s are treated as <delay> elements
./pcap2write.py -n name /tmp/dir # <cbid>$name</cbid>
./pcap2write.py -p 4 /tmp/dir # 4 parallel workers
./pcap2write.py -r /tmp/dir/ # /tmp/dir/**/*.(cap|pcap) -> /tmp/dir/**/*.$session_id.write
./pcap2write.py -s /root/roots /tmp/root # /tmp/root/*.(cap|pcap) -> /tmp/roots/*.$session_id.write
''')
    ap.add_argument('-c', '--cfe-pov', action='store_true', help='generate XML files of type cfe-pov.dtd (<cfepov>)')
    ap.add_argument('-d', '--delay-threshold', type=float, help='insert a <delay> element if the time interval between two I/O is larger than the specified value')
    ap.add_argument('-f', '--force', action='store_true', help='override existent XML files')
    ap.add_argument('-P', '--protocol', default='udp', help='cgc/udp/tcp (default: udp)')
    ap.add_argument('-p', '--parallel', type=int, default=0, help='number of parallel workers (default: 0, the number of cores)')
    ap.add_argument('-r', '--recursive', action='store_true', help='convert PCAP files recursively')
    ap.add_argument('-n', '--name', default='name', help='service name')
    ap.add_argument('-s', '--substitute', help='/pattern/replacement')
    ap.add_argument('-R', '--reverse', action='store_true', help='reverse')
    ap.add_argument('pcap_paths', nargs='+', help='files or directories to convert')
    args = ap.parse_args()
    delay_threshold = args.delay_threshold
    opt_force = args.force
    opt_recursive = args.recursive
    opt_cfe_pov = args.cfe_pov
    opt_name = args.name
    opt_protocol = args.protocol
    if opt_protocol not in ['cgc', 'tcp', 'udp']:
        ap.print_help()
    if args.substitute:
        opt_substitute = args.substitute.split('/')
        if len(opt_substitute) < 3:
            ap.print_help()

    tasks = []

    def walk(path, depth):
        if os.path.isdir(path):
            if depth == 0 or opt_recursive:
                for i in os.listdir(path):
                    walk(os.path.join(path, i), depth+1)
        elif re.search(r'\.(cap|pcap)$', path):
            try:
                if opt_force or os.path.getsize(to_write_path(path, 0)) == 0:
                    tasks.append(path)
            except OSError:
                tasks.append(path)

    for pcap_path in args.pcap_paths:
        walk(pcap_path, 0)

    if len(tasks):
        parallel = args.parallel or multiprocessing.cpu_count()
        for _ in multiprocessing.Pool(parallel).imap_unordered(split_sessions, tasks, 1):
            pass


if __name__ == '__main__':
    main()
    DEVNULL.close()
