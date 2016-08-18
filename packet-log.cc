#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <ctype.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <cinttypes>
#include <map>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sysexits.h>
#include <time.h>
#include <unistd.h>
using namespace std;

// snapshot length == 65536
// link-layer header type == 1 (Ethernet)
const char PCAP_HEADER[] = "\xd4\xc3\xb2\xa1\x02\x00\x04\00\0\0\0\0\0\0\0\0\0\0\1\0\1\0\0\0";
// ethertype == 0xffff (unused)
const char ETHERNET_HEADER[] = "\0\0\0\0\0\0\0\0\0\0\0\0\x08\x00";
uint16_t udp_port = 1999;
const int HEADER_LEN = 15;

void print_help(FILE *fh)
{
  fprintf(fh, "Usage: %s [OPTIONS] root\n", program_invocation_short_name);
  fputs(
        "\n"
        "Options:\n"
        "  -B %ld                    capture buffer size in MiB (default: 2), switch to the next PCAP after it reaches a size of %ld MiB\n"
        "  -d, --duration %ld        round duration in seconds (default: 300), switch to the next PCAP after %ld seconds have elapsed\n"
        "  -l, --listen %s           UDP listen address\n"
        "  -p, --port %s             UDP listen port\n"
        "  -s, --src %s              trusted source IP, packets from others will be dropped\n"
        "  -v, --verbose             verbose\n"
        "  -h, --help                display this help and exit\n"
        "\n"
        "Examples:\n"
        "./packet-log -s 10.5.0.1 pcap # packets will be saved to pcap/$csid/%Y%m%d-%H%M%S.cap\n"
        "\n"
        , fh);
  exit(fh == stdout ? 0 : EX_USAGE);
}

in_addr_t resolve_ip(const char *s)
{
  in_addr_t r = 0;
  addrinfo hint = {}, *res;
  hint.ai_family = AF_INET;
  hint.ai_socktype = SOCK_DGRAM;
  if (getaddrinfo(optarg, NULL, &hint, &res))
    err(EX_OSERR, "getaddrinfo");
  for (addrinfo* rp = res; rp; rp = rp->ai_next)
    r = ntohl(((struct sockaddr_in*)rp->ai_addr)->sin_addr.s_addr);
  freeaddrinfo(res);
  return r;
}

void create_pcap(map<int32_t, pair<int, FILE*>>& csid2fd, int csid, timeval ts)
{
  char tmp[99];
  time_t t = ts.tv_sec;
  strftime(tmp, sizeof tmp, "%Y%m%d-%H%M%S.cap", localtime(&t));
  int file = openat(csid2fd[csid].first, tmp, O_WRONLY | O_CREAT | O_TRUNC, 0666);
  if (file < 0) err(EX_IOERR, "openat");
  FILE* fh = fdopen(file, "wb");
  if (! fh) err(EX_IOERR, "fdopen");
  csid2fd[csid].second = fh;
  if (fwrite(PCAP_HEADER, sizeof PCAP_HEADER-1, 1, fh) != 1)
    err(EX_IOERR, "fwrite");
}

int main(int argc, char* argv[])
{
  int opt;
  bool opt_verbose = false;
  long capture_buffer_size = 20*1024*1024,
       duration = 5*60;
  in_addr_t src_ip = ntohl(INADDR_ANY), listen_ip = ntohl(INADDR_ANY);
  static struct option long_options[] = {
    {"duration",  required_argument, 0,   'd'},
    {"port",      required_argument, 0,   'p'},
    {"src",       required_argument, 0,   's'},
    {"listen",    required_argument, 0,   'l'},
    {"verbose",   required_argument, 0,   'v'},
    {"help",      required_argument, 0,   'h'},
    {0,           0,                 0,   0},
  };

  while ((opt = getopt_long(argc, argv, "B:d:hl:p:s:v", long_options, NULL)) != -1) {
    switch (opt) {
    case 'B':
      capture_buffer_size = atol(optarg)*1024*1024;
      break;
    case 'd':
      duration = atol(optarg);
      break;
    case 'h':
      print_help(stdout);
      break;
    case 'l':
      listen_ip = resolve_ip(optarg);
      break;
    case 'p':
      udp_port = atoi(optarg);
      break;
    case 's':
      src_ip = resolve_ip(optarg);
      break;
    case 'v':
      opt_verbose = true;
      break;
    case '?':
      print_help(stderr);
      break;
    }
  }
  argc -= optind;
  argv += optind;
  if (argc != 1)
    print_help(stderr);

  // root directory
  int root_dir = open(argv[0], O_RDONLY | O_DIRECTORY, 0777);
  if (root_dir < 0)
    err(EX_OSERR, "open");

  map<int32_t, pair<int, FILE*>> csid2fd;

  // bind
  char buf[65535-20-8];
  int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP), one = 1;
  if (fd < 0) err(EX_OSERR, "socket");
  if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMP, &one, sizeof one) < 0)
    err(EX_OSERR, "setsockopt");
  sockaddr_in sa = {}, src_sa;
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(listen_ip);
  sa.sin_port = htons(udp_port);
  if (bind(fd, (sockaddr*)&sa, sizeof sa) < 0)
    err(EX_OSERR, "bind");

  // default values for IP & UDP headers
  uint16_t ip_id = 0;
  iphdr ip = {};
  ip.ihl = 5;
  ip.version = 4;
  //ip.tot_len;
  //ip.id;
  ip.frag_off = 0;
  ip.ttl = 64;
  ip.protocol = IPPROTO_UDP;
  ip.frag_off = htons(IP_DF);
  //ip.check
  //ip.saddr
  //ip.daddr

  udphdr udp = {};

  // timer
  itimerspec itimer = {};
  itimer.it_value.tv_sec = itimer.it_interval.tv_sec = duration;
  int timer = timerfd_create(CLOCK_REALTIME, 0);
  if (timer < 0)
    err(EX_OSERR, "timerfd_create");
  if (timerfd_settime(timer, 0, &itimer, NULL) == -1)
    err(EX_OSERR, "timerfd_settime");

  pollfd fds[2];
  fds[0].fd = fd;
  fds[0].events = POLLIN;
  fds[1].fd = timer;
  fds[1].events = POLLIN;
  for(;;) {
    int ready = poll(fds, 2, -1);
    if (ready < 0) {
      if (errno == EINTR) continue;
      err(EX_OSERR, "poll");
    }
    timeval ts;

    if (fds[1].revents & POLLIN) {
      int64_t elapsed;
      if (read(timer, &elapsed, sizeof(int64_t)) < 0)
        err(EX_OSERR, "read");
      for (auto& it: csid2fd) {
        if (it.second.second) {
          if (fclose(it.second.second) < 0) err(EX_IOERR, "fclose");
          gettimeofday(&ts, NULL);
          create_pcap(csid2fd, it.first, ts);
        }
      }
    }

    if (fds[0].revents & POLLIN) {
      ssize_t len;
      msghdr msg;
      char tmp[512];
      iovec iov = {};
      iov.iov_base = buf;
      iov.iov_len = sizeof buf;
      msg.msg_name = &src_sa;
      msg.msg_namelen = sizeof src_sa;
      msg.msg_iov = &iov;
      msg.msg_iovlen = 1;
      msg.msg_control = tmp;
      msg.msg_controllen = sizeof tmp;
      if ((len = recvmsg(fd, &msg, 0)) < 0)
        err(EX_OSERR, "recvmsg");
      if (src_ip != ntohl(INADDR_ANY) && src_ip != ntohl(src_sa.sin_addr.s_addr)) {
        if (opt_verbose) {
          if (! inet_ntop(AF_INET, &src_sa.sin_addr, tmp, sizeof tmp))
            err(EX_OSERR, "inet_ntop");
          fprintf(stderr, "dropped packet from %s\n", tmp);
        }
        continue;
      }
      // read timestamp
      for (cmsghdr* i = CMSG_FIRSTHDR(&msg); i; i = CMSG_NXTHDR(&msg, i))
        if (i->cmsg_level == SOL_SOCKET && i->cmsg_type == SO_TIMESTAMP)
          ts = *(timeval*)CMSG_DATA(i);
      if (len < HEADER_LEN) {
        if (opt_verbose)
          fprintf(stderr, "invalid message length: %ld\n", len);
        continue;
      }

      uint32_t csid = *(uint32_t*)buf;
      uint32_t connection_id = *(uint32_t*)(buf+4);
      uint32_t msg_id = *(uint32_t*)(buf+8);
      uint16_t msg_len = *(uint16_t*)(buf+12);
      char side = *(char*)(buf+14);
      if (msg_len != len-HEADER_LEN) {
        if (opt_verbose)
          fprintf(stderr, "invalid message, actual: %ld, expected: %" PRIu16 "\n", len-HEADER_LEN, msg_len);
        continue;
      }

      // ensure sub directory
      if (! csid2fd.count(csid)) {
        sprintf(tmp, "%" PRIu32, csid);
        errno = 0;
        if (mkdirat(root_dir, tmp, 0777) < 0 && errno != EEXIST)
          err(EX_OSERR, "mkdirat");
        int dir = openat(root_dir, tmp, O_RDONLY | O_DIRECTORY);
        if (dir < 0)
          err(EX_OSERR, "openat");
        csid2fd[csid] = {dir, NULL};
      }

      // ensure PCAP file in sub directory
      if (! csid2fd[csid].second)
        create_pcap(csid2fd, csid, ts);

      FILE* fh = csid2fd[csid].second;
      // pcap-savefile timestamp
      if (fwrite(&ts.tv_sec, 4, 1, fh) != 1) err(EX_IOERR, "fwrite");
      if (fwrite(&ts.tv_usec, 4, 1, fh) != 1) err(EX_IOERR, "fwrite");

      // pcap-savefile length
      uint32_t tot_len = sizeof(ETHERNET_HEADER)-1 + sizeof(iphdr) + sizeof(udphdr) + len-HEADER_LEN;
      if (fwrite(&tot_len, 4, 1, fh) != 1) err(EX_IOERR, "fwrite"); // length of captured packet data
      if (fwrite(&tot_len, 4, 1, fh) != 1) err(EX_IOERR, "fwrite"); // un-truncated length of captured packet data

      // Ethernet header
      if (fwrite(ETHERNET_HEADER, sizeof ETHERNET_HEADER-1, 1, fh) != 1) err(EX_IOERR, "fwrite");

      // IP header denoting 'side'
      ip.id = htons(ip_id++);
      ip.tot_len = htons(tot_len - (sizeof(ETHERNET_HEADER)-1));
      if (side) {
        ip.saddr = 0xffffffff;
        ip.daddr = 0x00000000;
      } else {
        ip.saddr = 0x00000000;
        ip.daddr = 0xffffffff;
      }
      //ip.check = in_cksum((unsigned short*)&ip, sizeof ip);
      if (fwrite(&ip, sizeof ip, 1, fh) != 1) err(EX_IOERR, "fwrite");

      // UDP header denoting 'connection_id'
      udp.source = htons((connection_id / 65535 % 65535 + 1));
      udp.dest = htons(connection_id % 65535 + 1);
      if (side)
        swap(udp.source, udp.dest);

      udp.len = htons(ntohs(ip.tot_len) - sizeof ip);
      if (fwrite(&udp, sizeof udp, 1, fh) != 1) err(EX_IOERR, "fwrite");

      if (fwrite(buf+HEADER_LEN, len-HEADER_LEN, 1, fh) != 1) err(EX_IOERR, "fwrite");
      if (ftello(fh) > capture_buffer_size) {
        if (fclose(fh) < 0) err(EX_IOERR, "fclose");
        csid2fd[csid].second = NULL;
      } else {
        if (fflush(fh) < 0) err(EX_IOERR, "fflush");
      }
    }
  }
}
