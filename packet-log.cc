#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <netdb.h>
#include <cctype>
#include <fcntl.h>
#include <cstdint>
#include <cstdio>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <cinttypes>
#include <map>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sysexits.h>
#include <time.h>
#include <unistd.h>
using namespace std;

// snapshot length == 1024
// link-layer header type == 1 (Ethernet)
const char PCAP_HEADER[] = "\xd4\xc3\xb2\xa1\x02\x00\x04\00\0\0\0\0\0\0\0\0\0\4\0\0\1\0\0\0";
// ethertype == 0xffff (unused)
const char ETHERNET_HEADER[] = "\0\0\0\0\0\0\0\0\0\0\0\0\xff\xff";
uint16_t udp_port = 1999;
const int HEADER_LEN = 15;

void print_help(FILE *fh)
{
  fprintf(fh, "Usage: %s [OPTIONS] root\n", program_invocation_short_name);
  fputs(
        "\n"
        "Options:\n"
        "  -B %ld                    capture buffer size in MiB (default: 2), create a new PCAP if it is larger than this size\n"
        "  -p, --port %s             port of listening UDP socket\n"
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

int main(int argc, char* argv[])
{
  int opt;
  bool opt_verbose = false;
  long capture_buffer_size = 2*1024*1024;
  in_addr_t src_ip = ntohl(INADDR_ANY);
  static struct option long_options[] = {
    {"port",      required_argument, 0,   'p'},
    {"src",       required_argument, 0,   's'},
    {"verbose",   required_argument, 0,   'v'},
    {"help",      required_argument, 0,   'h'},
    {0,           0,                 0,   0},
  };

  while ((opt = getopt_long(argc, argv, "B:hp:s:v", long_options, NULL)) != -1) {
    switch (opt) {
    case 'B':
      capture_buffer_size = atol(optarg)*1024*1024;
      break;
    case 'h':
      print_help(stdout);
      break;
    case 'p':
      udp_port = atoi(optarg);
      break;
    case 's': {
      addrinfo hint = {}, *res;
      hint.ai_family = AF_INET;
      hint.ai_socktype = SOCK_DGRAM;
      if (getaddrinfo(optarg, NULL, &hint, &res))
        err(EX_OSERR, "getaddrinfo");
      for (addrinfo* rp = res; rp; rp = rp->ai_next)
        src_ip = ntohl(((struct sockaddr_in*)rp->ai_addr)->sin_addr.s_addr);
      freeaddrinfo(res);
      break;
    }
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
  char buf[65535-20-8];
  int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP), one = 1;
  if (fd < 0) err(EX_OSERR, "socket");
  if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMP, &one, sizeof one) < 0)
    err(EX_OSERR, "setsockopt");
  sockaddr_in sa = {}, src_sa;
  sa.sin_addr.s_addr = htonl(INADDR_ANY);
  sa.sin_port = htons(udp_port);
  if (bind(fd, (sockaddr*)&sa, sizeof sa) < 0)
    err(EX_OSERR, "bind");
  for(;;) {
    ssize_t len;
    msghdr msg;
    char tmp[512];
    timeval ts;
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
      err(EX_OSERR, "rercvmsg");
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
    // uint32_t connection_id = *(uint32_t*)(buf+4);
    // uint32_t msg_id = *(uint32_t*)(buf+8);
    uint16_t msg_len = *(uint16_t*)(buf+12);
    // char side = *(char*)(buf+14);
    if (msg_len != len-HEADER_LEN) {
      if (opt_verbose)
        fprintf(stderr, "invalid message, actual: %ld, expected: %" PRIu16 "\n", len-HEADER_LEN, msg_len);
      continue;
    }
    if (! csid2fd.count(csid)) {
      sprintf(tmp, "%" PRIu32, csid);
      int dir = mkdirat(root_dir, tmp, 0777);
      if (dir < 0 && errno == EEXIST)
        dir = openat(root_dir, tmp, O_RDONLY | O_DIRECTORY);
      if (dir < 0)
        err(EX_OSERR, "mkdirat");
      csid2fd[csid] = {dir, NULL};
    }
    if (! csid2fd[csid].second) {
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
    FILE* fh = csid2fd[csid].second;
    if (fwrite(&ts.tv_sec, 4, 1, fh) != 1) err(EX_IOERR, "fwrite");
    if (fwrite(&ts.tv_usec, 4, 1, fh) != 1) err(EX_IOERR, "fwrite");
    len += sizeof(ETHERNET_HEADER)-1;
    if (fwrite(&len, 4, 1, fh) != 1) err(EX_IOERR, "fwrite"); // length of captured packet data
    if (fwrite(&len, 4, 1, fh) != 1) err(EX_IOERR, "fwrite"); // un-truncated length of captured packet data
    if (fwrite(ETHERNET_HEADER, sizeof ETHERNET_HEADER-1, 1, fh) != 1) err(EX_IOERR, "fwrite");
    len -= sizeof(ETHERNET_HEADER)-1;
    if (fwrite(buf, len, 1, fh) != 1) err(EX_IOERR, "fwrite");
    if (ftello(fh) > capture_buffer_size) {
      if (fclose(fh) < 0) err(EX_IOERR, "fclose");
      csid2fd[csid].second = NULL;
    } else {
      if (fflush(fh) < 0) err(EX_IOERR, "fflush");
    }
  }
}
