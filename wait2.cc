#include <assert.h>
#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <set>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sysexits.h>
#include <unistd.h>
using namespace std;

typedef uint8_t u8;
typedef uint32_t u32;

const u32 MAGIC_PAGE = 0x4347c000;
//const u32 MAGIC_PAGE = 0x08048000;
bool opt_all_matches = false;

void print_help(FILE *fh)
{
  fprintf(fh, "Usage: %s [OPTIONS] root\n", program_invocation_short_name);
  fputs(
        "\n"
        "  -a, --all            all matches for 8 general registers\n"
        "  -i, --input          used as stdin of the program\n"
        "  -t, --timeout        in seconds, return 9(SIGALRM) if timeouts\n"
        "  --type2              return 127 if longest-common-substring(stdout of the program, magic page) >= 4: potential leak\n"
        "Options:\n"
        "\n"
        "Examples:\n"
        "  ./wait2 -i $input $program  # return 11(SIGSEGV) if SIGSEGV\n"
        "  ./wait2 -t 3 -i $input $program\n"
        "\n"
        , fh);
  exit(fh == stdout ? 0 : EX_USAGE);
}

void search(u8* input_mmap, size_t size, u32 reg, const char* reg_name)
{
  bool found = false;
  for (; size >= 4; size--)
    if (*(u32*)(input_mmap+size-4) == reg) {
      if (! found)
        printf("%s=%08x", reg_name, reg);
      printf(" %04zx", size-4);
      found = true;
      if (! opt_all_matches) break;
    }
  if (found)
    puts("");
}

int main(int argc, char* argv[])
{
  const char *opt_input = NULL;
  char opt_template[] = "/tmp/XXXXXX", magic_page[PAGE_SIZE];
  set<u32> quadruple;
  u8* input_mmap = (u8*)MAP_FAILED;
  int input_fd = -1, magic_fd = -1, opt, opt_timeout = 0;
  size_t input_size;
  bool opt_verbose = false;
  struct stat sb;
  static struct option long_options[] = {
    {"input",     required_argument, 0,   'i'},
    {"magic-page",required_argument, 0,   'm'},
    {"timeout",   required_argument, 0,   't'},
    {"verbose",   no_argument,       0,   'v'},
    {"help",      no_argument,       0,   'h'},
    {0,           0,                 0,   0},
  };

  while ((opt = getopt_long(argc, argv, "ahi:m:t:v", long_options, NULL)) != -1) {
    switch (opt) {
    case 'a':
      opt_all_matches = true;
      break;
    case 'h':
      print_help(stdout);
      break;
    case 'i':
      opt_input = optarg;
      break;
    case 'm':
      if (magic_fd >= 0)
        print_help(stderr);
      if ((magic_fd = open(optarg, O_WRONLY | O_CREAT | O_TRUNC, 0666)) < 0)
        err(EX_IOERR, "open");
      break;
    case 't':
      opt_timeout = atoi(optarg);
    case 'v':
      opt_verbose = true;
      break;
    case '?':
      break;
    }
  }
  argc -= optind;
  argv += optind;
  if (argc != 1)
    return 1;

  if (opt_input) {
    if ((input_fd = open(opt_input, O_RDONLY)) < 0)
      err(EX_IOERR, "open");
    dup2(input_fd, 0);
    if (fstat(input_fd, &sb) < 0)
      err(EX_IOERR, "fstat");
    if ((input_mmap = (u8*)mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, input_fd, 0)) == (u8*)MAP_FAILED)
      err(EX_IOERR, "mmap");
    input_size = sb.st_size;
  }

  int pfd[2];
  if (pipe(pfd) < 0) err(EX_OSERR, "pipe");
  pid_t pid = fork();
  if (pid < 0) err(EX_OSERR, "fork");
  if (pid == 0) {
    read(pfd[0], &argc, 1);
    close(pfd[0]);
    close(pfd[1]);
    alarm(opt_timeout);
    //ptrace(PTRACE_TRACEME, 0, 0, 0);
    execvp(argv[0], argv);
    return 1;
  }

  if (ptrace(PTRACE_ATTACH, pid, 0, 0) != 0)
    err(1, "PTRACE_ATTACH");
  write(pfd[1], &argc, 1);
  close(pfd[0]);
  close(pfd[1]);

  //int status;
  //waitpid(-1, &status, 0);
  //if (ptrace(PTRACE_CONT, pid, 0, 0))
  //  err(1, "PTRACE_CONT");

  int sig = 0, status;
  for(;;) {
    pid = waitpid(-1, &status, 0);
    if (WIFEXITED(status))
      ;
    else if (WIFSTOPPED(status)) {
      sig = WSTOPSIG(status);
      if (sig == SIGPIPE || sig == SIGTRAP || sig == SIGSTOP) {
        // fetch magic page
        if (sig == SIGTRAP && magic_fd >= 0) {
          errno = 0;
          for (int i = 0; i < PAGE_SIZE; i += 4)
            *(u32*)(magic_page+i) = ptrace(PTRACE_PEEKDATA, pid, MAGIC_PAGE+i, magic_page+i);
          if (errno)
            err(EX_OSERR, "PTRACE_PEEKDATA");
          for (int i = 0; i <= PAGE_SIZE-4; i++)
            quadruple.insert(*(u32*)(magic_page+i));
          if (write(magic_fd, (void*)magic_page, PAGE_SIZE) < int(PAGE_SIZE))
            err(EX_IOERR, "write");
        }
        ptrace(PTRACE_CONT, pid, 0, 0);
        continue;
      }
    } else if (WIFSIGNALED(status))
      sig = WTERMSIG(status);
    else
      assert(0);
    switch (sig) {
    case 0:
    case SIGUSR1:
    default:
      return 0;
    case SIGALRM:
      // timeout
      break;
    case SIGBUS:
    case SIGILL:
    case SIGSEGV: {
      struct user_regs_struct regs;
      if (ptrace(PTRACE_GETREGS, pid, 0, &regs))
        err(1, "ptrace");
      if (opt_verbose) {
        printf("signal %d\n", sig);
#ifdef __i386__
        printf("eax %08x ", regs.eax);
        printf("ecx %08x ", regs.ecx);
        printf("edx %08x ", regs.edx);
        printf("ebx %08x ", regs.ebx);
        printf("esp %08x ", regs.esp);
        printf("ebp %08x ", regs.ebp);
        printf("esi %08x ", regs.esi);
        printf("edi %08x ", regs.edi);
        printf("eip %08x\n", regs.eip);
#endif
      }
      if (opt_input) {
        ssize_t p;
#ifdef __i386__
# define F(REG) if (regs.REG && regs.REG != 0xffffffff) search(input_mmap, input_size, regs.REG, #REG);
        F(eip);
        F(eax);
        F(ebx);
        F(ecx);
        F(edx);
        F(esi);
        F(edi);
        F(ebp);
        F(esp);
        break;
#endif
      }
    }
    }

    ptrace(PTRACE_DETACH, pid, 0, 0);
    if (sig == 0)
      sig = SIGUSR1;
    kill(pid, sig);
  }

  if (input_fd >= 0) {
    munmap(input_mmap, sb.st_size);
    close(input_fd);
  }
  if (magic_fd >= 0)
    close(magic_fd);

  return sig;
}
