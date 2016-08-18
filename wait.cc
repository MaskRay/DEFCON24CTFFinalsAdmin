#include <err.h>
#include <stdio.h>
#include <sys/wait.h>
#include <sysexits.h>
#include <unistd.h>

int main(int argc, char* argv[])
{
  int status = 0, pfd[2];
  if (pipe(pfd) < 0) err(EX_OSERR, "pipe");
  pid_t pid = fork();
  if (pid < 0) err(EX_OSERR, "fork");
  if (pid == 0) {
    read(pfd[0], &status, 1);
    execvp(argv[1], argv+1);
  } else {
    write(pfd[1], &status, 1);
    waitpid(-1, &status, 0);
    return WTERMSIG(status);
  }
  return 1;
}
