/* Sandbox probe: reports what an action can see and do. Built static so it
 * runs on the sandbox's empty root. Writes out/report.txt. */
#include <dirent.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

extern char **environ;

int main(void) {
    mkdir("out", 0755);
    FILE *f = fopen("out/report.txt", "w");
    if (!f) return 2;

    fprintf(f, "uid=%d gid=%d\n", (int)getuid(), (int)getgid());

    int env_count = 0;
    for (char **e = environ; *e; e++) env_count++;
    fprintf(f, "env_count=%d\n", env_count);
    fprintf(f, "env_HARTLAND_TEST=%s\n", getenv("HARTLAND_TEST") ? getenv("HARTLAND_TEST") : "(unset)");
    fprintf(f, "env_token_request=%s\n", getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN") ? "VISIBLE" : "absent");

    /* Root directory contents: expect only work, proc, dev, tmp. */
    fprintf(f, "root=");
    DIR *d = opendir("/");
    struct dirent *de;
    while (d && (de = readdir(d))) if (de->d_name[0] != '.') fprintf(f, "%s ", de->d_name);
    if (d) closedir(d);
    fprintf(f, "\n");

    /* Processes visible: expect only our own few. */
    int procs = 0;
    d = opendir("/proc");
    while (d && (de = readdir(d))) if (de->d_name[0] >= '1' && de->d_name[0] <= '9') procs++;
    if (d) closedir(d);
    fprintf(f, "visible_pids=%d\n", procs);

    fprintf(f, "home_exists=%s\n", access("/home", F_OK) == 0 ? "yes" : "no");
    fprintf(f, "sudo_exists=%s\n", access("/usr/bin/sudo", F_OK) == 0 ? "yes" : "no");

    /* Network: expect failure (no interfaces besides a down loopback). */
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons(443);
    a.sin_addr.s_addr = htonl(0x01010101); /* 1.1.1.1 */
    int rc = s >= 0 ? connect(s, (struct sockaddr *)&a, sizeof a) : -1;
    fprintf(f, "network=%s (%s)\n", rc == 0 ? "CONNECTED" : "blocked", rc == 0 ? "" : strerror(errno));

    fprintf(f, "input_file=%s\n", access("input.txt", R_OK) == 0 ? "present" : "missing");
    fclose(f);
    printf("probe done\n");
    return 0;
}
