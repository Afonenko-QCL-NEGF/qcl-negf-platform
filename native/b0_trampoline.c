/* Source candidate: a fixed privileged entry, not a setuid interpreter.
 * Install/permissions/native qualification need separate HIGH+OPS admission.
 * No inherited descriptor, environment, cwd, PATH, config or exec argument is
 * trusted. The Root descriptor producer is a separate protected owning route.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#ifndef QCL_B0_PYTHON
#error fixed Python closure required
#endif
#ifndef QCL_B0_ENTRY
#error fixed helper closure required
#endif

static int slot_ok(const char *s) {
    size_t n = strnlen(s, 97);
    if (n == 0 || n > 96) return 0;
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)s[i];
        int alnum = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9');
        if (!alnum && (i == 0 || (c != '_' && c != '-'))) return 0;
    }
    return 1;
}

static int close_inherited(void) {
#ifdef SYS_close_range
    if (syscall(SYS_close_range, 3U, UINT_MAX, 0U) == 0) return 0;
#endif
    /* Current RLIMIT_NOFILE cannot bound inherited descriptors: a caller can
     * open fd1000 and then lower its hard limit to64. Unsupported/failing
     * close_range therefore refuses; no privileged exec follows a fallback. */
    return -1;
}

int main(int argc, char **argv) {
    if (argc != 3 || strcmp(argv[1], "run-bound-b0") || !slot_ok(argv[2]) ||
        getuid() != 3000 || getgid() != 3000 || geteuid() != 0) return 126;
    if (setgroups(0, NULL) || setresgid(0, 0, 0) || setresuid(0, 0, 0) ||
        clearenv() || chdir("/") || prctl(PR_SET_DUMPABLE, 0)) return 126;
    umask(077);
    struct rlimit core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &core) || close_inherited()) return 126;
    int nullfd = open("/dev/null", O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    struct stat info;
    if (nullfd < 0 || fstat(nullfd, &info) || !S_ISCHR(info.st_mode) ||
        info.st_rdev != makedev(1, 3)) return 126;
    for (int fd = 0; fd < 3; ++fd)
        if (dup2(nullfd, fd) < 0 || fcntl(fd, F_SETFD, 0) < 0) return 126;
    if (nullfd > 2 && close(nullfd)) return 126;
    char *const fixed[] = {QCL_B0_PYTHON, "-I", "-S", QCL_B0_ENTRY,
                          "run-bound-b0", argv[2], NULL};
    char *const environment[] = {NULL};
    execve(QCL_B0_PYTHON, fixed, environment);
    return 126;
}
