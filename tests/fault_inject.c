/*
 * 测试专用故障注入共享库（非生产代码），仅经 LD_PRELOAD 加载。
 *
 * 目的：让回归测试在自身安排的条件下，稳定触发两类真实的文件访问
 * 错误，而不依赖碰巧出现的磁盘故障或人工干预：
 *
 *   1. 文件确实存在却打不开：
 *      BRANCHAUDIT_TEST_OPEN_FAIL=<path>
 *      对该路径的 fopen/open 系列调用直接失败，errno = EACCES。
 *
 *   2. 文件已打开、取得部分内容后继续读取时出错：
 *      BRANCHAUDIT_TEST_READ_FAIL=<path>[:<bytes>]
 *      该路径可以正常打开；读取照常交付前 <bytes> 个字节（默认 40），
 *      此后对该文件描述符的下一次 read 失败，errno = EIO。
 *
 * 空文件在第二种注入下仍然是正常读完成功：首次 read 即返回 0（一个
 * 字节都没有读到）时透传 EOF，不把“没有读到内容”当作错误。夹具文件
 * 应大于 <bytes>，以保证“取得部分内容后继续读取”确实发生。
 *
 * 不设置上述环境变量时，本库对程序行为没有任何影响：所有调用都透传
 * 给 libc。错误发生在与生产代码完全相同的 libc 文件访问接口上，因此
 * 被测程序必须真正完成“定位 -> 打开 -> 流式读取 -> 错误传播”的整条
 * 路径，不可能用一个写死错误文字的返回值蒙混过关。
 *
 * 实现为介入公共 libc 符号（fopen/fopen64、open/openat 系列、read、
 * __read_chk、close）。不同 glibc 的 std::basic_filebuf 可能经由
 * fopen 或 open 系列打开、经由 read 或 __read_chk 读取，因此这些入口
 * 一并覆盖；read 侧另用 /proc/self/fd 比对目标路径作为兜底，使任何
 * 打开入口下的故障文件描述符都能被识别。
 */

#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define FD_CAP 4096

/* fd 分类：0=未知（首次见到），1=读取故障文件，-1=与故障无关。 */
static int g_state[FD_CAP];
/* g_state==1 的 fd：已交付字节数与开始报错的阈值。 */
static long g_delivered[FD_CAP];
static long g_fail_after[FD_CAP];

static FILE *(*g_real_fopen)(const char *, const char *);
static FILE *(*g_real_fopen64)(const char *, const char *);
static int (*g_real_open)(const char *, int, mode_t);
static int (*g_real_openat)(int, const char *, int, mode_t);
static ssize_t (*g_real_read)(int, void *, size_t);
static int (*g_real_close)(int);

/* 提前在构造器中解析真实符号：read 在动态链接器装载阶段就可能被调用，
 * 惰性 dlsym 若内部再调用 read 会递归。 */
__attribute__((constructor)) static void resolve_real_symbols(void) {
    g_real_fopen = dlsym(RTLD_NEXT, "fopen");
    g_real_fopen64 = dlsym(RTLD_NEXT, "fopen64");
    g_real_open = dlsym(RTLD_NEXT, "open");
    g_real_openat = dlsym(RTLD_NEXT, "openat");
    g_real_read = dlsym(RTLD_NEXT, "read");
    g_real_close = dlsym(RTLD_NEXT, "close");
}

static const char *open_fail_target(void) {
    return getenv("BRANCHAUDIT_TEST_OPEN_FAIL");
}

/* 返回读取故障目标路径，并通过 *bytes_out 回传部分交付阈值。 */
static const char *read_fail_target(long *bytes_out) {
    const char *spec = getenv("BRANCHAUDIT_TEST_READ_FAIL");
    long n = 40;
    if (spec) {
        const char *colon = strchr(spec, ':');
        if (colon) {
            long parsed = strtol(colon + 1, NULL, 10);
            if (parsed > 0) n = parsed;
        }
    }
    *bytes_out = n;
    return spec;
}

static int path_matches(const char *path, const char *target) {
    if (!path || !target) return 0;
    /* 目标规格里冒号之后是阈值，比较时只取路径部分。 */
    size_t len = strcspn(target, ":");
    return strlen(path) == len && strncmp(path, target, len) == 0;
}

/* 通过 /proc/self/fd 判定打开着的 fd 是否指向目标路径。 */
static int fd_points_at(int fd, const char *target) {
    if (fd < 0 || fd >= FD_CAP || !target) return 0;
    char proc[64];
    snprintf(proc, sizeof proc, "/proc/self/fd/%d", fd);
    char link[4096];
    ssize_t n = readlink(proc, link, sizeof link - 1);
    if (n <= 0) return 0;
    link[n] = '\0';
    size_t len = strcspn(target, ":");
    return (size_t)n == len && strncmp(link, target, len) == 0;
}

static void classify_fd(int fd) {
    if (fd < 0 || fd >= FD_CAP || g_state[fd] != 0) return;
    long threshold;
    const char *target = read_fail_target(&threshold);
    if (target && fd_points_at(fd, target)) {
        g_state[fd] = 1;
        g_delivered[fd] = 0;
        g_fail_after[fd] = threshold;
    } else {
        g_state[fd] = -1;
    }
}

/* fd -> 文件的关联在 open 成功时才建立。无论旧 fd 是如何关闭的（可能
 * 经过未介入的内部 close，留下过期缓存），这里都先清掉该 fd 的旧状态再
 * 重新分类，避免复用的 fd 沿用启动期（如读取 locale/ELF 时）的结论。 */
static void reclassify_fd(int fd) {
    if (fd < 0 || fd >= FD_CAP) return;
    g_state[fd] = 0;
    g_delivered[fd] = 0;
    g_fail_after[fd] = 0;
    classify_fd(fd);
}

/* ---- 打开失败：fopen 系列 ----------------------------------------------- */

FILE *fopen(const char *path, const char *mode) {
    if (path_matches(path, open_fail_target())) {
        errno = EACCES;
        return NULL;
    }
    FILE *f = g_real_fopen(path, mode);
    if (f) reclassify_fd(fileno(f));
    return f;
}

FILE *fopen64(const char *path, const char *mode) {
    if (path_matches(path, open_fail_target())) {
        errno = EACCES;
        return NULL;
    }
    FILE *f = g_real_fopen64(path, mode);
    if (f) reclassify_fd(fileno(f));
    return f;
}

/* ---- 打开失败：open/openat 系列（含 FORTIFY 变体） ---------------------- */
/*
 * 无版本号的介入定义在部分 glibc 上不会接管带版本号的 __*_2 引用，但对
 * 经由普通 open/openat 打开文件的构建同样有效；两条打开路径都覆盖以提高
 * 可移植性，fopen 系列在常见 glibc 构建上负责实际接管。
 */

static int intercept_open(const char *path, int flags, int has_mode,
                          mode_t mode) {
    if (path_matches(path, open_fail_target())) {
        errno = EACCES;
        return -1;
    }
    int fd = g_real_open(path, flags, has_mode ? mode : 0);
    reclassify_fd(fd);
    return fd;
}

static int intercept_openat(int dirfd, const char *path, int flags,
                            int has_mode, mode_t mode) {
    if (path_matches(path, open_fail_target())) {
        errno = EACCES;
        return -1;
    }
    int fd = g_real_openat(dirfd, path, flags, has_mode ? mode : 0);
    reclassify_fd(fd);
    return fd;
}

int open(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    return intercept_open(path, flags, flags & O_CREAT, mode);
}

int open64(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    return intercept_open(path, flags, flags & O_CREAT, mode);
}

int openat(int dirfd, const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    return intercept_openat(dirfd, path, flags, flags & O_CREAT, mode);
}

int openat64(int dirfd, const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    return intercept_openat(dirfd, path, flags, flags & O_CREAT, mode);
}

int __open_2(const char *path, int flags) {
    return intercept_open(path, flags, 0, 0);
}

int __open64_2(const char *path, int flags) {
    return intercept_open(path, flags, 0, 0);
}

int __openat_2(int dirfd, const char *path, int flags) {
    return intercept_openat(dirfd, path, flags, 0, 0);
}

int __openat64_2(int dirfd, const char *path, int flags) {
    return intercept_openat(dirfd, path, flags, 0, 0);
}

/* ---- 部分内容后读取失败 -------------------------------------------------- */

static ssize_t fault_read(int fd, void *buf, size_t n) {
    if (fd < 0 || fd >= FD_CAP) return g_real_read(fd, buf, n);

    if (g_state[fd] == 0) classify_fd(fd);

    if (g_state[fd] != 1) return g_real_read(fd, buf, n);

    const long threshold = g_fail_after[fd];
    const long delivered = g_delivered[fd];
    if (delivered > 0 && delivered >= threshold) {
        /* 已经取得部分内容，继续读取即报错——不能当作正常到达文件末尾。 */
        errno = EIO;
        return -1;
    }

    /* 把本次读取限制在阈值之内，确保错误发生在“部分内容之后”的下一次
     * 读取上，而不是等文件被一次性读完。空文件首次 real_read 返回 0，
     * 原样透传为正常 EOF。 */
    size_t want = n;
    const long remain = threshold - delivered;
    if (remain > 0 && (long)n > remain) want = (size_t)remain;

    ssize_t r = g_real_read(fd, buf, want);
    if (r > 0) g_delivered[fd] += r;
    return r;
}

ssize_t read(int fd, void *buf, size_t n) {
    return fault_read(fd, buf, n);
}

ssize_t __read_chk(int fd, void *buf, size_t n, size_t buflen) {
    if (n > buflen) abort();  // 与 glibc __chk_fail 相同的 fortify 失败语义
    return fault_read(fd, buf, n);
}

/* ---- 关闭时清理 fd 状态 -------------------------------------------------- */

int close(int fd) {
    if (fd >= 0 && fd < FD_CAP) {
        g_state[fd] = 0;
        g_delivered[fd] = 0;
        g_fail_after[fd] = 0;
    }
    return g_real_close(fd);
}
