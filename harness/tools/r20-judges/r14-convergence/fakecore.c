/* fakecore.c — 自守护化假核心（R14 版）：argv 形状与真 mihomo 一致
 * （{d}/mihomo -d {d}）。main 里 fork，父进程立即退出（调用方 subshell 不
 * 阻塞、无需 shell `&`——R14 排查发现 bash 快速连发 `( cmd & )` 有位置依赖
 * 的 fork/exec 竞态，后发进程可能整段不执行，pid 文件假缺失），子进程
 * setsid 后把自己的 pid 写进 PROBE_PID_FILE，然后永远 pause()。
 * 用途：F-056 收割网探针（r13-orphan-probe 同型，R13 版无自守护、单发场景
 * 无碍；本版供 ere-matrix.sh 连发矩阵使用）。 */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    if (fork() > 0)
        _exit(0); /* 父即退：subshell 不等 */
    setsid();
    const char *rec = getenv("PROBE_PID_FILE");
    if (rec) {
        FILE *f = fopen(rec, "w");
        if (f) {
            fprintf(f, "%d\n", getpid());
            fclose(f);
        }
    }
    for (;;) {
        pause();
    }
    return 0;
}
