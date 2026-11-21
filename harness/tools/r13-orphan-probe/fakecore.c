/* fakecore.c — argv 形状与真 mihomo 一致的假核心：{d}/mihomo -d {d} -f {d}/config.yaml
 * 行为：把自己的 pid 写进 PROBE_PID_FILE（若设置），然后永远 pause()，
 * 等待外部信号。仅用于 R13 收割网探针，不是 mihomo。 */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
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
