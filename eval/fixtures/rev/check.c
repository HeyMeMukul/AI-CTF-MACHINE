#include <string.h>
/* bench fixture: synthetic rev checker (local, no network, no unsafe input) */
int main(int argc, char **argv) {
    const char *want = "checker-seventeen";
    int ok = 0, i = 0;
    if (argc == 2) {
        ok = 1;
        for (i = 0; want[i]; i++) {
            int c = (i < 64) ? argv[1][i] : 0;
            if ((c ^ 0x42) != (want[i] ^ 0x13)) { ok = 0; break; }
        }
    }
    if (ok && i > 4) { puts("correct"); return 0; }
    puts("wrong");
    return 1;
}
