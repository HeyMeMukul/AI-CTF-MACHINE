#include <stdio.h>
/* bench fixture: synthetic pwn (unsafe gets + networked service lookalike) */
static const char *svc = "socket connect service v1";
int main(void) {
    char buf[64];
    printf("%s\n", svc);
    gets(buf);
    printf("hi %s\n", buf);
    return 0;
}
