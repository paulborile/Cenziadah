// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

/*
 * victim — a deliberately-vulnerable test target for cenziadah.
 *
 * This program is ONLY for validating the detector against a GENUINE compromise.
 * It is never linked into cenziadah itself.
 *
 * The victim is "unaware": it does NOT allocate executable memory or inject code
 * itself. It merely contains two real memory-corruption bugs reachable from its
 * network input. A separate exploit (testharness/exploit/) drives attacker-
 * controlled code to execute by corrupting the victim's memory:
 *
 *   LOGIN <hexpayload>  - unbounded memcpy into a stack buffer. Overwriting the
 *                         saved return address redirects control flow (stack smash).
 *   SETNAME <hexpayload>- unbounded copy into a heap struct whose field sits before
 *                         a function pointer; overflowing it corrupts that pointer,
 *                         which the victim then CALLS (function-pointer hijack).
 *   PING                - liveness, returns "pong".
 *
 * Build (see testharness/Makefile): -fno-stack-protector -no-pie, with NX enforced
 * (non-executable stack, the modern default), run under `setarch -R` so the leaked
 * addresses stay valid. The exploit therefore has to defeat NX with a real ROP
 * chain (mprotect), as in-field exploits do. These are the conditions of an
 * exploitable binary, intentionally chosen for a reproducible test; they are NOT
 * production-safe settings.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* ---- heap object with a function pointer after a fixed-size name buffer ---- */
/* Records &buf from the last handle_login call: models an info-leak primitive an
 * exploit uses to defeat ASLR. */
static volatile void *g_leaked_buf = NULL;

struct session {
    char name[64];
    void (*on_login)(void); /* overflow of name[] clobbers this pointer */
};

/* The benign callback a non-malicious SETNAME would leave in place. */
static void default_on_login(void) { /* nothing */ }

/* decode_hex turns an ASCII hex string into raw bytes. Returns byte count, or -1.
 * This is ordinary, non-vulnerable input decoding; the bug is in the handlers. */
static long decode_hex(const char *hex, unsigned char *out, long outcap) {
    long n = 0;
    for (const char *p = hex; p[0] && p[1]; p += 2) {
        if (n >= outcap) return -1;
        unsigned int b;
        if (sscanf(p, "%2x", &b) != 1) return -1;
        out[n++] = (unsigned char)b;
    }
    return n;
}

/* VULN 1: classic stack buffer overflow. A fixed 64-byte stack buffer is filled
 * from an attacker-controlled, attacker-sized payload with no bounds check. */
__attribute__((noinline)) static void handle_login(const unsigned char *payload, long len) {
    char buf[64];
    g_leaked_buf = buf; /* leak primitive: remember this frame's buffer address */
    memcpy(buf, payload, (size_t)len); /* no bounds check: overflows buf */
    /* Touch buf so the compiler keeps the frame; returning here is where a smashed
     * return address takes control. */
    if (buf[0] == '\xff') puts("");
}

/* VULN 2: heap/struct overflow clobbering an adjacent function pointer, which is
 * then invoked. The victim believes it is calling a legitimate callback. */
__attribute__((noinline)) static void handle_setname(const unsigned char *payload, long len) {
    struct session *s = calloc(1, sizeof(*s));
    s->on_login = default_on_login;
    memcpy(s->name, payload, (size_t)len); /* no bounds check: overflows into on_login */
    s->on_login();                         /* calls through the (possibly hijacked) pointer */
    free(s);
}

static void handle(const char *line, int cfd) {
    unsigned char payload[4096];
    if (!strncmp(line, "PING", 4)) {
        write(cfd, "pong\n", 5);
        return;
    }
    if (!strncmp(line, "LEAK", 4)) {
        /* Report a stack address (&buf) and a libc address (&read). A real exploit
         * obtains equivalent leaks from uninitialized memory or a GOT entry to
         * defeat ASLR; we expose them directly so the test stays reproducible. */
        char out[64];
        int k = snprintf(out, sizeof(out), "%p %p\n", (void *)g_leaked_buf, (void *)&read);
        write(cfd, out, (size_t)k);
        return;
    }
    if (!strncmp(line, "LOGIN ", 6)) {
        long n = decode_hex(line + 6, payload, (long)sizeof(payload));
        if (n >= 0) handle_login(payload, n);
    } else if (!strncmp(line, "SETNAME ", 8)) {
        long n = decode_hex(line + 8, payload, (long)sizeof(payload));
        if (n >= 0) handle_setname(payload, n);
    }
    write(cfd, "ok\n", 3);
}

int main(int argc, char **argv) {
    int port = (argc > 1) ? atoi(argv[1]) : 0;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons((unsigned short)port);
    if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) != 0) { perror("bind"); return 1; }
    socklen_t sl = sizeof(sa);
    getsockname(s, (struct sockaddr *)&sa, &sl);
    printf("PID %d\n", (int)getpid());
    printf("PORT %d\n", ntohs(sa.sin_port));
    fflush(stdout);
    listen(s, 4);

    for (;;) {
        int c = accept(s, NULL, NULL);
        if (c < 0) continue;
        char line[16384];
        ssize_t n = read(c, line, sizeof(line) - 1);
        if (n > 0) { line[n] = 0; handle(line, c); }
        close(c);
    }
    return 0;
}
