/* vim: set noet ts=8 sw=8: */
#include <asm/ptrace.h>
#include <linux/elf.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

/* Output file consists of sequential records.
 * Each record starts with an 8-byte header:
 *
 *     b1 b2 b3 f1 f2 f3 f4 f5
 *
 * followed by zero or more 8-byte values.
 * Flags 0-17 mean that a new value of a corresponding register is stored
 * in a subsequent value field.
 * Flags 18-35 mean that a signed difference between an old and a new value
 * is stored in a byte b1, b2 or b3. */

#define IDX_PSWA 0
#define IDX_PSWM 1
#define IDX_GPR0 2
#define IDX_GPR15 17
#define IDX_MAX 18

unsigned long get_s390_reg(const s390_regs *regs, int i)
{
	if (i == IDX_PSWA)
		return regs->psw.addr;
	else if (i == IDX_PSWM)
		return regs->psw.mask;
	else if (i >= IDX_GPR0 && i <= IDX_GPR15)
		return regs->gprs[i - IDX_GPR0];
	else
		abort();
}

int write_s390_regs(
		FILE *out,
		const s390_regs *new_regs,
		const s390_regs *old_regs)
{
	unsigned long new_reg, old_reg;
	long delta_reg;
	unsigned long values[IDX_MAX];
	int i, n, d;

	values[0] = 0;
	for (i = 0, n = 1, d = 56; i < IDX_MAX; i++) {
		new_reg = get_s390_reg(new_regs, i);
		old_reg = get_s390_reg(old_regs, i);
		delta_reg = new_reg - old_reg;
		if (delta_reg == 0)
			continue;
		if (d >= 40 && delta_reg >= -128 && delta_reg <= 127) {
			values[0] |= ((delta_reg & 0xff) << d) |
				(1 << (IDX_MAX + i));
			d -= 8;
		} else {
			values[0] |= (1 << i);
			values[n++] = new_reg;
		}
	}
	if (fwrite(&values, n * sizeof(values[0]), 1, out) != 1)
		return -1;
	return 0;
}

int main(int argc, char **argv)
{
	FILE *out;
	pid_t pid;
	int wstatus;
	struct iovec iov;
	s390_regs regs[2];
	int r;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s utility [argument ...]\n", argv[0]);
		return EXIT_FAILURE;
	}

	out = fopen("ptracer.out", "wb");
	if (out == NULL) {
		perror("fopen(ptracer.out) failed");
		return EXIT_FAILURE;
	}

	pid = fork();
	if (pid == -1) {
		perror("fork() failed");
		return EXIT_FAILURE;
	}
	if (pid == 0) {
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
			perror("ptrace(PTRACE_TRACEME) failed");
			return EXIT_FAILURE;
		}
		if (raise(SIGSTOP) == -1) {
			perror("raise(SIGSTOP) failed");
			return EXIT_FAILURE;
		}
		if (execvp(argv[1], argv + 1) == -1) {
			perror("execvp() failed");
			return EXIT_FAILURE;
		}
		return EXIT_FAILURE;
	}
	if (waitpid(pid, &wstatus, WUNTRACED) == -1) {
		perror("waitpid(WUNTRACED) failed");
		return EXIT_FAILURE;
	}
	if (!WIFSTOPPED(wstatus) || WSTOPSIG(wstatus) != SIGSTOP) {
		fprintf(stderr, "not WIFSTOPPED with SIGSTOP\n");
		return EXIT_FAILURE;
	}
	memset(&regs, 0, sizeof(regs));
	for (r = 0; ; r = 1 - r) {
		iov.iov_base = &regs[r];
		iov.iov_len = sizeof(regs[r]);
		if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == -1) {
			perror("ptrace(PTRACE_GETREGSET) failed");
			return EXIT_FAILURE;
		}
		if (write_s390_regs(out, &regs[r], &regs[1 - r]) == -1) {
			perror("write_s390_regs() failed");
			return EXIT_FAILURE;
		}
		if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) {
			perror("ptrace(PTRACE_SINGLESTEP) failed");
			return EXIT_FAILURE;
		}
		if (waitpid(pid, &wstatus, __WALL) == -1) {
			perror("waitpid(__WALL) failed");
			return EXIT_FAILURE;
		}
		if (WIFEXITED(wstatus))
			return WEXITSTATUS(wstatus);
		if (!WIFSTOPPED(wstatus) || WSTOPSIG(wstatus) != SIGTRAP) {
			fprintf(stderr, "not WIFSTOPPED with SIGTRAP "
					"and not WIFEXITED\n");
			return EXIT_FAILURE;
		}
	}
}
