/* vim: set noet ts=8 sw=8: */
#define _LARGEFILE64_SOURCE
#include <asm/ptrace.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/elf.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
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
 * followed by zero or more 8-byte values, and, possibly, insn bytes.
 * Flags 0-17 mean that a new value of a corresponding register is stored
 * in a subsequent value field.
 * Flags 18-35 mean that a signed difference between an old and a new value
 * is stored in a byte b1, b2 or b3.
 * Flag 36 means that insn bytes are present. */

#define IDX_PSWA 0
#define IDX_PSWM 1
#define IDX_GPR0 2
#define IDX_GPR15 17
#define IDX_MAX 18
#define FLAG_INSN (1ul << (IDX_MAX * 2))

static unsigned long get_s390_reg(const s390_regs *regs, int i)
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

static int get_ilen(uint8_t opc)
{
	switch (opc >> 6) {
	case 0:
		return 2;
	case 1:
	case 2:
		return 4;
	default:
		return 6;
	}
}

static int write_entry(
		FILE *out,
		const s390_regs *new_regs,
		const s390_regs *old_regs,
		const char *insn,
		size_t ilen)
{
	unsigned long values[IDX_MAX];
	int i, n, d;

	values[0] = 0;
	if (ilen > 0)
		values[0] |= FLAG_INSN;
	for (i = 0, n = 1, d = 56; i < IDX_MAX; i++) {
		unsigned long new_reg, old_reg;
		long delta_reg;

		new_reg = get_s390_reg(new_regs, i);
		old_reg = get_s390_reg(old_regs, i);
		delta_reg = new_reg - old_reg;
		if (delta_reg == 0)
			continue;
		if (d >= 40 && delta_reg >= -128 && delta_reg <= 127) {
			values[0] |= ((delta_reg & 0xff) << d) |
				(1ul << (IDX_MAX + i));
			d -= 8;
		} else {
			values[0] |= (1ul << i);
			values[n++] = new_reg;
		}
	}
	if (fwrite(&values, n * sizeof(values[0]), 1, out) != 1)
		return -1;
	if ((values[0] & FLAG_INSN) &&
			(fwrite(insn, ilen, 1, out) != 1)) {
		fprintf(stderr, "fwrite(insn, %zd) failed: %s\n",
				ilen, strerror(errno));
		return -1;
	}
	return 0;
}

static int open_mem(pid_t pid)
{
	char mem_name[32];
	int mem_fd;

	mem_name[snprintf(mem_name, sizeof(mem_name) - 1,
			"/proc/%d/mem", pid)] = 0;
	mem_fd = open(mem_name, O_RDONLY);
	if (mem_fd == -1) {
		fprintf(stderr, "open(%s) failed: %s",
				mem_name, strerror(errno));
		return -1;
	}
	return mem_fd;
}

#define MAX_INSN_SIZE 6

static int read_insn(pid_t pid, unsigned long pswa, int *mem_fd,
		char *insn, size_t *ilen)
{
	int i;

	for (i = 0; i < 2; i++) {
		size_t actual_ilen;

		if (lseek64(*mem_fd, pswa, SEEK_SET) == -1) {
			fprintf(stderr, "lseek64(%lx) failed: %s\n",
					pswa, strerror(errno));
			return -1;
		}
		*ilen = read(*mem_fd, insn, MAX_INSN_SIZE);
		if (*ilen == (size_t)-1) {
			perror("read() failed");
			return -1;
		}
		if (*ilen == 0) {
			if (i) {
				fprintf(stderr, "Unexpected EOF\n");
				return -1;
			}
			/* exec() must have recreated `mm' */
			close(*mem_fd);
			*mem_fd = open_mem(pid);
			if (*mem_fd == -1)
				return -1;
			continue;
		}
		actual_ilen = get_ilen(insn[0]);
		if (actual_ilen > *ilen) {
			fprintf(stderr, "Incomplete insn\n");
			return -1;
		}
		*ilen = actual_ilen;
		break;
	}
	return 0;
}

int main(int argc, char **argv)
{
	int rc = EXIT_FAILURE;
	FILE *out;
	pid_t pid;
	int wstatus;
	int mem_fd;
	struct iovec iov;
	s390_regs regs[2];
	int r;
	char insn[MAX_INSN_SIZE];
	size_t ilen;

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
	mem_fd = open_mem(pid);
	if (mem_fd == -1)
		return EXIT_FAILURE;
	memset(&regs, 0, sizeof(regs));
	for (r = 0; ; r = 1 - r) {
		iov.iov_base = &regs[r];
		iov.iov_len = sizeof(regs[r]);
		if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == -1) {
			perror("ptrace(PTRACE_GETREGSET) failed");
			return EXIT_FAILURE;
		}
		if (read_insn(pid, get_s390_reg(&regs[r], IDX_PSWA), &mem_fd,
					insn, &ilen) == -1)
			goto _close_out;
		if (write_entry(out, &regs[r], &regs[1 - r],
					insn, ilen) == -1)
			goto _close_out;
		if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) {
			perror("ptrace(PTRACE_SINGLESTEP) failed");
			return EXIT_FAILURE;
		}
		if (waitpid(pid, &wstatus, __WALL) == -1) {
			perror("waitpid(__WALL) failed");
			return EXIT_FAILURE;
		}
		if (WIFEXITED(wstatus)) {
			rc = WEXITSTATUS(wstatus);
			goto _close_out;
		}
		if (!WIFSTOPPED(wstatus) || WSTOPSIG(wstatus) != SIGTRAP) {
			fprintf(stderr, "not WIFSTOPPED with SIGTRAP "
					"and not WIFEXITED\n");
			return EXIT_FAILURE;
		}
	}
_close_out:
	fclose(out);
	return rc;
}
