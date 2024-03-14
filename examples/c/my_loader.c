#include <../uapi/linux/bpf.h>
#include <arpa/inet.h>
#include <asm/unistd_64.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <linux/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <linux/bpf.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#define ptr_to_u64(x) ((uint64_t)x)
#define LOG_BUF_SIZE  0x1000

int bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}
char bpf_log_buf[LOG_BUF_SIZE];

int bpf_prog_load(enum bpf_prog_type type, const struct bpf_insn *insns, int insn_cnt,
		  const char *license)
{
	union bpf_attr attr = {
		.prog_type = type,
		.insns = ptr_to_u64(insns),
		.insn_cnt = insn_cnt,
		.license = ptr_to_u64(license),
		.log_buf = ptr_to_u64(bpf_log_buf),
		.log_size = LOG_BUF_SIZE,
		.log_level = 2,
	};
	return bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

int get_listen_socket(char *ip, int port)
{
	int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	struct sockaddr_in serv_addr;
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr(ip);
	serv_addr.sin_port = htons(port);

	bind(sock, (struct sockaddr *)(&serv_addr), sizeof(serv_addr));

	listen(sock, 20);

	return sock;
}

struct bpf_insn bpf_prog[0x100];

// struct bpf_btf_load_opts {
// 	size_t sz; /* size of this struct for forward/backward compatibility */
//
// 	/* kernel log options */
// 	char *log_buf;
// 	__u32 log_level;
// 	__u32 log_size;
// 	/* output: actual total log contents size (including termintaing zero).
// 	 * It could be both larger than original log_size (if log was
// 	 * truncated), or smaller (if log buffer wasn't filled completely).
// 	 * If kernel doesn't support this feature, log_size is left unchanged.
// 	 */
// 	__u32 log_true_size;
// 	size_t :0;
// };

int main(int argc, char *argv[])
{
	int len = atoi(argv[2]);
	int file = open(argv[1], O_RDONLY);
	if (read(file, (void *)bpf_prog, len) < 0) {
		perror("fail to read program text");
		exit(-1);
	}
	close(file);

	printf("%s\n", bpf_log_buf);
	int prog_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, bpf_prog,
				    len / sizeof(bpf_prog[0]), "GPL");
	if (prog_fd < 0) {
		perror("fail to get the fd of program");
		exit(-1);
	}
	printf("prog_fd: %d\n", prog_fd);

	int sock = get_listen_socket("0.0.0.0", 9527);
	printf("socket: %d\n", sock);

	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd)) < 0) {
		perror("fail to set the socket");
		exit(-1);
	}

	struct sockaddr_in clnt_addr;
	socklen_t clnt_addr_size = sizeof(clnt_addr);
	int clnt_sock = accept(sock, (struct sockaddr *)(&clnt_addr), &clnt_addr_size);
}
