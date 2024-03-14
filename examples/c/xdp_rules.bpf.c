#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_rule(struct xdp_md *ctx)
{
	void *start = (void *)(long)ctx->data;
	void *end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = start;
	struct iphdr *ip = start + sizeof(*eth);
	bpf_trace_printk("%i", (__u64)eth);
}
