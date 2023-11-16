#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("xdp_drop_icmp")
int drop_icmp(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;


	struct ethhdr *eth = data;
	struct iphdr *ip = data + sizeof(*eth);
	struct icmphdr *icmp = data + sizeof(*eth) + sizeof(*ip);

	if ((void *)icmp + 1 > data_end)
		return XDP_PASS;

	if (ip->protocol == IPPROTO_ICMP)
		return XDP_DROP;

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
