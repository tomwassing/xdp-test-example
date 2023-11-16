#include <bpf/bpf.h>
#include <assert.h>
#include <netinet/ip.h>
#include <linux/icmp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#include "example.skel.h"

int main (int argc, char *argv[]) {

        // Mock packet.
        int pkt_len = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr);
        char pkt[pkt_len];

        // Fill in Ethernet header.
        struct ethhdr *eth_hdr = (struct ethhdr*) pkt;
        unsigned char dest_mac[ETH_ALEN] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB};
        unsigned char src_mac[ETH_ALEN] = {0xAB, 0x89, 0x67, 0x45, 0x23, 0x01};
        memcpy(eth_hdr->h_dest, dest_mac, ETH_ALEN);
        memcpy(eth_hdr->h_source, src_mac, ETH_ALEN);
        eth_hdr->h_proto = htons(ETH_P_IP);

        // Fill in IP header.
        struct iphdr * ip_hdr = (struct iphdr*) (pkt + sizeof(struct ethhdr));
        ip_hdr->version = 4;
        ip_hdr->ihl = 5;
        ip_hdr->tos = 0;
        ip_hdr->tot_len = htons(pkt_len);
        ip_hdr->id = htons(42);
        ip_hdr->frag_off = 0;
        ip_hdr->ttl = 64;
        ip_hdr->protocol = IPPROTO_ICMP;
        ip_hdr->check = 0;
        ip_hdr->saddr = inet_addr("");
        ip_hdr->daddr = inet_addr("");

        // Fill in ICMP header.
        struct icmphdr *icmp_hdr = (struct icmphdr*) (pkt + sizeof(struct ethhdr) + sizeof(struct iphdr));
        icmp_hdr->type = ICMP_ECHO;
        icmp_hdr->code = 0;
        icmp_hdr->checksum = 0;

        // Define our BPF_PROG_RUN options with our mock data.
        struct bpf_test_run_opts opts = {
                .sz = sizeof(struct bpf_test_run_opts),
                .data_in = &pkt,
                .data_size_in = sizeof(pkt),
        };

        // Load program into kernel.
        struct example_bpf *prog = example_bpf__open_and_load();
        if (!prog) {
                printf("[error]: failed to open and load program.\n");
                return -1;
        }

        // Get the prog_fd from the skeleton.
        int prog_fd = bpf_program__fd(prog->progs.drop_icmp);
        
        // Run test with ICMP packet.
        int err = bpf_prog_test_run_opts(prog_fd, &opts);
        if (err != 0) {
                printf("[error]: bpf_prog_test_run_opts failed: %d\n", err);
                perror("bpf_prog_test_run_opts");
                return -1;
        }

        // Testing!
        assert(opts.retval == XDP_DROP);
        printf("[success] drop ICMP packets\n");

        // Run test with non-ICMP packet.
        ip_hdr->protocol = IPPROTO_TCP;
        err = bpf_prog_test_run_opts(prog_fd, &opts);
        if (err != 0) {
                printf("[error]: bpf_prog_test_run_opts failed: %d\n", err);
                perror("bpf_prog_test_run_opts");
                return -1;
        }

        // Testing!
        assert(opts.retval == XDP_PASS);
        printf("[success] pass non-ICMP packets\n");

        return 0;
}