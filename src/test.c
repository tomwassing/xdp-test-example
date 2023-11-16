#include <bpf/bpf.h>
#include <assert.h>

#include "net/ethernet.h"
#include "linux/ip.h"
#include "netinet/tcp.h"
#include "example.skel.h"

int main (int argc, char *argv[]) {

        // Mock packet.
        char pkt[(sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr))];

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

        // Get the prog_fd from the skeleton, and run our test.
        int prog_fd = bpf_program__fd(prog->progs.xdp_prog_simple);
        int err = bpf_prog_test_run_opts(prog_fd, &opts);
        if (err != 0) {
                printf("[error]: bpf_prog_test_run_opts failed: %d\n", err);
                perror("bpf_prog_test_run_opts");
                return -1;
        }

        // Testing!
        assert(opts.retval == XDP_PASS);
        printf("[success]\n");

        return 0;
}