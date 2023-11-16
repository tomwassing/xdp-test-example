all: vmlinux example.bpf.o example.skel.h test

vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

example.bpf.o: example.bpf.c
	clang -target bpf -Wall -O2 -c $<

example.skel.h: example.bpf.o
	bpftool gen skeleton $< > $@

test: test.c
	gcc -Wall -o $@ $< -lbpf

.PHONY:
clean:
	rm -rf vmlinux.h
	rm -rf example.bpf.o
	rm -rf example.skel.h
	rm -rf test
