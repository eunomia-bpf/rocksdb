#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint64_t); // jobid
    __type(value, uint64_t); // bitmap get random maping
    __uint(max_entries, 1000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} my_pid_map SEC(".maps");


SEC("uretprobe/rocksdb:")
int BPF_KPROBE(uprobe_sub, int a, int b)
{
    bpf_printk("uprobed_sub ENTRY: a = %d, b = %d", a, b);
    return 0;
}

char _license[] SEC("license") = "GPL";