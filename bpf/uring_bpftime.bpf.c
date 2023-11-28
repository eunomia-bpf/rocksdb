#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct uring_check_id{
    uint64_t jobid;
    uint32_t inode;
    uint32_t hashed_inode;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint64_t); // pid
    __type(value, struct uring_check_id); // bitmap get murmurhash
    __uint(max_entries, 1000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} bpftime_uring_map SEC(".maps");

/**
 * `murmurhash.h' - murmurhash
 *
 * copyright (c) 2014-2022 joseph werle <joseph.werle@gmail.com>
 */
uint32_t
murmurhash (const char *key, uint32_t len, uint32_t seed) {
    uint32_t c1 = 0xcc9e2d51;
    uint32_t c2 = 0x1b873593;
    uint32_t r1 = 15;
    uint32_t r2 = 13;
    uint32_t m = 5;
    uint32_t n = 0xe6546b64;
    uint32_t h = 0;
    uint32_t k = 0;
    uint8_t *d = (uint8_t *) key; // 32 bit extract from `key'
    const uint32_t *chunks = NULL;
    const uint8_t *tail = NULL; // tail - last 8 bytes
    int i = 0;
    int l = len / 4; // chunk length

    h = seed;

    chunks = (const uint32_t *) (d + l * 4); // body
    tail = (const uint8_t *) (d + l * 4); // last 8 byte chunk of `key'

    // for each 4 byte chunk of `key'
    for (i = -l; i != 0; ++i) {
        // next 4 byte chunk of `key'
        k = chunks[i];

        // encode next 4 byte chunk of `key'
        k *= c1;
        k = (k << r1) | (k >> (32 - r1));
        k *= c2;

        // append to hash
        h ^= k;
        h = (h << r2) | (h >> (32 - r2));
        h = h * m + n;
    }

    k = 0;

    // remainder
    switch (len & 3) { // `len % 4'
        case 3: k ^= (tail[2] << 16);
        case 2: k ^= (tail[1] << 8);

        case 1:
            k ^= tail[0];
            k *= c1;
            k = (k << r1) | (k >> (32 - r1));
            k *= c2;
            h ^= k;
    }

    h ^= len;

    h ^= (h >> 16);
    h *= 0x85ebca6b;
    h ^= (h >> 13);
    h *= 0xc2b2ae35;
    h ^= (h >> 16);

    return h;
}

//SEC("uretprobe/rocksdb:_ZN7rocksdb6Urings14wait_for_queueEPNS_11uring_queueE")
//int wait_f(_ZN7rocksdb6Urings14wait_for_queueEPNS_11uring_queueE, int a, int b)
//{
//    bpf_printk("uprobed_sub ENTRY: a = %d, b = %d", a, b);
//    return 0;
//}

SEC("uprobe/rocksdb:io_uring_wait_cqe")
int notify_io_uring_wait_cqe(io_uring_wait_cqe, int a, int b)
{
    // if it's ready, set the iouring done flag and continue for this fd
    bpf_printk("uprobed_sub ENTRY: a = %d, b = %d", a, b);
    return 0;
}

SEC("uprobe/rocksdb:io_uring_get_sqe")
int get_fd_inode_hash(io_uring_wait_cqe, int a, int b)
{ // get fd submit id pid
    // insert job id pid to map
    bpf_printk("uprobed_sub ENTRY: a = %d, b = %d", a, b);
    return 0;
}

// 找到一个kernel
// trace点可以把 fd 的 inodemap拿到
//SEC("kretprobe:__writeback_single_inode")
//int check_done_ext_writeback(struct pt_regs *ctx)
//{
//    u32 pid = bpf_get_current_pid_tgid();
//    u64 *val, key = 0;
//    val = bpf_map_lookup_elem(&bpftime_uring_map, &key);
//    bpf_printk("__writeback_single_inode ENTRY: a = %d, b = %d", key, pid);
//
//    return 0;
//}

SEC("kretprobe:__writeback_single_inode")
int check_done_ext_writeback(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 *val, key = 0;
    val = bpf_map_lookup_elem(&bpftime_uring_map, &key);
    bpf_printk("__writeback_single_inode ENTRY: a = %d, b = %d", key, pid);

    return 0;
}

SEC("kretprobe:jbd2_journal_commit_transaction")
int check_done()
{
    bpf_printk("jbd2_journal_commit_transaction ENTRY: a = %d, b = %d", a, b);
    // 如果是这个inode的最后一个提交，那么就可以把这个inode的标记清除了 更新map
    return 0;
}


char _license[] SEC("license") = "GPL";