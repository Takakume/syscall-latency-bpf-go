//go:build ignore
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

/* =========================
 * Structures
 * =========================
 */

struct start_t {
    __u64 ts;
    __u32 id;
};

struct key_t {
    __u32 id;
    __u32 pid;
};

struct stats_t {
    __u64 count;
    __u64 total_ns;
    __u64 max_ns;
};

/* =========================
 * Maps
 * =========================
 */

// In-flight syscall start times
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);              // pid_tgid
    __type(value, struct start_t);
} start SEC(".maps");

// Aggregated stats per (syscall id, pid)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct key_t);
    __type(value, struct stats_t);
} stats SEC(".maps");

/* =========================
 * Tracepoints
 * =========================
 */

SEC("tracepoint/raw_syscalls/sys_enter")
int handle_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 id = ctx->id;

    struct start_t s = {};
    s.ts = bpf_ktime_get_ns();
    s.id = id;

    bpf_map_update_elem(&start, &pid_tgid, &s, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit")
int handle_sys_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    struct start_t *s;
    s = bpf_map_lookup_elem(&start, &pid_tgid);
    if (!s)
        return 0;

    __u64 delta = bpf_ktime_get_ns() - s->ts;

    struct key_t key = {};
    key.id = s->id;
    key.pid = pid;

    struct stats_t zero = {};
    struct stats_t *st;

    st = bpf_map_lookup_elem(&stats, &key);
    if (!st) {
        zero.count = 1;
        zero.total_ns = delta;
        zero.max_ns = delta;
        bpf_map_update_elem(&stats, &key, &zero, BPF_ANY);
    } else {
        __sync_fetch_and_add(&st->count, 1);
        __sync_fetch_and_add(&st->total_ns, delta);

        if (delta > st->max_ns)
            st->max_ns = delta;
    }

    bpf_map_delete_elem(&start, &pid_tgid);

    return 0;
}

