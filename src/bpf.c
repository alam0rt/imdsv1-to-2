// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/sched.h>

#define IP_169_254_169_254 0xFEA9FEA9

struct imds_state_t {
    bool token_requested;
    char token[128];  // Store IMDSv2 token after we get it
};

// Map to hold IMDS state; key=0 for simplicity
BPF_HASH(imds_state, u32, struct imds_state_t, 1);

#define MAX_PKT 31*1024
struct imds_http_data_t {
    u32 pid[4];
    // i could not get 2d type conversion right in python, so...
    char comm[TASK_COMM_LEN];
    char parent_comm[TASK_COMM_LEN];
    char gparent_comm[TASK_COMM_LEN];
    char ggparent_comm[TASK_COMM_LEN];
    u32 pkt_size;
    char pkt[MAX_PKT];
    u32 contains_payload;
};
BPF_PERF_OUTPUT(imds_events);

// single element per-cpu array to hold the current event off the stack
BPF_PERCPU_ARRAY(imds_http_data,struct imds_http_data_t,1);

// Simple helper to detect an IMDSv1 GET request
static __inline bool is_imdsv1_request(const char *pkt) {
    // Check for a string like "GET /latest/meta-data"
    return (__builtin_memcmp(pkt, "GET /latest/meta-data", 20) == 0);
}

int trace_sock_sendmsg(struct pt_regs *ctx)
{
    bpf_printk("trace_sock_sendmsg\n");
    return 0;
}