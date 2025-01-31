// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <bcc/helpers.h>
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
    struct socket *skt = (struct socket *)PT_REGS_PARM1(ctx);
    struct sock *sk = skt->sk;
    if (sk->__sk_common.skc_daddr != IP_169_254_169_254) {
        return 0;
    }

    struct msghdr *msghdr = (struct msghdr *)PT_REGS_PARM2(ctx);

    #if defined(iter_iov) || defined (iter_iov_len)
    const struct iovec * iov = msghdr->msg_iter.__iov;
    #else
    const struct iovec * iov = msghdr->msg_iter.iov;
    #endif
    const void *iovbase;
    if (*(char *)iov->iov_base == '\0'){
      iovbase = iov;
    }
    else{
      iovbase = iov->iov_base;
    }
    const size_t iovlen = iov->iov_len > MAX_PKT ? MAX_PKT : iov->iov_len;
    
    if (!iovlen) {
      return 0;
    }
    char req[256] = {};
    bpf_probe_read_str(req, sizeof(req), iov->iov_base);

    // Rewrite if IMDSv1
    if (is_imdsv1_request(req)) {
        char new_req[] = "PUT /latest/api/token HTTP/1.1\r\n"
                         "X-aws-ec2-metadata-token-ttl-seconds: 21600\r\n\r\n";
        __builtin_memcpy(req, new_req, sizeof(new_req));
        bpf_probe_write_user((void *)iov->iov_base, req, sizeof(new_req));
        bpf_printk("IMDSv1 request detected and rewritten\n");
    }

    // Prepare data for perf_submit
    u32 zero = 0;
    struct imds_http_data_t *data = imds_http_data.lookup(&zero);

    if (!data)
        return 0;

    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read(data->comm, TASK_COMM_LEN, t->comm);
    // Traverse parents as per your snippet:
    if (t->real_parent) {
        struct task_struct *parent = t->real_parent;
        data->pid[1] = parent->tgid;
        bpf_probe_read(data->parent_comm, TASK_COMM_LEN, parent->comm);
        // ...carry on with gparent if needed...
    }

    imds_events.perf_submit(ctx, data, sizeof(struct imds_http_data_t));
    return 0;
}