// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <bcc/proto.h>

int trace_sock_sendmsg(struct pt_regs *ctx)
{
    return bpf_printk("trace_sock_sendmsg\n");
}