// SPDX-License-Identifier: Apache-2.0
/* Copyright Leon Hwang */

package bice

import (
	"fmt"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// SimpleCompile compiles simple C expressions to bpf instructions.
//
// It can not handle complex expressions like function calls, pointer
// dereferences, or array accesses.
// Currently, it only supports struct member access and comparison operators.
//
// For examples with ATT-like syntax:
//
//  1. skb->dev->ifindex == 1
//     movq r1, r3
//     addq offsetof(skb->dev), r3
//     movq 8, r2
//     movq r10, r1
//     subq 8, r1
//     callq bpf_probe_read_kernel(r1, 8, r3)
//     movq -8(r10), r3
//     testq   %rdx, %rdx, goto __exit
//     addq offsetof(dev->ifindex), r3
//     movq 8, r2
//     movq r10, r1
//     subq 8, r1
//     callq bpf_probe_read_kernel(r1, 8, r3)
//     movq -8(r10), r3
//     movq 1, r0
//     cmpq 1, r3
//     je __return
//     __exit:
//     movq 0, r0
//     __return:
//     retq
//
//  2. skb->users.refs.counter != 0
//     movq r1, r3
//     addq offsetof(skb->users), r3
//     addq offsetof(users.refs), r3
//     addq offsetof(refs.counter), r3
//     movq 8, r2
//     movq r10, r1
//     subq 8, r1
//     callq bpf_probe_read_kernel(r1, 8, r3)
//     movq -8(r10), r3
//     movq 1, r0
//     cmpq 0, r3
//     jne __return
//     __exit:
//     movq r4, r0
//     __return:
//     retq
//
// Only struct/union member access and comparison operators are supported. No
// function calls, pointer dereferences, array accesses, parentheses, bitwise
// operators, logical operators, or arithmetic operators are supported.
//
// The left part of the expression must be struct/union member access, and the
// right part must be a constant number.
//
// The operator must be one of the following: =, ==, !=, <, <=, >, >=. '=' is
// used for comparison too.
func SimpleCompile(expr string, typ btf.Type) (asm.Instructions, error) {
	ast, err := parse(expr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse expression(%s): %w", expr, err)
	}

	if err := validate(ast); err != nil {
		return nil, fmt.Errorf("failed to validate expression(%s): %w", expr, err)
	}

	insns, err := compile(ast, typ)
	if err != nil {
		return nil, fmt.Errorf("failed to compile expression(%s): %w", expr, err)
	}

	return insns, nil
}

// SimpleInjectFilter injects the simply compiled instructions into the given
// bpf program's stub function.
func SimpleInjectFilter(opts InjectOptions) error {
	if opts.Expr == "" || opts.Prog == nil || opts.StubFunc == "" || opts.Type == nil {
		return nil
	}

	insns, err := SimpleCompile(opts.Expr, opts.Type)
	if err != nil {
		return err
	}

	return inject(opts, insns)
}
