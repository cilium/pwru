// SPDX-License-Identifier: Apache-2.0
/* Copyright Leon Hwang */

package bice

import (
	"strconv"
	"strings"

	"rsc.io/c2go/cc"
)

func parse(expr string) (*cc.Expr, error) {
	return cc.ParseExpr(expr)
}

func parseNumber(text string) (uint64, error) {
	if strings.HasPrefix(text, "0x") {
		return strconv.ParseUint(text[2:], 16, 64)
	}
	if strings.HasPrefix(text, "0o") {
		return strconv.ParseUint(text[2:], 8, 64)
	}
	if strings.HasPrefix(text, "0b") {
		return strconv.ParseUint(text[2:], 2, 64)
	}
	return strconv.ParseUint(text, 10, 64)
}
