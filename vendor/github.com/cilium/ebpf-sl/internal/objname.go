package internal

import (
	"strings"

	"github.com/cilium/ebpf/sys"
)

// sanitizeName replaces all invalid characters in name with replacement.
// Passing a negative value for replacement will delete characters instead
// of replacing them.
//
// The set of allowed characters may change over time.
// TODO(dylandreimerink): deduplicate this with the sanitizeName function in syscalls.go
func sanitizeName(name string, replacement rune) string {
	return strings.Map(func(char rune) rune {
		switch {
		case char >= 'A' && char <= 'Z':
			return char
		case char >= 'a' && char <= 'z':
			return char
		case char >= '0' && char <= '9':
			return char
		case char == '.':
			return char
		case char == '_':
			return char
		default:
			return replacement
		}
	}, name)
}

func MaybeFillObjName(name string) sys.ObjName {
	name = sanitizeName(name, -1)
	return sys.NewObjName(name)
}
