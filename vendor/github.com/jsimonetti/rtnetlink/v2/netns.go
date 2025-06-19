package rtnetlink

import (
	"github.com/jsimonetti/rtnetlink/v2/internal/unix"
)

// NetNS represents a Linux network namespace handle to specify in
// [LinkAttributes].
//
// Use [NetNSForPID] to create a handle to the network namespace of an existing
// PID, or [NetNSForFD] for a handle to an existing network namespace created by
// another library.
type NetNS struct {
	fd  *uint32
	pid *uint32
}

// NetNSForPID returns a handle to the network namespace of an existing process
// given its pid. The process must be alive when the NetNS is used in any API
// calls.
//
// The resulting NetNS doesn't hold a hard reference to the netns (it doesn't
// increase its refcount) and becomes invalid when the process it points to
// dies.
func NetNSForPID(pid uint32) *NetNS {
	return &NetNS{pid: &pid}
}

// NetNSForFD returns a handle to an existing network namespace created by
// another library. It does not clone fd or manage its lifecycle in any way.
// The caller is responsible for making sure the underlying fd stays alive
// for the duration of any API calls using the NetNS.
func NetNSForFD(fd uint32) *NetNS {
	return &NetNS{fd: &fd}
}

// value returns the type and value of the NetNS for use in netlink attributes.
func (ns *NetNS) value() (uint16, uint32) {
	if ns.fd != nil {
		return unix.IFLA_NET_NS_FD, *ns.fd
	}
	if ns.pid != nil {
		return unix.IFLA_NET_NS_PID, *ns.pid
	}
	return 0, 0
}
