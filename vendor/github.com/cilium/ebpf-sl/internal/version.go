package internal

import (
	"fmt"
)

// A Version in the form Major.Minor.Patch.
type Version [3]uint16

// NewVersion creates a version from a string like "Major.Minor.Patch".
//
// Patch is optional.
func NewVersion(ver string) (Version, error) {
	var major, minor, patch uint16
	n, _ := fmt.Sscanf(ver, "%d.%d.%d", &major, &minor, &patch)
	if n < 2 {
		return Version{}, fmt.Errorf("invalid version: %s", ver)
	}
	return Version{major, minor, patch}, nil
}

// NewVersionFromCode creates a version from a LINUX_VERSION_CODE.
func NewVersionFromCode(code uint32) Version {
	return Version{
		uint16(uint8(code >> 16)),
		uint16(uint8(code >> 8)),
		uint16(uint8(code)),
	}
}

// Less returns true if the version is less than another version.
func (v Version) Less(other Version) bool {
	for i, a := range v {
		if a == other[i] {
			continue
		}
		return a < other[i]
	}
	return false
}
